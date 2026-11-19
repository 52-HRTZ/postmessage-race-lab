# Walkthrough — the popup postMessage race

## 0. Mental model

The provider is a popup, like a real "Login with Example" / OAuth consent window. The client
opens it with `window.open` and the provider replies through `window.opener.postMessage`. The
provider must return the token only to a registered origin. The race lets an un-registered
attacker receive it.

Two `postMessage` facts to hold onto:

1. `event.origin` is set by the **browser** and cannot be forged. Anything in `event.data` (the
   payload) is fully controlled by the sender.
2. `targetWindow.postMessage(data, targetOrigin)` only delivers if `targetOrigin` matches the
   receiving window's origin. So to receive the token, the provider's outbound `targetOrigin`
   (here the variable `k`) must become the attacker's origin.

## 1. The legitimate flow

- Partner at `http://localhost:5000` opens the provider popup.
- Partner → provider: `{ type:"getToken", appOrigin:"http://localhost:5000" }`.
- Provider sets `k = 5000`, calls `/api/authorize?origin=5000` → allowed, then
  `window.opener.postMessage(token, k)` → token reaches the partner. Correct.

## 2. The attack

The attacker page (`http://localhost:4000`) opens the provider popup and, the moment the popup
signals it is ready, fires **two messages back-to-back**:

- **msg #1** — `{ type:"getToken", appOrigin:"http://localhost:5000" }`. The valid partner origin,
  so it **passes** the provider's async check.
- **msg #2** — `{ type:"register", appOrigin:"http://localhost:4000" }`. Overwrites `k` to the
  attacker's origin. Fired immediately, so it lands while msg #1's check is still in flight.

Inside the provider:

```
getToken: k = 5000 ; fetch("/api/authorize?origin=5000")  // yields to the event loop
register: k = 4000                                          // runs during the await
          check resolves: allowed(5000) == true
          window.opener.postMessage(token, k)  // k is now 4000 → delivered to the attacker
```

No precise timing is needed: because both messages are posted synchronously, the overwrite is
already queued before the real async check resolves. The gap is a **genuine** operation (a real
round-trip), not an injected delay — the attacker simply fires faster than the server can answer.

## 3. Observing it

- Attacker page shows `🏆 STOLEN TOKEN: FIRST_PARTY_ACCESS_TOKEN_s3cr3t` and notes the origin was
  validated as `5000` but the token was delivered to `4000`.
- Provider log shows `token sent to k = http://localhost:4000`, though only `5000` was allowlisted.

## 4. Against the fixed build (`/fixed`)

The patched handler reads `event.origin` (always `http://localhost:4000` for the attacker's
messages, because the browser sets it), checks it synchronously against the allowlist, and uses
that captured origin to send. The payload's `appOrigin` is ignored, there is no shared `k`, and
there is no await to race. Every attacker message is rejected.

## 5. Where to hunt for this in the wild

- `postMessage` listeners that take a destination origin from the **message body** and echo a
  token/secret back to it.
- An **async** step (fetch, `await`, dynamic `import`) between validating the destination and using it.
- OAuth / SSO popups and iframes that return `access_token` / `code` by postMessage.
- Use Frans Rosén's **postMessage-tracker** extension to enumerate listeners, then read each one to
  see what it trusts and when.
