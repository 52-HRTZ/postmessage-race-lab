# postMessage Client-Side Race Condition Lab (popup OAuth → token theft)

A tiny, self-contained lab that reproduces the client-side `postMessage` race condition
Youssef Sammouda (`@samm0uda`) described on the Critical Thinking Bug Bounty Podcast (Ep. 58)
and used to steal first-party OAuth tokens from Meta.

The flow is modeled realistically: the provider is opened as a **popup** (like a real
"Login with Example" window) and talks back through `window.opener.postMessage`. The race is run
against a **genuine async operation** — a real origin-check round-trip — not an artificial
`setTimeout`. The attacker wins by overwriting the destination **fast**, so no precise timing is needed.

> **Ethics / scope.** Everything runs on `localhost`, to teach and to fix this bug class.
> Only run it against this lab or systems you are explicitly authorized to test.

## The core idea

A provider returns a secret (an access token) to a destination origin `k`. `k` is read from the
message payload and validated with an **async** check, and re-read when the token is sent. Because
`k` is shared and mutable, a second message delivered **during the async gap** overwrites it — the
check passes for a valid origin, but the token is sent to the attacker's origin. Classic **TOCTOU**
(time-of-check ≠ time-of-use).

```
getToken  appOrigin = PARTNER   ── store k=PARTNER, start real async check ──┐  the gap
register  appOrigin = ATTACKER  ── overwrite k=ATTACKER (fired immediately)  ┘
             async check resolves (PARTNER allowed) ── send token to k == ATTACKER ✗
```

## Layout

```
postmessage-race-lab/
├── provider/
│   ├── server.js                    # :3000  popup "identity provider" + /api/authorize
│   └── public/
│       ├── provider-vulnerable.html # vulnerable listener (shared mutable k, async check)
│       └── provider-fixed.html      # patched listener
├── attacker/
│   ├── server.js                    # :4000  attacker origin (NOT allowlisted)
│   └── public/attacker.html         # opens the popup and wins the race
└── docs/walkthrough.md
```

Provider allowlists one partner origin, `http://localhost:5000`. The attacker lives on
`http://localhost:4000`, which is **not** allowlisted, so it must never receive the token.

## Run it

Requires Node.js ≥ 18 (no `npm install` — standard library only).

```bash
node provider/server.js      # http://localhost:3000
node attacker/server.js      # http://localhost:4000
```

Then open **http://localhost:4000** and try the three scenarios in order (allow the pop-up if
prompted). Watch what actually comes back — the outcome is decided by the browser, not asserted:

1. **Direct, with our own origin** — `getToken(appOrigin = 4000)`. The provider refuses: 4000 is
   not allowed. No token.
2. **Allowed origin, no race** — `getToken(appOrigin = 5000)`. The check passes, so the provider
   sends the token with `targetOrigin = 5000`. But our window is 4000, so **the browser itself
   blocks delivery** with a real `postMessage` origin-mismatch error (visible in the provider
   popup's console). No token.
3. **Race** — `getToken(5000)` + `register(4000)` fired back-to-back. The check passes for 5000,
   but `k` is overwritten to 4000 before the send, so the token is delivered to us.

Scenario 3 is verified end-to-end in real Chrome (via Playwright): 1 and 2 yield no token, 3
delivers it. The `/fixed` provider makes all three fail.

## Why the vulnerable handler is wrong

```js
let k = location.origin;                         // shared, mutable destination
addEventListener("message", async (e) => {
  const m = JSON.parse(e.data);
  if (m.type === "register") { k = m.appOrigin; return; }   // overwrites k any time
  if (m.type === "getToken") {
    k = m.appOrigin;                             // destination from the payload
    const ok = await fetch("/api/authorize?origin=" + k).then(r=>r.json()).then(j=>j.allowed);
    if (!ok) return;
    window.opener.postMessage({ token }, k);     // re-reads k → may be the attacker now
  }
});
```

Two mistakes, either enough on its own: trusting an origin from the **payload** instead of
`event.origin`, and making a security decision across an `await` against **shared mutable state**.

## The fix

```js
const ALLOW = new Set(["http://localhost:5000"]);
addEventListener("message", (e) => {
  const origin = e.origin;                 // browser-set, unforgeable, per-handler local
  const m = JSON.parse(e.data);
  if (m.type !== "getToken") return;
  if (!ALLOW.has(origin)) return;          // synchronous check, no gap
  window.opener.postMessage({ token }, origin);   // use the captured origin
});
```

Trust `event.origin`; keep it in a local `const` (no shared state); decide synchronously (or
re-validate the same captured value right before use).

## Verified

Both paths were tested end-to-end in real Chrome (via Playwright): the vulnerable provider leaks
the token to the un-allowlisted attacker origin; the fixed provider rejects it.

## Port note (why a browser may say the page "doesn't work")

Browsers block a set of "unsafe" ports outright (`ERR_UNSAFE_PORT`) — notably 6000, 6665–6669
(IRC), and others. This lab uses **3000** (provider) and **4000** (attacker), both safe. If you
re-port it, avoid the blocked list or the page simply won't load.

## Sources

- Critical Thinking – Bug Bounty Podcast, Ep. 58: “Youssef Sammouda – Client-Side & ATO War Stories.”
- ysamm.com — “More secure Facebook Canvas Part 2” (the `k` variable, register message, `fbconnect://success`).
- MDN: `Window.postMessage()` security notes.
