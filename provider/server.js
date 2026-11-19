/*
 * VULNERABLE "OAuth provider" — lab target (popup flow).
 * Runs on http://localhost:3000
 *
 * Opened by a client as a POPUP (window.open), exactly like a real
 * "Login with Example" / OAuth consent window. It returns a first-party
 * access token to the opener via window.opener.postMessage.
 *
 * The async gap here is a GENUINE operation: a real round-trip to the
 * provider's own /api/authorize endpoint (an actual origin check). We do NOT
 * inject an artificial setTimeout "latency" — the race is run against real
 * async work, and the attacker wins by overwriting the destination fast.
 *
 * No external dependencies — Node's built-in http module only.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 3000;

// Only this origin is a registered partner allowed to receive the token.
// The attacker (localhost:4000) is NOT on the list.
const ALLOWLIST = new Set(["http://localhost:5000"]);

function send(res, status, body, type = "text/html; charset=utf-8") {
  res.writeHead(status, { "Content-Type": type, "Access-Control-Allow-Origin": "*" });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // --- GENUINE async origin check (the real round-trip = the race window) ---
  // No artificial delay: the gap is simply the cost of doing a real request.
  if (url.pathname === "/api/authorize") {
    const origin = url.searchParams.get("origin") || "";
    const allowed = ALLOWLIST.has(origin);
    return send(res, 200, JSON.stringify({ allowed }), "application/json");
  }

  // --- static pages -------------------------------------------------------
  let file;
  if (url.pathname === "/" || url.pathname === "/vulnerable") file = "provider-vulnerable.html";
  else if (url.pathname === "/fixed") file = "provider-fixed.html";
  else return send(res, 404, "Not found");

  fs.readFile(path.join(__dirname, "public", file), (err, data) => {
    if (err) return send(res, 500, "Error reading " + file);
    send(res, 200, data);
  });
});

server.listen(PORT, () => {
  console.log(`[provider] VULNERABLE provider (popup) on http://localhost:${PORT}`);
  console.log(`[provider]   /        -> vulnerable listener`);
  console.log(`[provider]   /fixed   -> patched listener`);
  console.log(`[provider]   allowlist-> ${[...ALLOWLIST].join(", ")}`);
});
