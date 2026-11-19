/*
 * ATTACKER origin — lab only.
 * Runs on http://localhost:4000 (NOT on the provider's allowlist).
 *
 * Serves a page that opens the provider popup and wins the client-side race
 * to make the provider post the first-party token to THIS origin.
 *
 * Node built-in http only, no dependencies.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 4000;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  let file = url.pathname === "/" ? "attacker.html" : url.pathname.slice(1);
  // allow extension-less routes like /experiment -> experiment.html
  if (!path.extname(file)) file += ".html";
  const full = path.join(__dirname, "public", path.basename(file));
  fs.readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("Not found");
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`[attacker] evil page on http://localhost:${PORT} (origin NOT allowlisted)`);
});
