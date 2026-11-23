// Checks a deployed dashboard from the outside, as a stranger would see it.
//   dashboard-security-kit check-live https://dash.client.com [https://<worker>.<account>.workers.dev]
// Run without being signed in. Every check should show ✓.
const base = process.argv[2]?.replace(/\/$/, "");
if (!base || !base.startsWith("https://")) {
  console.error("usage: dashboard-security-kit check-live https://your-dashboard-domain [workers.dev URL]");
  process.exit(1);
}
const results = [];
const check = (name, ok, info = "") => results.push({ name, ok, info });
const host = new URL(base).host;
const get = (url, init = {}) => fetch(url, { redirect: "manual", ...init });

try {
  const r = await get(`http://${host}/`);
  const loc = r.headers.get("location") ?? "";
  check("HTTP redirects to HTTPS", r.status >= 300 && r.status < 400 && loc.startsWith("https://"), `${r.status} → ${loc}`);
} catch (e) {
  check("HTTP redirects to HTTPS", false, String(e));
}

for (const path of ["/", "/api/me", "/api/csrf", "/index.html", "/assets/", "/some/deep/page"]) {
  const r = await get(base + path);
  const loc = r.headers.get("location") ?? "";
  const blocked = (r.status === 302 && loc.includes(".cloudflareaccess.com")) || r.status === 401 || r.status === 403;
  check(`${path} blocked without sign-in`, blocked, `${r.status} ${loc.slice(0, 60)}`);
}

// A forged session must be rejected (Access, or the Worker's own check).
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeToken = [b64({ alg: "RS256" }), b64({ email: "x@x.com" }), "c2ln"].join(".");
const forged = await get(base + "/api/me", { headers: { "Cf-Access-Jwt-Assertion": fakeToken } });
check("Forged session token rejected", [302, 401, 403].includes(forged.status), String(forged.status));
const body = await forged.text();
check("No stack traces in error responses", !/at\s+\S+\s+\(|Error:|stack|node_modules/i.test(body), body.slice(0, 80).replace(/\s+/g, " "));

const root = await get(base + "/");
const hsts = root.headers.get("strict-transport-security") ?? "";
check("HSTS on (zone or app)", /max-age=\d{7,}/.test(hsts), hsts || "missing — turn on HSTS in Cloudflare SSL/TLS → Edge Certificates");

const cors = await get(base + "/api/me", { method: "OPTIONS", headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "GET" } });
check("No CORS for other origins", !cors.headers.get("access-control-allow-origin"), cors.headers.get("access-control-allow-origin") ?? "none");

for (const leak of ["/.env", "/.git/config", "/wrangler.jsonc", "/package.json"]) {
  const r = await get(base + leak);
  // A 200 is fine only if it's the app's own HTML page (single-page app fallback), not the file itself.
  const served = r.status === 200 && !(r.headers.get("content-type") ?? "").includes("text/html");
  check(`${leak} not served`, !served, String(r.status));
}

const wd = process.argv[3];
if (wd) {
  const r = await get(wd).catch(() => null);
  check("workers.dev URL disabled", !r || r.status === 404 || r.status >= 500, r ? String(r.status) : "unreachable");
}

let fail = 0;
for (const x of results) {
  console.log(`${x.ok ? "✓" : "✗"} ${x.name}  ${x.info}`);
  if (!x.ok) fail++;
}
console.log(fail ? `\n${fail} check(s) failed.` : "\nAll outside checks passed.");
process.exit(fail ? 1 : 0);
