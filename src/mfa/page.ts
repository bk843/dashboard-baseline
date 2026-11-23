/**
 * The built-in 2FA screen. Served by the kit itself (not the dashboard), so it can't be skipped
 * or broken by dashboard code. No inline script or style: it works under the strict CSP.
 * All text is set with textContent; nothing from the server is ever parsed as HTML.
 */

export const MFA_PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Two-step verification</title>
<link rel="stylesheet" href="/__mfa/mfa.css">
<script type="module" src="/__mfa/mfa.js"></script>
</head>
<body>
<main class="card">
  <h1 id="title">Two-step verification</h1>
  <p id="intro" class="muted">Loading…</p>
  <div id="setup" hidden>
    <ol class="steps">
      <li>Install an authenticator app on your phone: Google Authenticator, Microsoft Authenticator, or Authy.</li>
      <li>In the app, add an account and scan this code.</li>
    </ol>
    <img id="qr" alt="QR code for your authenticator app" width="220" height="220">
    <details>
      <summary>Can't scan? Enter this key instead</summary>
      <code id="manual"></code>
    </details>
    <p class="muted">3. Type the 6-digit code the app shows.</p>
  </div>
  <form id="form" hidden autocomplete="off">
    <label for="code">6-digit code</label>
    <input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
    <button id="submit" type="submit">Verify</button>
    <p id="error" class="error" role="alert"></p>
  </form>
  <p class="muted small">Lost your phone? Ask an admin to reset your two-step verification.</p>
</main>
</body>
</html>`;

export const MFA_PAGE_CSS = `:root{--bg:#f7f7f5;--card:#fff;--text:#1c1c1a;--muted:#6b6b66;--line:#e4e4df;--accent:#2f5bd3;--bad:#b3261e;color-scheme:light dark;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--text:#ececea;--muted:#a3a39e;--line:#2e2e2b;--accent:#8fb0ff;--bad:#f2b8b5}}
body{margin:0;background:var(--bg);color:var(--text);display:flex;justify-content:center;padding:40px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;max-width:380px;width:100%}
h1{font-size:1.25rem;margin:0 0 8px}.muted{color:var(--muted)}.small{font-size:.85rem;margin-top:20px}
.steps{padding-left:20px;line-height:1.5}#qr{display:block;margin:12px auto;background:#fff;padding:8px;border-radius:8px}
code{display:block;word-break:break-all;font-size:.95rem;margin-top:8px;letter-spacing:.08em}
label{display:block;font-weight:600;margin:12px 0 6px}
input{font-size:1.4rem;letter-spacing:.3em;width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text)}
button{margin-top:12px;width:100%;padding:10px;font-size:1rem;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
button:disabled{opacity:.6}.error{color:var(--bad);min-height:1.2em}`;

export const MFA_PAGE_JS = `const $ = (id) => document.getElementById(id);
let csrf = "";
let mode = "verify";
const messages = {
  invalid_code: "That code didn't work. Check the app and try again.",
  locked: "Too many wrong codes. Wait a few minutes, then try again.",
  enrollment_expired: "Setup took too long. Reload the page to start again.",
  rate_limited: "Too many attempts. Wait a minute.",
};
async function call(path, body) {
  const init = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body) };
  const r = await fetch(path, { credentials: "same-origin", ...init });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || "request_failed"), { info: j });
  return j;
}
async function start() {
  csrf = (await call("/api/csrf")).token;
  const s = await call("/api/mfa/status");
  if (s.enrolled) {
    $("intro").textContent = "Open your authenticator app and enter the 6-digit code for this dashboard.";
  } else {
    mode = "enroll";
    $("title").textContent = "Set up two-step verification";
    $("intro").textContent = "This dashboard needs a code from an authenticator app each time you sign in. It takes about a minute to set up.";
    const e = await call("/api/mfa/enroll/start", {});
    $("qr").src = e.qr;
    $("manual").textContent = e.secret.replace(/(.{4})/g, "$1 ").trim();
    $("setup").hidden = false;
  }
  $("form").hidden = false;
  $("code").focus();
}
$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("error").textContent = "";
  $("submit").disabled = true;
  try {
    await call(mode === "enroll" ? "/api/mfa/enroll/confirm" : "/api/mfa/verify", { code: $("code").value.trim() });
    window.location.reload();
  } catch (e) {
    $("error").textContent = messages[e.message] || "Something went wrong. Reload and try again.";
    $("code").value = "";
    $("code").focus();
  } finally {
    $("submit").disabled = false;
  }
});
start().catch((e) => {
  $("intro").textContent = messages[e.message] || "Couldn't start two-step verification. Reload the page.";
});
`;
