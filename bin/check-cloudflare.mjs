// Audits a client's Cloudflare account against the baseline, using a READ-ONLY API token.
// It changes nothing. Settings live in the client's account, so this proves they're still right.
//
//   CF_AUDIT_TOKEN=…  CF_ACCOUNT_ID=…  CF_ZONE_ID=…  APP_HOSTNAME=dash.client.com  WORKER_NAME=client-dashboard \
//     dashboard-security-kit check-cloudflare
//
// Token permissions (all Read): Account → Access: Apps and Policies, Access: Organizations,
// Identity Providers, and Groups, Workers Scripts.  Zone → Zone Settings, DNS.
// Optional: MAX_SESSION_HOURS (default 12). MFA_MODE=app when the dashboard enforces the
// authenticator-app step itself (Cloudflare plans without Access independent MFA).

const env = process.env;
const need = ["CF_AUDIT_TOKEN", "CF_ACCOUNT_ID", "CF_ZONE_ID", "APP_HOSTNAME", "WORKER_NAME"];
const missing = need.filter((k) => !env[k]);
if (missing.length) {
  console.error(`Missing: ${missing.join(", ")}\nSee the comment at the top of check-cloudflare.mjs for what each one is.`);
  process.exit(1);
}
const { CF_AUDIT_TOKEN: TOKEN, CF_ACCOUNT_ID: ACCOUNT, CF_ZONE_ID: ZONE, APP_HOSTNAME: HOST, WORKER_NAME: WORKER } = env;
const MAX_HOURS = Number(env.MAX_SESSION_HOURS ?? 12);
const APP_MFA = (env.MFA_MODE || "access") === "app";

const results = [];
const pass = (name, info = "") => results.push({ s: "✓", name, info });
const fail = (name, info = "") => results.push({ s: "✗", name, info });
const warn = (name, info = "") => results.push({ s: "!", name, info });
const ok = (cond, name, good, bad) => (cond ? pass(name, good) : fail(name, bad));

async function api(path) {
  const r = await fetch(`https://api.cloudflare.com/client/v4${path}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) {
    const msg = j.errors?.map((e) => e.message).join("; ") || `HTTP ${r.status}`;
    throw new Error(r.status === 403 || r.status === 401 ? `no permission (${msg}) — check the audit token's permissions` : msg);
  }
  return j.result;
}
async function safe(label, fn) {
  try {
    await fn();
  } catch (e) {
    fail(label, e.message);
  }
}

/** Duration string like "24h", "30m", "720h" → hours. */
function hours(d) {
  if (!d) return NaN;
  let h = 0;
  for (const [, n, u] of String(d).matchAll(/(\d+(?:\.\d+)?)(h|m|s)/g)) h += Number(n) / (u === "h" ? 1 : u === "m" ? 60 : 3600);
  return h;
}

// ---------- Zone: TLS / HTTPS ----------
await safe("Zone settings readable", async () => {
  const list = await api(`/zones/${ZONE}/settings`);
  const s = Object.fromEntries(list.map((x) => [x.id, x.value]));
  ok(s.ssl === "strict", "SSL mode is Full (strict)", s.ssl, `is "${s.ssl}" — set SSL/TLS → Overview → Full (strict)`);
  ok(["1.2", "1.3"].includes(s.min_tls_version), "Minimum TLS 1.2+", s.min_tls_version, `is ${s.min_tls_version}`);
  ok(s.always_use_https === "on", "Always Use HTTPS", s.always_use_https, "off — SSL/TLS → Edge Certificates");
  ok(s.tls_1_3 && s.tls_1_3 !== "off", "TLS 1.3 enabled", s.tls_1_3, "off");
  const hsts = s.security_header?.strict_transport_security;
  if (hsts?.enabled && hsts.max_age >= 15552000) pass("HSTS at the edge", `max-age ${hsts.max_age}`);
  else warn("HSTS at the edge", "off at zone level (the Worker still sends it; turning it on also covers Access pages)");
  if (s.security_level === "essentially_off") fail("Security level", "essentially_off");
  else pass("Security level", s.security_level);
  if (s.browser_check !== "on") warn("Browser integrity check", String(s.browser_check));
});

await safe("DNSSEC readable", async () => {
  const d = await api(`/zones/${ZONE}/dnssec`);
  if (d.status === "active") pass("DNSSEC active");
  else warn("DNSSEC", `${d.status} — DNS → Settings → enable DNSSEC (protects the domain from spoofing)`);
});

// ---------- Access: org-level sign-in + MFA ----------
let org = {};
await safe("Access organization readable", async () => {
  org = await api(`/accounts/${ACCOUNT}/access/organizations`);
  if (APP_MFA) {
    pass("Authenticator-app step enforced", "by the dashboard itself (MFA_MODE=app)");
    return;
  }
  const mfa = org.mfa_config ?? {};
  ok((mfa.allowed_authenticators ?? []).includes("totp"), "Authenticator-app MFA allowed", (mfa.allowed_authenticators ?? []).join(", "), "totp not in allowed_authenticators — Zero Trust → Access settings → MFA");
  ok(mfa.amr_matching_enabled !== true, "Identity-provider MFA can't stand in for the app code", "AMR matching off",
    "AMR matching is ON: a login method that reports its own 'otp' could skip the authenticator-app step. Turn off \"Use identity provider MFA\".");
  const mh = hours(mfa.session_duration);
  if (!isNaN(mh)) ok(mh <= MAX_HOURS, `MFA re-check at least every ${MAX_HOURS}h`, mfa.session_duration, `is ${mfa.session_duration}`);
});

await safe("Identity providers readable", async () => {
  const idps = await api(`/accounts/${ACCOUNT}/access/identity_providers`);
  const types = idps.map((i) => i.type);
  if (types.includes("onetimepin")) pass("Email one-time PIN login available");
  else warn("Email one-time PIN login", `not configured (found: ${types.join(", ") || "none"})`);
});

// ---------- Access: the dashboard's application ----------
const hostOf = (d) => String(d ?? "").replace(/^https?:\/\//, "").toLowerCase();
const domainsOf = (a) => [a.domain, ...(a.self_hosted_domains ?? []), ...(a.destinations ?? []).map((d) => d.uri)].filter(Boolean).map(hostOf);

await safe("Access applications readable", async () => {
  const apps = await api(`/accounts/${ACCOUNT}/access/apps`);
  const host = HOST.toLowerCase();
  const matching = apps.filter((a) => domainsOf(a).some((d) => d === host || d.startsWith(host + "/") || d === `*.${host.split(".").slice(1).join(".")}`));
  const whole = matching.filter((a) => domainsOf(a).some((d) => d === host || d === host + "/*" || d === host + "/"));
  if (!whole.length) {
    fail(`Access app covers all of ${HOST}`, matching.length ? "only part of the site is covered" : "no Access application found for this hostname");
    return;
  }
  pass(`Access app covers all of ${HOST}`, whole.map((a) => a.name).join(", "));

  for (const a of matching) {
    const label = `[${a.name}]`;
    const mfa = a.mfa_config;
    if (APP_MFA) {
      /* the dashboard enforces the second step */
    } else if (mfa?.mfa_disabled === true) fail(`${label} MFA not disabled for this app`, "MFA is disabled for this app");
    else if (mfa && mfa.mfa_disabled === false) pass(`${label} app requires MFA`);
    else ok(org.mfa_required_for_all_apps === true, `${label} app requires MFA`, "via account-wide setting",
      "MFA isn't required: set the app's MFA tab to Custom (authenticator app), or turn on \"Apply global MFA settings by default\"");

    const sh = hours(a.session_duration ?? org.session_duration ?? "24h");
    ok(sh <= MAX_HOURS, `${label} sign-in expires within ${MAX_HOURS}h`, a.session_duration ?? "(org default)", `is ${a.session_duration ?? org.session_duration}`);
    ok(a.http_only_cookie_attribute !== false, `${label} Access cookie is HttpOnly`, "", "turn on HttpOnly in the app's cookie settings");
    ok(["lax", "strict"].includes(a.same_site_cookie_attribute ?? "lax"), `${label} Access cookie SameSite`, a.same_site_cookie_attribute ?? "lax (default)", String(a.same_site_cookie_attribute));
    if (!a.enable_binding_cookie) warn(`${label} binding cookie`, "off — optional extra protection against stolen session cookies");

    let policies = a.policies ?? [];
    if (!policies.length || policies.some((p) => !p.include)) {
      policies = await Promise.all(
        (policies.length ? policies : await api(`/accounts/${ACCOUNT}/access/apps/${a.id}/policies`)).map((p) =>
          p.include ? p : api(`/accounts/${ACCOUNT}/access/policies/${p.id}`),
        ),
      );
    }
    if (!policies.length) fail(`${label} has an allow policy`, "no policies");
    let people = 0;
    for (const p of policies) {
      const pl = `${label} policy "${p.name}"`;
      if (p.decision === "bypass") {
        fail(`${pl} is not Bypass`, "Bypass lets anyone in without signing in");
        continue;
      }
      if (p.decision === "non_identity") {
        warn(`${pl} is a service-token policy`, "only OK for machine access you set up on purpose");
        continue;
      }
      if (!APP_MFA && p.mfa_config?.mfa_disabled === true) fail(`${pl} doesn't skip MFA`, "MFA disabled on this policy");
      const kinds = (p.include ?? []).flatMap((r) => Object.keys(r));
      const loose = kinds.filter((k) => !["email", "email_list"].includes(k));
      ok(loose.length === 0, `${pl} lists named people only`, `${kinds.length} entr${kinds.length === 1 ? "y" : "ies"}`,
        `uses ${loose.join(", ")} — replace with individual email addresses`);
      people += kinds.filter((k) => k === "email").length;
    }
    if (people) pass(`${label} named staff on allow policies`, String(people));
  }
});

// ---------- Worker: no public side doors ----------
await safe("Worker readable", async () => {
  const sub = await api(`/accounts/${ACCOUNT}/workers/scripts/${WORKER}/subdomain`);
  ok(sub.enabled === false, "workers.dev URL disabled", "", "enabled — anyone could reach the Worker outside Access");
  ok(sub.previews_enabled !== true, "Preview URLs disabled", "", "enabled — preview URLs bypass the custom domain");
});

// ---------- Report ----------
let failures = 0;
for (const r of results) {
  console.log(`${r.s} ${r.name}${r.info ? `  — ${r.info}` : ""}`);
  if (r.s === "✗") failures++;
}
const warns = results.filter((r) => r.s === "!").length;
console.log(failures ? `\n${failures} check(s) failed, ${warns} warning(s).` : `\nAll required checks passed (${warns} warning(s)).`);
process.exit(failures ? 1 : 0);
