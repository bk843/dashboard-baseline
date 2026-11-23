# The dashboard security baseline

Every public-facing client dashboard meets all of this. Column 3 is what makes it automatic.
Items marked **(audit)** live in the client's Cloudflare account and are checked by
`dashboard-security-kit check-cloudflare` before every deploy and weekly.

## 1. Who can get in

| Control | Detail | Enforced by |
|---|---|---|
| Sign-in in front of everything | Cloudflare Access covers the whole hostname; no public routes exist | Access app **(audit)**; `createSecureApp` has no way to add an unauthenticated route; conformance tests |
| Two factors | Email one-time PIN + authenticator app (TOTP). Either Cloudflare Access enforces the app step (`MFA_MODE=access`, paid feature) or the dashboard does (`MFA_MODE=app`, any plan) | Access MFA settings **(audit)**, or the kit's 2FA gate + conformance tests |
| Emailed code can't replace the app code | "Use identity provider MFA" (AMR matching) off (access mode) | **(audit)** fails if on |
| App-mode 2FA hardening | Nothing reachable before the second step except the 2FA screen; authenticator secrets AES-256-GCM encrypted and bound to each user; codes single-use; 5 wrong codes → 15-min lock, doubling (max 24h); signed HttpOnly session cookie bound to the user's current authenticator; admin reset ends sessions at once; admins can't reset themselves | `mfaGate()`, `MfaStore`; conformance tests (RFC 6238 vectors, replay, lockout, forged/stolen/expired cookies, reset) |
| Named people only | Allow policy lists individual emails; no Everyone / domain / Bypass rules | **(audit)** |
| Sessions expire | Sign-in and MFA re-checked at least every 12h | **(audit)** |
| Second lock in the app | Worker verifies the Access JWT (signature, issuer, audience, expiry) on every request and checks the email against `ALLOWED_EMAILS` | `authenticate()`; conformance tests (forged, expired, wrong-app, wrong-team, outsider tokens) |
| Roles | `viewer` by default, `admin` from `ADMIN_EMAILS`; `requireRole("admin")` per route | `authenticate()`, `requireRole()` |
| No side doors | Exactly one address, covered by Access. Custom domain: `workers.dev` and preview URLs off. No custom domain: the `workers.dev` address is the one address (Access on it), preview URLs off | `wrangler.jsonc`; **(audit)**, which detects workers.dev mode from the hostname; `check-live` |

## 2. What the app does on every request

| Control | Enforced by |
|---|---|
| Refuses to run with missing, placeholder, or unsafe config (e.g. dev sign-in in production, http origin) | `defineConfig()` / `loadConfig()`; conformance tests |
| Strict CSP (no inline script, no eval, no other sites unless an exact https origin is added), no framing, nosniff, no referrer, locked-down permissions | `securityHeaders()`; CSP additions validated at startup |
| HTTPS only + HSTS (2 years, preload) | `securityHeaders()`; zone settings **(audit)** |
| No CORS: other sites can't call the API; preflights refused | `sameOriginOnly()` |
| CSRF: Origin check + double-submit token bound to the user, HMAC-signed, 8h expiry; cookie `__Host-`, Secure, HttpOnly, SameSite=Strict | `csrfProtect()` |
| JSON-only bodies, 64 KB default cap | `jsonBodiesOnly()` |
| Input validation with zod on every body/query | `readJson()` / `readQuery()` |
| Rate limit per user (120/min default) | `rateLimit()` + `RL_API` binding (required) |
| Signed-in pages and data never cached | `Cache-Control: no-store` on API + HTML |
| Errors reveal nothing: generic codes, no stack traces, request ID for support | `createSecureApp` error handler |
| Logs never contain secrets (masked by name and by shape) | `log()` / `redact()` |

## 3. Secrets

| Control | Enforced by |
|---|---|
| Secrets only in Worker secrets / GitHub encrypted secrets, never in git | `.gitignore`; gitleaks pre-commit hook + CI over full history |
| Feature code reads keys only via `requireSecret()`, sends them in headers, never in URLs | lint preset |
| Browser bundle contains no keys, secret names, real `.env` values, or source maps | `check-bundle` in CI and before deploy; Vite preset (`PUBLIC_` prefix only, no source maps) |
| Browser code can't import server code | lint preset |
| Claude Code is denied reading `.env` | `.claude/settings.json` |

## 4. Code and dependencies

| Control | Enforced by |
|---|---|
| No raw HTML injection, no raw SQL, no eval | lint preset |
| Exact dependency versions, lockfile installs, Node engine pinned | `.npmrc`, `npm ci` |
| No high/critical vulnerabilities in runtime deps | `npm audit` blocks CI |
| Dependency + Actions updates proposed weekly | Dependabot |
| Third-party GitHub Actions pinned to commit SHAs | `secure-ci.yml` |

## 5. GitHub and deploys

| Control | Enforced by |
|---|---|
| Client repos private | `harden-github` warns |
| Default branch can't be force-pushed or deleted (`--strict`: PR + passing checks required) | `harden-github` ruleset |
| Workflow token read-only by default | `harden-github`; `permissions: contents: read` |
| Deploys only from `main`, only via the `production` environment, only after verify + secrets + audit pass | `secure-ci.yml`; `harden-github` environment rules |
| Deploy token is scoped to one client account + zone, stored only in that repo's `production` environment | `CLIENT-SETUP.md` |
| Separate read-only audit token | `CLIENT-SETUP.md`; `check-cloudflare` |
| Live site probed from the outside after every deploy | `check-live` |
| Client's Cloudflare settings re-audited weekly | scheduled CI run |

## Changing the baseline

Every change gets a new version tag and a line in `CHANGELOG.md`. Tightening a rule is a minor
version (`v1.1.0`). Anything that could break an existing dashboard is a major version (`v2.0.0`)
with upgrade notes. Never loosen a rule to make one dashboard work. Use that dashboard's `csp`
option, or add a reviewed, opt-in setting here.
