# dashboard-baseline

The shared security layer for every client dashboard on Cloudflare Workers. Dashboards install
it from GitHub at a pinned version, so a fix here reaches every dashboard with one version bump.

**What it enforces:** see [BASELINE.md](BASELINE.md).

## What's inside

| Path | What it is |
|---|---|
| `src/` | `createSecureApp()` and the middleware: Access JWT check, staff list + roles, CSRF, headers/CSP, rate limits, JSON-only bodies, config validation, safe errors, redacted logging, crypto helpers |
| `src/testing.ts` | `securityConformance()`: the shared security test suite every dashboard runs against its own app |
| `eslint/` | `securityLint()`: lint rules (no raw HTML/SQL, no keys in URLs, no server code in the browser) |
| `vite/` | `secureVite()`: safe build settings (no source maps, nothing inlined, `PUBLIC_` env only) |
| `bin/` | CLI `dashboard-baseline …`: `setup-dev`, `check-bundle`, `check-live`, `check-cloudflare`, `harden-github` |
| `.github/workflows/secure-ci.yml` | The reusable pipeline every dashboard calls: verify → secret scan → Cloudflare audit → deploy → live check |

## Working on it

```bash
npm install
npm run hooks      # turn on the gitleaks pre-commit hook
npm run verify     # typecheck + lint + tests
```

## Releasing a version

1. Make the change and add a line to `CHANGELOG.md`.
2. `npm run verify`
3. Bump `version` in `package.json`, commit, then tag and push:
   ```bash
   git tag v1.1.0 && git push origin main v1.1.0
   ```
4. In each dashboard: `npm install github:<you>/dashboard-baseline#v1.1.0`, bump the `@v…` in its
   `ci.yml`, run `npm run verify`, push.

## Public or private repo?

**Public is recommended.** This repo contains no secrets or client data, only defensive code, and
good security doesn't depend on hiding the code. Public also means dashboards can install it and
call its workflow with no extra GitHub setup, and GitHub's secret scanning is free on it.

If you keep it private, each dashboard's CI needs a read-only deploy key to install it, and you must
allow access under this repo's Settings → Actions → General → Access.
