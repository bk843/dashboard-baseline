# Changelog

## v1.1.1 — 2026-11-23
- **Secret scan works on organization accounts.** The pipeline now runs the gitleaks CLI
  (v8.30.1, checksum verified) instead of the gitleaks GitHub Action, which needs a paid license
  on organization accounts. Same scan, same `.gitleaks.toml`, full history.
- Dashboards should pin the kit by commit ID (package and workflow), not by tag.

## v1.1.0 — 2026-11-23
- **Authenticator-app 2FA built into the kit** (`MFA_MODE=app`) for Cloudflare plans where Access
  can't enforce it. Cloudflare Access still sends the email code; the dashboard then asks for the
  authenticator-app code. Includes enrolment by QR code, encrypted secrets in D1 (`MFA_DB`),
  single-use codes, escalating lockouts, an admin view + reset, and a built-in 2FA screen.
- New settings: `MFA_MODE` (`access` default), `MFA_ENCRYPTION_KEY`, `MFA_SESSION_SECRET`,
  `MFA_SESSION_HOURS`, `MFA_ISSUER`.
- Shared security suite: 10 new 2FA tests every dashboard runs. RFC 6238 test vectors.
- `check-cloudflare` and the pipeline accept `MFA_MODE`; pipeline pushes the 2FA keys.
- New dependency: `uqr` 0.1.3 (QR codes; no dependencies of its own).

## v1.0.1 — 2026-11-23
- Renamed from `dashboard-baseline` to `dashboard-security-kit` (package, CLI command, and repo).
  Dashboards import `dashboard-security-kit` and run `dashboard-security-kit <command>`.

## v1.0.0 — 2026-11-20
- First release, a security baseline for
  multi-user client dashboards: staff list + admin/viewer roles, Access email PIN + authenticator-app
  MFA, conformance test suite, Cloudflare account audit, GitHub hardening, reusable CI/deploy pipeline.
