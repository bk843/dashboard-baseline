/**
 * App-level two-step verification (MFA_MODE=app), for Cloudflare plans where Access can't
 * enforce an authenticator app itself. Cloudflare Access still does the first step (emailed
 * one-time code); this adds the second (authenticator-app code), inside the Worker.
 *
 *  - Until the second step is done, every page shows the built-in 2FA screen and every API
 *    call returns 401 mfa_required. Only the 2FA endpoints themselves are reachable.
 *  - Secrets are encrypted at rest, codes can't be reused, and wrong guesses lock the account
 *    for 15 minutes, doubling each time (max 24 hours).
 *  - The verified session is a signed, HttpOnly cookie bound to the user and to their current
 *    authenticator. An admin reset ends it immediately.
 *  - First sign-in sets up the authenticator ("trust on first use"). Admins can see who has
 *    set up 2FA and reset anyone's.
 */
import type { Context, Hono, MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { z } from "zod";
import { renderSVG } from "uqr";
import type { SecureEnv } from "../types";
import { HttpError } from "../errors";
import { hmac, safeEqual } from "../crypto";
import { log } from "../log";
import { readJson } from "../validate";
import { requireRole } from "../auth";
import { MfaStore, type MfaRow } from "./store";
import { base32Decode, base32Encode, matchCode, newSecret, otpauthUri } from "./totp";
import { MFA_PAGE_CSS, MFA_PAGE_HTML, MFA_PAGE_JS } from "./page";

export { MfaStore } from "./store";
export { codeForStep, base32Decode, stepAt } from "./totp";

const ENROLL_WINDOW_MS = 15 * 60_000;
const FAILS_PER_LOCK = 5;
const BASE_LOCK_MS = 15 * 60_000;
const MAX_LOCK_MS = 24 * 60 * 60_000;

const base = (c: Context) => c as unknown as Context<SecureEnv>;
const appMode = (c: Context) => base(c).get("config").MFA_MODE === "app";

function store(c: Context): MfaStore {
  const db = (c.env as Record<string, unknown>).MFA_DB as D1Database;
  return new MfaStore(db, base(c).get("config").MFA_ENCRYPTION_KEY!);
}

function cookieName(c: Context) {
  return base(c).get("config").ENVIRONMENT === "production" ? "__Host-mfa" : "mfa";
}

function sign(c: Context, email: string, enrolledAt: number, issued: number) {
  return hmac(base(c).get("config").MFA_SESSION_SECRET!, `mfa-session|${email}|${enrolledAt}|${issued}`);
}

async function startSession(c: Context, email: string, enrolledAt: number) {
  const cfg = base(c).get("config");
  const issued = Date.now();
  const value = `${enrolledAt}.${issued}.${await sign(c, email, enrolledAt, issued)}`;
  const secure = !(cfg.ENVIRONMENT === "development" && cfg.APP_ORIGIN.startsWith("http://"));
  setCookie(c, cookieName(c), value, { httpOnly: true, secure, sameSite: "Strict", path: "/", maxAge: cfg.MFA_SESSION_HOURS * 3600 });
}

async function hasSession(c: Context): Promise<boolean> {
  const cfg = base(c).get("config");
  const email = base(c).get("user").email;
  const [enrolledStr, issuedStr, mac] = (getCookie(c, cookieName(c)) ?? "").split(".");
  const enrolledAt = Number(enrolledStr);
  const issued = Number(issuedStr);
  if (!mac || !Number.isInteger(enrolledAt) || !Number.isInteger(issued)) return false;
  const now = Date.now();
  if (issued > now + 60_000 || now - issued > cfg.MFA_SESSION_HOURS * 3600_000) return false;
  if (!safeEqual(mac, await sign(c, email, enrolledAt, issued))) return false;
  // Still the same authenticator? (An admin reset or re-enrolment ends old sessions.)
  const row = await store(c).get(email);
  return !!row?.secret && row.enrolled_at === enrolledAt;
}

/** Blocks everything until the second step is done. Runs right after sign-in is verified. */
export const mfaGate =
  <E extends SecureEnv>(): MiddlewareHandler<E> =>
  async (c, next) => {
    if (!appMode(c)) return next();
    const path = new URL(c.req.url).pathname;
    if (path.startsWith("/__mfa/") || path === "/api/csrf" || path.startsWith("/api/mfa/")) return next();
    if (await hasSession(c)) return next();
    if (path.startsWith("/api/") || (c.req.method !== "GET" && c.req.method !== "HEAD")) throw new HttpError(401, "mfa_required");
    return c.html(MFA_PAGE_HTML);
  };

/** The 2FA screen's own script and stylesheet (same-origin, so the strict CSP allows them). */
export function registerMfaAssets<E extends SecureEnv>(app: Hono<E>) {
  const a = app as unknown as Hono;
  a.get("/__mfa/mfa.js", (c) => c.body(MFA_PAGE_JS, 200, { "Content-Type": "text/javascript; charset=utf-8" }));
  a.get("/__mfa/mfa.css", (c) => c.body(MFA_PAGE_CSS, 200, { "Content-Type": "text/css; charset=utf-8" }));
}

function checkLock(c: Context, row: MfaRow | null) {
  const wait = (row?.locked_until ?? 0) - Date.now();
  if (wait > 0) {
    c.header("Retry-After", String(Math.ceil(wait / 1000)));
    throw new HttpError(429, "locked");
  }
}

async function failed(c: Context, row: MfaRow): Promise<never> {
  const failures = row.failures + 1;
  let lockedUntil = 0;
  if (failures % FAILS_PER_LOCK === 0) {
    lockedUntil = Date.now() + Math.min(MAX_LOCK_MS, BASE_LOCK_MS * 2 ** (failures / FAILS_PER_LOCK - 1));
    log("warn", "mfa.locked", { user: row.email, failures });
  }
  await store(c).recordFailure(row.email, failures, lockedUntil);
  throw new HttpError(lockedUntil ? 429 : 400, lockedUntil ? "locked" : "invalid_code");
}

const codeBody = z.object({ code: z.string().trim().max(10) });

/** /api/mfa/* (reachable before the second step) and /api/admin/mfa* (behind it, admins only). */
export function registerMfaRoutes<E extends SecureEnv>(api: Hono<E>) {
  const a = api as unknown as Hono<SecureEnv>;
  a.use("/mfa/*", async (c, next) => {
    if (!appMode(c)) throw new HttpError(404, "not_found");
    return next();
  });
  a.use("/admin/mfa*", async (c, next) => {
    if (!appMode(c)) throw new HttpError(404, "not_found");
    return next();
  });

  a.get("/mfa/status", async (c) => {
    const row = await store(c).get(c.get("user").email);
    return c.json({ enrolled: !!row?.secret });
  });

  a.post("/mfa/enroll/start", async (c) => {
    const email = c.get("user").email;
    const s = store(c);
    const row = await s.get(email);
    if (row?.secret) throw new HttpError(409, "already_enrolled");
    checkLock(c, row);
    const secret = base32Encode(newSecret());
    await s.setPending(email, await s.encrypt(email, secret), Date.now());
    const cfg = c.get("config");
    const issuer = cfg.MFA_ISSUER || new URL(cfg.APP_ORIGIN).hostname;
    const svg = renderSVG(otpauthUri(issuer, email, secret), { border: 1 });
    log("info", "mfa.enroll_started", { user: email });
    return c.json({ secret, qr: `data:image/svg+xml;base64,${btoa(svg)}` });
  });

  a.post("/mfa/enroll/confirm", async (c) => {
    const { code } = await readJson(c, codeBody);
    const email = c.get("user").email;
    const s = store(c);
    const row = await s.get(email);
    if (row?.secret) throw new HttpError(409, "already_enrolled");
    if (!row?.pending_secret || !row.pending_at || Date.now() - row.pending_at > ENROLL_WINDOW_MS) throw new HttpError(400, "enrollment_expired");
    checkLock(c, row);
    const step = await matchCode(base32Decode(await s.decrypt(email, row.pending_secret)), code, Date.now(), row.last_step);
    if (step === null || !(await s.useStep(email, step))) return failed(c, row);
    const now = Date.now();
    await s.confirm(email, now);
    await startSession(c, email, now);
    log("info", "mfa.enrolled", { user: email });
    return c.json({ ok: true });
  });

  a.post("/mfa/verify", async (c) => {
    const { code } = await readJson(c, codeBody);
    const email = c.get("user").email;
    const s = store(c);
    const row = await s.get(email);
    if (!row?.secret || !row.enrolled_at) throw new HttpError(409, "not_enrolled");
    checkLock(c, row);
    const step = await matchCode(base32Decode(await s.decrypt(email, row.secret)), code, Date.now(), row.last_step);
    if (step === null || !(await s.useStep(email, step))) return failed(c, row);
    await startSession(c, email, row.enrolled_at);
    return c.json({ ok: true });
  });

  a.get("/admin/mfa", requireRole("admin"), async (c) => {
    const cfg = c.get("config");
    const rows = new Map((await store(c).list()).map((r) => [r.email, r]));
    const now = Date.now();
    return c.json(
      cfg.ALLOWED_EMAILS.map((email) => {
        const r = rows.get(email);
        return {
          email,
          role: cfg.ADMIN_EMAILS.includes(email) ? "admin" : "viewer",
          enrolled: !!r?.secret,
          enrolledAt: r?.enrolled_at ?? null,
          locked: (r?.locked_until ?? 0) > now,
        };
      }),
    );
  });

  a.post("/admin/mfa/reset", requireRole("admin"), async (c) => {
    const { email } = await readJson(c, z.object({ email: z.email() }));
    const target = email.toLowerCase();
    const me = c.get("user").email;
    if (target === me) throw new HttpError(400, "cannot_reset_self", "Ask another admin to reset your own two-step verification.");
    await store(c).reset(target);
    log("warn", "mfa.reset", { user: target, by: me });
    return c.json({ ok: true });
  });
}
