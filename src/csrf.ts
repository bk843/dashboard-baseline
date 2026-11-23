import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { SecureEnv } from "./types";
import { HttpError } from "./errors";
import { bytesToB64url, hmac, safeEqual } from "./crypto";

/**
 * CSRF, CORS and secure cookies.
 *
 * State-changing requests must pass all of:
 *   1. Origin header equals APP_ORIGIN (or Sec-Fetch-Site: same-origin when Origin is absent).
 *   2. X-CSRF-Token header equals the CSRF cookie (double submit).
 *   3. The token's HMAC is valid, unexpired, and bound to the signed-in user.
 * The cookie is Secure, HttpOnly, SameSite=Strict, and __Host- prefixed in production.
 * Cross-origin requests and CORS preflights are refused outright: no other site may call the API.
 */

const SAFE_METHODS = new Set(["GET", "HEAD"]);
const MAX_AGE_S = 8 * 60 * 60;

const base = (c: Context) => c as unknown as Context<SecureEnv>;

export function csrfCookieName(c: Context): string {
  return base(c).get("config").ENVIRONMENT === "production" ? "__Host-csrf" : "csrf";
}

async function sign(secret: string, nonce: string, email: string, issued: number): Promise<string> {
  return hmac(secret, `csrf|${nonce}|${email}|${issued}`);
}

export async function issueCsrfToken(c: Context): Promise<string> {
  const cfg = base(c).get("config");
  const nonce = bytesToB64url(crypto.getRandomValues(new Uint8Array(18)));
  const issued = Math.floor(Date.now() / 1000);
  const token = `${nonce}.${issued}.${await sign(cfg.CSRF_SECRET, nonce, base(c).get("user").email, issued)}`;
  const secure = !(cfg.ENVIRONMENT === "development" && cfg.APP_ORIGIN.startsWith("http://"));
  setCookie(c, csrfCookieName(c), token, { httpOnly: true, secure, sameSite: "Strict", path: "/", maxAge: MAX_AGE_S });
  return token;
}

export const sameOriginOnly =
  <E extends SecureEnv>(): MiddlewareHandler<E> =>
  async (c, next) => {
    const origin = c.req.header("Origin");
    if (c.req.method === "OPTIONS") throw new HttpError(403, "cross_origin_blocked");
    if (origin && origin !== base(c).get("config").APP_ORIGIN) throw new HttpError(403, "cross_origin_blocked");
    return next();
  };

export const csrfProtect =
  <E extends SecureEnv>(): MiddlewareHandler<E> =>
  async (c, next) => {
    if (SAFE_METHODS.has(c.req.method)) return next();
    const cfg = base(c).get("config");

    const origin = c.req.header("Origin");
    const site = c.req.header("Sec-Fetch-Site");
    if (origin ? origin !== cfg.APP_ORIGIN : site !== "same-origin") throw new HttpError(403, "csrf_origin");

    const header = c.req.header("X-CSRF-Token") ?? "";
    const cookie = getCookie(c, csrfCookieName(c)) ?? "";
    if (!header || !safeEqual(header, cookie)) throw new HttpError(403, "csrf_token");

    const [nonce, issuedStr, mac] = header.split(".");
    const issued = Number(issuedStr);
    if (!nonce || !mac || !Number.isInteger(issued) || Date.now() / 1000 - issued > MAX_AGE_S) throw new HttpError(403, "csrf_token");
    const expected = await sign(cfg.CSRF_SECRET, nonce, base(c).get("user").email, issued);
    if (!safeEqual(mac, expected)) throw new HttpError(403, "csrf_token");
    return next();
  };
