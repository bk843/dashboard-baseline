import type { MiddlewareHandler } from "hono";
import type { SecureEnv } from "./types";

/**
 * HTTPS + HSTS and security headers on every response, including static files
 * (wrangler `run_worker_first: true` sends every request through the Worker).
 *
 * The CSP is strict by default: everything from this site only, no inline scripts, no eval.
 * A dashboard that must load something from elsewhere (e.g. a map tile server or an API the
 * browser calls directly) adds exact https origins via `CspAllow`. Wildcards, inline and eval
 * are refused at startup, so a dashboard can't weaken the policy by accident.
 */

export interface CspAllow {
  connect?: string[];
  img?: string[];
  font?: string[];
  style?: string[];
  frame?: string[];
}

const ORIGIN_RE = /^https:\/\/[a-z0-9.-]+(:\d+)?$/;

export function validateCspAllow(allow: CspAllow = {}): void {
  for (const [kind, list] of Object.entries(allow)) {
    for (const src of list ?? []) {
      if (!ORIGIN_RE.test(src)) {
        throw new Error(`CSP ${kind}: "${src}" is not allowed. Use an exact https origin like https://api.example.com (no wildcards, no 'unsafe-*', no paths).`);
      }
    }
  }
}

export function buildCsp(isProd: boolean, allow: CspAllow = {}): string {
  const src = (base: string[], extra?: string[]) => [...base, ...(extra ?? [])].join(" ");
  return [
    "default-src 'self'",
    "script-src 'self'",
    `style-src ${src(["'self'"], allow.style)}`,
    `img-src ${src(["'self'", "data:"], allow.img)}`,
    `font-src ${src(["'self'"], allow.font)}`,
    `connect-src ${src(["'self'"], allow.connect)}`,
    `frame-src ${src(["'none'"].filter(() => !allow.frame?.length), allow.frame)}`,
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "worker-src 'none'",
    "manifest-src 'self'",
    ...(isProd ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
}

export const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy":
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Permitted-Cross-Domain-Policies": "none",
};

const CORS_HEADERS = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods"];

export const securityHeaders = <E extends SecureEnv>(allow: CspAllow = {}): MiddlewareHandler<E> => {
  validateCspAllow(allow);
  return async (c, next) => {
    const isProd = (c.env as { ENVIRONMENT?: string }).ENVIRONMENT === "production";
    const url = new URL(c.req.url);
    if (isProd && url.protocol === "http:") {
      url.protocol = "https:";
      return c.redirect(url.toString(), 301);
    }
    await next();
    // Copy into a mutable response (asset responses can have immutable headers).
    c.res = new Response(c.res.body, c.res);
    const h = c.res.headers;
    h.set("Content-Security-Policy", buildCsp(isProd, allow));
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) h.set(k, v);
    if (isProd) h.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    for (const k of CORS_HEADERS) h.delete(k);
    // Signed-in data must never be cached by the browser or a proxy.
    if (url.pathname.startsWith("/api/") || (c.res.headers.get("Content-Type") ?? "").includes("text/html")) h.set("Cache-Control", "no-store");
    h.delete("X-Powered-By");
    h.delete("Server");
  };
};
