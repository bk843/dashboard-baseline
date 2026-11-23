import type { Context, MiddlewareHandler } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { SecureEnv } from "./types";
import { HttpError } from "./errors";

/**
 * Rate limiting per signed-in user (falls back to IP). RL_API covers every API call. Put a
 * stricter limiter (e.g. RL_EXPENSIVE) on anything that costs money, exports data, or emails.
 * Sign-in rate limiting is handled by Cloudflare Access, since the app has no login form.
 */
export const rateLimit =
  <E extends SecureEnv>(binding: string, scope: string): MiddlewareHandler<E> =>
  async (c, next) => {
    const ctx = c as unknown as Context<SecureEnv>;
    const limiter = (c.env as Record<string, unknown>)[binding] as RateLimit | undefined;
    if (!limiter) throw new HttpError(503, "service_unavailable");
    const who = ctx.get("user")?.email ?? c.req.header("CF-Connecting-IP") ?? "anon";
    const { success } = await limiter.limit({ key: `${scope}:${who}` });
    if (!success) {
      c.header("Retry-After", "60");
      throw new HttpError(429, "rate_limited");
    }
    return next();
  };

/** Request bodies: JSON only, max 64 KB unless a path is given a larger limit. No multipart uploads. */
export const jsonBodiesOnly = <E extends SecureEnv>(largerLimits: Record<string, number> = {}): MiddlewareHandler<E> => {
  const make = (maxSize: number) =>
    bodyLimit({
      maxSize,
      onError: () => {
        throw new HttpError(413, "payload_too_large");
      },
    });
  const standard = make(64 * 1024);
  const special = new Map(Object.entries(largerLimits).map(([path, size]) => [path, make(size)]));
  return async (c, next) => {
    if (c.req.method === "GET" || c.req.method === "HEAD") return next();
    const len = c.req.header("Content-Length");
    const hasBody = len !== undefined ? len !== "0" : c.req.raw.body !== null;
    const type = (c.req.header("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (hasBody && type !== "application/json") throw new HttpError(415, "unsupported_media_type");
    return (special.get(new URL(c.req.url).pathname) ?? standard)(c, next);
  };
};
