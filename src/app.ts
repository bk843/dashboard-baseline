import { Hono } from "hono";
import { ZodError, type z } from "zod";
import type { BaseBindings, SecureEnv } from "./types";
import { ConfigError, loadConfig, type BaseConfig } from "./config";
import { HttpError } from "./errors";
import { log } from "./log";
import { securityHeaders, type CspAllow } from "./headers";
import { authenticate, type AuthDeps } from "./auth";
import { csrfProtect, issueCsrfToken, sameOriginOnly } from "./csrf";
import { jsonBodiesOnly, rateLimit } from "./limits";
import { mfaGate, registerMfaAssets, registerMfaRoutes } from "./mfa/index";

export interface SecureAppOptions<C extends BaseConfig, B extends BaseBindings> {
  /** Config schema from defineConfig(). */
  config: z.ZodType<C>;
  /** Extra bindings the app can't run without (e.g. "DB"). ASSETS and RL_API are always required. */
  requiredBindings?: string[];
  /** Register API routes here. They are mounted under /api, AFTER every security check. */
  api: (api: Hono<SecureEnv<C, B>>) => void;
  /** Exact https origins the browser may load from, if the dashboard needs any. */
  csp?: CspAllow;
  /** Larger body limits for specific paths, e.g. { "/api/import": 600 * 1024 }. Default 64 KB. */
  bodyLimits?: Record<string, number>;
  /** Test hooks. */
  deps?: AuthDeps;
}

/**
 * Builds a dashboard Worker with the full security baseline already in place.
 * The order is fixed here on purpose, so no dashboard can put a route in front of auth:
 *
 *   security headers → config check → sign-in check → 2FA check (MFA_MODE=app) →
 *   (API only) same-origin, JSON-only,
 *   rate limit, CSRF → your routes → 404 → static UI → safe error handler
 *
 * There is deliberately no way to add an unauthenticated route. Every page and API call
 * requires a signed-in, allow-listed staff member.
 */
export function createSecureApp<C extends BaseConfig, B extends BaseBindings = BaseBindings>(opts: SecureAppOptions<C, B>) {
  type E = SecureEnv<C, B>;
  const app = new Hono<E>();

  app.use("*", securityHeaders<E>(opts.csp));

  app.use("*", async (c, next) => {
    c.set("requestId", crypto.randomUUID());
    c.set("config", loadConfig(opts.config, c.env as Record<string, unknown>, opts.requiredBindings));
    await next();
    c.res.headers.set("X-Request-Id", c.get("requestId"));
  });

  app.use("*", authenticate<E>(opts.deps));
  // MFA_MODE=app: nothing past this point until the authenticator-app step is done.
  app.use("*", mfaGate<E>());
  registerMfaAssets(app);

  app.use("/api/*", sameOriginOnly<E>(), jsonBodiesOnly<E>(opts.bodyLimits), rateLimit<E>("RL_API", "api"), csrfProtect<E>());

  const api = new Hono<E>();
  api.get("/me", (c) => c.json(c.get("user")));
  api.get("/csrf", async (c) => c.json({ token: await issueCsrfToken(c) }));
  registerMfaRoutes(api);
  opts.api(api);
  app.route("/api", api);
  app.all("/api/*", () => {
    throw new HttpError(404, "not_found");
  });

  // Static UI (already authenticated above).
  app.get("*", async (c) => {
    const res = await c.env.ASSETS.fetch(c.req.raw);
    return new Response(res.body, res);
  });
  app.all("*", () => {
    throw new HttpError(404, "not_found");
  });

  // No stack traces or internals in responses, ever.
  app.onError((err, c) => {
    let requestId: string | undefined;
    try {
      requestId = c.get("requestId");
    } catch {
      requestId = undefined;
    }
    if (err instanceof HttpError) {
      return c.json({ error: err.code, ...(err.publicMessage ? { message: err.publicMessage } : {}) }, err.status);
    }
    if (err instanceof ZodError) {
      return c.json({ error: "invalid_input", issues: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })) }, 400);
    }
    if (err instanceof ConfigError) {
      log("error", "config.invalid", { problems: err.problems });
      return c.json({ error: "service_unavailable" }, 503);
    }
    log("error", "unhandled", { requestId, name: err.name, message: err.message, path: new URL(c.req.url).pathname });
    return c.json({ error: "internal_error", requestId }, 500);
  });

  return app;
}
