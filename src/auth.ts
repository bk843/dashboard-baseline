import type { Context, MiddlewareHandler } from "hono";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { Role, SecureEnv } from "./types";
import { HttpError } from "./errors";

/**
 * Auth on every route, checked on the server.
 *
 * Production: Cloudflare Access sits in front of the whole site and handles sign-in
 * (email one-time PIN) and 2FA (authenticator app). The Worker does NOT trust that blindly:
 * it verifies the signed Access JWT on every request (signature, issuer, audience, expiry)
 * and checks the email against its own ALLOWED_EMAILS list. Two independent locks.
 *
 * Development: AUTH_MODE=dev signs you in as the first ALLOWED_EMAILS entry, but only on
 * localhost and only when ENVIRONMENT=development (config refuses dev auth anywhere else).
 */

export interface AuthDeps {
  /** Override the Access signing keys (tests only). */
  getAccessKey?: JWTVerifyGetKey;
}

const jwksByTeam = new Map<string, JWTVerifyGetKey>();

function accessKeys(team: string): JWTVerifyGetKey {
  let k = jwksByTeam.get(team);
  if (!k) {
    k = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
    jwksByTeam.set(team, k);
  }
  return k;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export const authenticate =
  <E extends SecureEnv>(deps: AuthDeps = {}): MiddlewareHandler<E> =>
  async (c, next) => {
    const ctx = c as unknown as Context<SecureEnv>;
    const cfg = ctx.get("config");
    let email: string;

    if (cfg.AUTH_MODE === "dev") {
      if (cfg.ENVIRONMENT !== "development" || !LOCAL_HOSTS.has(new URL(c.req.url).hostname)) throw new HttpError(403, "forbidden");
      email = cfg.ALLOWED_EMAILS[0]!;
    } else {
      const token = c.req.header("Cf-Access-Jwt-Assertion");
      if (!token) throw new HttpError(401, "unauthenticated");
      let claim: unknown;
      try {
        const { payload } = await jwtVerify(token, deps.getAccessKey ?? accessKeys(cfg.ACCESS_TEAM_DOMAIN), {
          issuer: cfg.ACCESS_TEAM_DOMAIN,
          audience: cfg.ACCESS_AUD,
          algorithms: ["RS256"],
          clockTolerance: 30,
          requiredClaims: ["exp", "iat", "email"],
        });
        claim = payload.email;
      } catch {
        throw new HttpError(403, "invalid_session");
      }
      if (typeof claim !== "string") throw new HttpError(403, "forbidden");
      email = claim.toLowerCase();
      if (!cfg.ALLOWED_EMAILS.includes(email)) throw new HttpError(403, "forbidden");
    }

    ctx.set("user", { email, role: cfg.ADMIN_EMAILS.includes(email) ? "admin" : "viewer" });
    return next();
  };

/** Route-level role check, e.g. `api.post("/settings", requireRole("admin"), handler)`. */
export const requireRole =
  <E extends SecureEnv>(...roles: Role[]): MiddlewareHandler<E> =>
  async (c, next) => {
    const user = (c as unknown as Context<SecureEnv>).get("user");
    if (!user || !roles.includes(user.role)) throw new HttpError(403, "forbidden");
    return next();
  };
