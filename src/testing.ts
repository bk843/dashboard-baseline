/**
 * Test helpers + the security conformance suite.
 *
 * Every dashboard runs `securityConformance(...)` in its own test folder, so the same
 * security checks run against every client's real app, not just against this package.
 */
import { describe, expect, it } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose";
import type { AuthDeps } from "./auth";

export const DEV_ORIGIN = "http://localhost:8787";
export const PROD_ORIGIN = "https://dash.example.com";
export const TEAM = "https://test-team.cloudflareaccess.com";
export const AUD = "a".repeat(64);
export const ADMIN = "admin@example.com";
export const VIEWER = "viewer@example.com";
export const OUTSIDER = "outsider@example.com";
export const CSRF_SECRET = "test-csrf-secret-0123456789abcdefghijklmnop";

export function makeLimiter(max = 1000): RateLimit {
  const counts = new Map<string, number>();
  return {
    async limit({ key }: { key: string }) {
      const n = (counts.get(key) ?? 0) + 1;
      counts.set(key, n);
      return { success: n <= max };
    },
  } as RateLimit;
}

export function makeAssets(html = "<!doctype html><title>Dashboard</title>"): Fetcher {
  return {
    fetch: async () => new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } }),
  } as unknown as Fetcher;
}

type Env = Record<string, unknown>;

export function devEnv(overrides: Env = {}, extra: Env = {}): Env {
  return {
    ENVIRONMENT: "development",
    APP_ORIGIN: DEV_ORIGIN,
    AUTH_MODE: "dev",
    ALLOWED_EMAILS: `${ADMIN},${VIEWER}`,
    ADMIN_EMAILS: ADMIN,
    CSRF_SECRET,
    ASSETS: makeAssets(),
    RL_API: makeLimiter(),
    ...extra,
    ...overrides,
  };
}

export function prodEnv(overrides: Env = {}, extra: Env = {}): Env {
  return devEnv(
    { ENVIRONMENT: "production", APP_ORIGIN: PROD_ORIGIN, AUTH_MODE: "access", ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ...overrides },
    extra,
  );
}

export interface MintOptions {
  wrongKey?: boolean;
  expired?: boolean;
}

/** Fake Cloudflare Access: signing keys for the app + a function to mint session tokens. */
export async function makeAccess() {
  const good = await generateKeyPair("RS256");
  const bad = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(good.publicKey)), kid: "k1", alg: "RS256" };
  const getAccessKey: JWTVerifyGetKey = createLocalJWKSet({ keys: [jwk] });
  const mint = async (claims: Record<string, unknown> = {}, o: MintOptions = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const { iss, aud, ...rest } = { iss: TEAM, aud: AUD, email: ADMIN, ...claims } as Record<string, unknown>;
    return new SignJWT({ type: "app", ...rest })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(String(iss))
      .setAudience(aud as string)
      .setIssuedAt(o.expired ? now - 7200 : now)
      .setExpirationTime(o.expired ? now - 3600 : now + 3600)
      .sign(o.wrongKey ? bad.privateKey : good.privateKey);
  };
  return { getAccessKey, mint };
}

export function cookieFrom(r: Response): string {
  return (r.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
}

interface RequestableApp {
  request(input: string, init?: RequestInit, env?: Env): Response | Promise<Response>;
}

export interface ConformanceOptions {
  /** Build the dashboard app, passing `deps` through to createSecureApp. */
  createApp: (deps: AuthDeps) => RequestableApp;
  /** Extra env the dashboard needs in tests (its own bindings and secrets). */
  extraEnv?: () => Env;
  /** Signed-in GET paths to probe, besides "/" and "/api/me". */
  paths?: string[];
}

/** Registers the shared security test suite. Call it from a dashboard's test file. */
export function securityConformance(opts: ConformanceOptions) {
  const extra = () => opts.extraEnv?.() ?? {};
  const dEnv = (o: Env = {}) => devEnv(o, extra());
  const pEnv = (o: Env = {}) => prodEnv(o, extra());
  const paths = ["/", "/api/me", ...(opts.paths ?? [])];

  describe("baseline: config refuses to run when wrong", () => {
    const app = opts.createApp({});
    const cases: [string, Env, boolean][] = [
      ["missing CSRF_SECRET", { CSRF_SECRET: undefined }, false],
      ["placeholder secret", { CSRF_SECRET: "REPLACE_ME_REPLACE_ME_REPLACE_ME_1234" }, false],
      ["no staff emails", { ALLOWED_EMAILS: "" }, false],
      ["admin not on staff list", { ADMIN_EMAILS: OUTSIDER }, false],
      ["production with dev sign-in", { AUTH_MODE: "dev" }, true],
      ["production without Access AUD", { ACCESS_AUD: "REPLACE_ME" }, true],
      ["production over http", { APP_ORIGIN: "http://dash.example.com" }, true],
      ["missing rate limiter", { RL_API: undefined }, false],
    ];
    for (const [name, o, prod] of cases) {
      it(`${name} → generic 503`, async () => {
        const r = await app.request((prod ? PROD_ORIGIN : DEV_ORIGIN) + "/api/me", undefined, prod ? pEnv(o) : dEnv(o));
        expect(r.status).toBe(503);
        expect(await r.text()).toBe('{"error":"service_unavailable"}');
      });
    }
  });

  describe("baseline: sign-in checked on the server for every page and API call", async () => {
    const { getAccessKey, mint } = await makeAccess();
    const app = opts.createApp({ getAccessKey });
    const get = async (path: string, token?: string, env = pEnv()) =>
      app.request(PROD_ORIGIN + path, { headers: token ? { "Cf-Access-Jwt-Assertion": token } : {} }, env);

    it("no session → 401 everywhere", async () => {
      for (const p of [...paths, "/api/does-not-exist", "/some/page"]) expect((await get(p)).status, p).toBe(401);
    });
    it("valid session for staff → 200, with the right role", async () => {
      const a = await get("/api/me", await mint({ email: ADMIN }));
      expect(a.status).toBe(200);
      expect(await a.json()).toEqual({ email: ADMIN, role: "admin" });
      const v = await get("/api/me", await mint({ email: VIEWER.toUpperCase() }));
      expect(await v.json()).toEqual({ email: VIEWER, role: "viewer" });
    });
    it("every probed path works when signed in", async () => {
      for (const p of paths) expect((await get(p, await mint())).status, p).toBe(200);
    });
    it("valid session for someone not on the staff list → 403", async () => {
      expect((await get("/api/me", await mint({ email: OUTSIDER }))).status).toBe(403);
    });
    it("forged, expired, wrong-app and wrong-team tokens → 403", async () => {
      expect((await get("/api/me", await mint({}, { wrongKey: true }))).status).toBe(403);
      expect((await get("/api/me", await mint({}, { expired: true }))).status).toBe(403);
      expect((await get("/api/me", await mint({ aud: "b".repeat(64) }))).status).toBe(403);
      expect((await get("/api/me", await mint({ iss: "https://evil.cloudflareaccess.com" }))).status).toBe(403);
      expect((await get("/api/me", "not-a-jwt")).status).toBe(403);
    });
    it("dev sign-in only works on localhost", async () => {
      const r = await app.request("http://dash.example.com/api/me", undefined, dEnv({ APP_ORIGIN: "http://dash.example.com" }));
      expect(r.status).toBe(403);
    });
  });

  describe("baseline: security headers", async () => {
    const { getAccessKey, mint } = await makeAccess();
    const app = opts.createApp({ getAccessKey });
    it("strict CSP, HSTS, no framing, no CORS, no caching of signed-in data", async () => {
      for (const p of paths) {
        const r = await app.request(PROD_ORIGIN + p, { headers: { "Cf-Access-Jwt-Assertion": await mint() } }, pEnv());
        const csp = r.headers.get("content-security-policy") ?? "";
        expect(csp).toContain("script-src 'self'");
        expect(csp).toContain("frame-ancestors 'none'");
        expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
        expect(r.headers.get("strict-transport-security")).toMatch(/max-age=\d{8}/);
        expect(r.headers.get("x-content-type-options")).toBe("nosniff");
        expect(r.headers.get("x-frame-options")).toBe("DENY");
        expect(r.headers.get("access-control-allow-origin")).toBeNull();
        expect(r.headers.get("cache-control"), p).toBe("no-store");
      }
    });
    it("http → https redirect in production", async () => {
      const r = await app.request("http://dash.example.com/", undefined, pEnv());
      expect(r.status).toBe(301);
      expect(r.headers.get("location")).toBe("https://dash.example.com/");
    });
    it("error responses carry headers too and reveal nothing", async () => {
      const r = await app.request(PROD_ORIGIN + "/api/me", undefined, pEnv());
      expect(r.headers.get("content-security-policy")).toBeTruthy();
      expect(await r.text()).toBe('{"error":"unauthenticated"}');
    });
  });

  describe("baseline: CSRF, CORS and request bodies", () => {
    const app = opts.createApp({});
    const session = async (env: Env) => {
      const r = await app.request(DEV_ORIGIN + "/api/csrf", undefined, env);
      const { token } = (await r.json()) as { token: string };
      return { token, cookie: cookieFrom(r), setCookie: r.headers.get("set-cookie") ?? "" };
    };
    const post = (env: Env, headers: Record<string, string>, body = "{}") =>
      app.request(DEV_ORIGIN + "/api/__baseline_probe__", { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body }, env);

    it("CSRF cookie is HttpOnly and SameSite=Strict", async () => {
      const { setCookie } = await session(dEnv());
      expect(setCookie).toMatch(/HttpOnly/i);
      expect(setCookie).toMatch(/SameSite=Strict/i);
    });
    it("POST without a token → 403", async () => {
      expect((await post(dEnv(), { Origin: DEV_ORIGIN })).status).toBe(403);
    });
    it("POST with a token but no matching cookie → 403", async () => {
      const env = dEnv();
      const { token } = await session(env);
      expect((await post(env, { Origin: DEV_ORIGIN, "X-CSRF-Token": token })).status).toBe(403);
    });
    it("POST with a tampered token → 403", async () => {
      const env = dEnv();
      const { token, cookie } = await session(env);
      const bad = token.slice(0, -2) + (token.endsWith("A") ? "BB" : "AA");
      expect((await post(env, { Origin: DEV_ORIGIN, "X-CSRF-Token": bad, Cookie: cookie.replace(token, bad) })).status).toBe(403);
    });
    it("POST from another site → 403, even with a valid token", async () => {
      const env = dEnv();
      const { token, cookie } = await session(env);
      expect((await post(env, { Origin: "https://evil.example", "X-CSRF-Token": token, Cookie: cookie })).status).toBe(403);
    });
    it("valid same-origin POST gets past the checks (reaches 404 for an unknown route)", async () => {
      const env = dEnv();
      const { token, cookie } = await session(env);
      expect((await post(env, { Origin: DEV_ORIGIN, "X-CSRF-Token": token, Cookie: cookie })).status).toBe(404);
    });
    it("cross-origin GET and CORS preflight → 403", async () => {
      expect((await app.request(DEV_ORIGIN + "/api/me", { headers: { Origin: "https://evil.example" } }, dEnv())).status).toBe(403);
      expect((await app.request(DEV_ORIGIN + "/api/me", { method: "OPTIONS", headers: { Origin: "https://evil.example" } }, dEnv())).status).toBe(403);
    });
    it("non-JSON bodies → 415, oversized bodies → 413", async () => {
      const env = dEnv();
      const { token, cookie } = await session(env);
      const h = { Origin: DEV_ORIGIN, "X-CSRF-Token": token, Cookie: cookie };
      const form = await app.request(DEV_ORIGIN + "/api/__baseline_probe__", { method: "POST", headers: { ...h, "Content-Type": "text/plain" }, body: "x" }, env);
      expect(form.status).toBe(415);
      expect((await post(env, h, JSON.stringify({ x: "y".repeat(70 * 1024) }))).status).toBe(413);
    });
  });

  describe("baseline: rate limiting and leaks", () => {
    const app = opts.createApp({});
    it("over the API limit → 429", async () => {
      const env = dEnv({ RL_API: makeLimiter(2) });
      for (let i = 0; i < 2; i++) expect((await app.request(DEV_ORIGIN + "/api/me", undefined, env)).status).toBe(200);
      expect((await app.request(DEV_ORIGIN + "/api/me", undefined, env)).status).toBe(429);
    });
    it("secrets never appear in any response", async () => {
      const env = dEnv();
      const secrets = Object.entries(env)
        .filter(([k, v]) => typeof v === "string" && /SECRET|KEY|TOKEN|PASSWORD/.test(k))
        .map(([, v]) => v as string);
      for (const p of [...paths, "/api/csrf", "/api/nope"]) {
        const r = await app.request(DEV_ORIGIN + p, undefined, env);
        const text = (await r.text()) + JSON.stringify([...r.headers]);
        for (const s of secrets) expect(text.includes(s), `${p} leaked a secret`).toBe(false);
      }
    });
  });
}
