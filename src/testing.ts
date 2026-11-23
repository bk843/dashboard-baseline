/**
 * Test helpers + the security conformance suite.
 *
 * Every dashboard runs `securityConformance(...)` in its own test folder, so the same
 * security checks run against every client's real app, not just against this package.
 */
import { describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose";
import type { AuthDeps } from "./auth";
import { base32Decode, codeForStep, stepAt } from "./mfa/totp";

export const DEV_ORIGIN = "http://localhost:8787";
export const PROD_ORIGIN = "https://dash.example.com";
export const TEAM = "https://test-team.cloudflareaccess.com";
export const AUD = "a".repeat(64);
export const ADMIN = "admin@example.com";
export const VIEWER = "viewer@example.com";
export const OUTSIDER = "outsider@example.com";
export const CSRF_SECRET = "test-csrf-secret-0123456789abcdefghijklmnop";

/** Test-only 2FA keys (32 random-looking bytes, base64). */
export const MFA_ENCRYPTION_KEY = "dGVzdC1tZmEta2V5LTAxMjM0NTY3ODlhYmNkZWZnaGk=";
export const MFA_SESSION_SECRET = "test-mfa-session-secret-0123456789abcdef";

/** In-memory D1 (real SQLite) for tests. */
export function makeD1(): D1Database {
  const db = new DatabaseSync(":memory:");
  type P = string | number | null;
  const stmt = (sql: string, params: P[] = []) => ({
    bind: (...p: unknown[]) => stmt(sql, p.map((v) => (v === undefined ? null : (v as P)))),
    first: async () => db.prepare(sql).get(...params) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...params), success: true, meta: {} }),
    run: async () => {
      const r = db.prepare(sql).run(...params);
      return { success: true, results: [], meta: { changes: Number(r.changes) } };
    },
  });
  return { prepare: (sql: string) => stmt(sql) } as unknown as D1Database;
}

/** Env for MFA_MODE=app (dev sign-in). Pass a shared `db` to simulate several users. */
export function mfaEnv(overrides: Env = {}, db: D1Database = makeD1(), extra: Env = {}): Env {
  return devEnv({ MFA_MODE: "app", MFA_ENCRYPTION_KEY, MFA_SESSION_SECRET, MFA_DB: db, ...overrides }, extra);
}

/** The current authenticator code for a base32 secret (offset in 30-second steps). */
export function currentCode(secretB32: string, offsetSteps = 0): Promise<string> {
  return codeForStep(base32Decode(secretB32), stepAt(Date.now()) + offsetSteps);
}

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

/** A tiny browser: keeps cookies and sends the CSRF token on changes. */
export function browser(app: RequestableApp, env: Env, origin = DEV_ORIGIN) {
  const jar = new Map<string, string>();
  const req = async (path: string, init: { method?: string; body?: unknown } = {}) => {
    const method = init.method ?? (init.body === undefined ? "GET" : "POST");
    const headers: Record<string, string> = { Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") };
    if (method !== "GET") Object.assign(headers, { "Content-Type": "application/json", Origin: origin, "X-CSRF-Token": jar.get("csrf") ?? "" });
    const r = await app.request(origin + path, { method, headers, body: init.body === undefined ? undefined : JSON.stringify(init.body) }, env);
    for (const sc of r.headers.getSetCookie()) {
      const kv = sc.split(";")[0]!;
      const i = kv.indexOf("=");
      jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
    return r;
  };
  return { req, jar, csrf: () => req("/api/csrf") };
}

/** Signs a dev browser through 2FA enrolment. Returns the browser and the authenticator secret. */
export async function enrolled(app: RequestableApp, env: Env) {
  const b = browser(app, env);
  await b.csrf();
  const start = await b.req("/api/mfa/enroll/start", { body: {} });
  const { secret } = (await start.json()) as { secret: string };
  const r = await b.req("/api/mfa/enroll/confirm", { body: { code: await currentCode(secret) } });
  if (r.status !== 200) throw new Error(`enrolment failed: ${r.status} ${await r.text()}`);
  return { b, secret };
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

  describe("baseline: authenticator-app 2FA (MFA_MODE=app)", () => {
    const app = opts.createApp({});
    const env = (o: Env = {}, db?: D1Database) => mfaEnv(o, db, extra());
    const apiPaths = paths.filter((p) => p.startsWith("/api/"));

    it("refuses to run without its keys or database", async () => {
      for (const o of [{ MFA_ENCRYPTION_KEY: undefined }, { MFA_SESSION_SECRET: undefined }, { MFA_DB: undefined }, { MFA_ENCRYPTION_KEY: "c2hvcnQta2V5LXNob3J0LWtleS1zaG9ydC1rZXkt" }, { MFA_SESSION_SECRET: MFA_ENCRYPTION_KEY }]) {
        const r = await app.request(DEV_ORIGIN + "/api/me", undefined, env(o));
        expect(r.status, JSON.stringify(Object.keys(o))).toBe(503);
      }
    });
    it("2FA endpoints don't exist when Cloudflare Access does 2FA", async () => {
      expect((await app.request(DEV_ORIGIN + "/api/mfa/status", undefined, dEnv())).status).toBe(404);
      expect((await app.request(DEV_ORIGIN + "/api/admin/mfa", undefined, dEnv())).status).toBe(404);
    });
    it("before the second step: pages show the 2FA screen, every API call is refused", async () => {
      const e = env();
      const page = await app.request(DEV_ORIGIN + "/", undefined, e);
      expect(page.status).toBe(200);
      expect(await page.text()).toContain("Two-step verification");
      expect(page.headers.get("content-security-policy")).toContain("script-src 'self'");
      expect(page.headers.get("cache-control")).toBe("no-store");
      for (const p of apiPaths) {
        const r = await app.request(DEV_ORIGIN + p, undefined, e);
        expect(r.status, p).toBe(401);
        expect(await r.json()).toEqual({ error: "mfa_required" });
      }
      const js = await app.request(DEV_ORIGIN + "/__mfa/mfa.js", undefined, e);
      expect(js.headers.get("content-type")).toContain("javascript");
    });
    it("enrolment: QR code + key, wrong code refused, right code unlocks everything", async () => {
      const b = browser(app, env());
      await b.csrf();
      const start = await b.req("/api/mfa/enroll/start", { body: {} });
      const { secret, qr } = (await start.json()) as { secret: string; qr: string };
      expect(qr).toMatch(/^data:image\/svg\+xml;base64,/);
      expect(secret).toMatch(/^[A-Z2-7]{32}$/);
      const wrong = (await currentCode(secret)) === "000000" ? "111111" : "000000";
      expect((await b.req("/api/mfa/enroll/confirm", { body: { code: wrong } })).status).toBe(400);
      expect((await b.req("/api/mfa/enroll/confirm", { body: { code: await currentCode(secret) } })).status).toBe(200);
      expect(b.jar.get("mfa")).toBeTruthy();
      for (const p of paths) expect((await b.req(p)).status, p).toBe(200);
      expect((await b.req("/api/mfa/enroll/start", { body: {} })).status).toBe(409);
    });
    it("2FA cookie is HttpOnly and SameSite=Strict", async () => {
      const b = browser(app, env());
      await b.csrf();
      const { secret } = (await (await b.req("/api/mfa/enroll/start", { body: {} })).json()) as { secret: string };
      const r = await b.req("/api/mfa/enroll/confirm", { body: { code: await currentCode(secret) } });
      const sc = r.headers.getSetCookie().find((c) => c.startsWith("mfa=")) ?? "";
      expect(sc).toMatch(/HttpOnly/i);
      expect(sc).toMatch(/SameSite=Strict/i);
    });
    it("a code can't be used twice", async () => {
      const db = makeD1();
      const e = env({}, db);
      const { secret } = await enrolled(app, e);
      const b2 = browser(app, e);
      await b2.csrf();
      expect((await b2.req("/api/mfa/verify", { body: { code: await currentCode(secret) } })).status).toBe(400);
      expect((await b2.req("/api/mfa/verify", { body: { code: await currentCode(secret, 1) } })).status).toBe(200);
      expect((await b2.req("/api/me")).status).toBe(200);
    });
    it("five wrong codes lock the account, even against the right code", async () => {
      const e = env({}, makeD1());
      const { secret } = await enrolled(app, e);
      const b = browser(app, e);
      await b.csrf();
      const statuses = [];
      for (let i = 0; i < 5; i++) statuses.push((await b.req("/api/mfa/verify", { body: { code: "000000" } })).status);
      expect(statuses.slice(0, 4).every((s) => s === 400)).toBe(true);
      expect(statuses[4]).toBe(429);
      const r = await b.req("/api/mfa/verify", { body: { code: await currentCode(secret, 1) } });
      expect(r.status).toBe(429);
      expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(800);
    });
    it("forged, other people's and expired 2FA cookies are refused", async () => {
      const db = makeD1();
      const adminEnv = env({}, db);
      const viewerEnv = env({ ALLOWED_EMAILS: `${VIEWER},${ADMIN}` }, db);
      const { b } = await enrolled(app, adminEnv);
      await enrolled(app, viewerEnv);
      const good = b.jar.get("mfa")!;
      const forged = browser(app, adminEnv);
      forged.jar.set("mfa", good.slice(0, -3) + "xyz");
      expect((await forged.req("/api/me")).status).toBe(401);
      const stolen = browser(app, viewerEnv);
      stolen.jar.set("mfa", good);
      expect((await stolen.req("/api/me")).status).toBe(401);
      vi.useFakeTimers({ toFake: ["Date"] });
      try {
        vi.setSystemTime(Date.now() + 13 * 3600_000);
        expect((await b.req("/api/me")).status).toBe(401);
      } finally {
        vi.useRealTimers();
      }
    });
    it("admins see who has 2FA and can reset others (ending their session), not themselves", async () => {
      const db = makeD1();
      const adminEnv = env({}, db);
      const viewerEnv = env({ ALLOWED_EMAILS: `${VIEWER},${ADMIN}` }, db);
      const { b: admin } = await enrolled(app, adminEnv);
      const { b: viewer } = await enrolled(app, viewerEnv);
      const list = (await (await admin.req("/api/admin/mfa")).json()) as { email: string; enrolled: boolean }[];
      expect(list.filter((u) => u.enrolled).map((u) => u.email).sort()).toEqual([ADMIN, VIEWER]);
      expect((await viewer.req("/api/admin/mfa")).status).toBe(403);
      expect((await viewer.req("/api/admin/mfa/reset", { body: { email: ADMIN } })).status).toBe(403);
      expect((await admin.req("/api/admin/mfa/reset", { body: { email: ADMIN } })).status).toBe(400);
      expect((await admin.req("/api/admin/mfa/reset", { body: { email: VIEWER } })).status).toBe(200);
      expect((await viewer.req("/api/me")).status).toBe(401);
      expect((await (await viewer.req("/api/mfa/status")).json())).toEqual({ enrolled: false });
    });
  });
}
