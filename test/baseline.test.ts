import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createSecureApp, defineConfig, requireRole, readJson, buildCsp, validateCspAllow, redact, secretString, requireSecret } from "../src/index";
import { securityConformance, devEnv, DEV_ORIGIN, cookieFrom, VIEWER } from "../src/testing";
import type { AuthDeps } from "../src/auth";

const config = defineConfig({ PARTNER_API_KEY: secretString(10).optional() });

function sampleApp(deps: AuthDeps = {}) {
  return createSecureApp({
    config,
    deps,
    api: (api) => {
      api.get("/stats", (c) => c.json({ visitors: 42 }));
      api.get("/boom", () => {
        throw new Error("database password is hunter2 at /srv/app.ts:12");
      });
      api.get("/partner", (c) => c.json({ ok: requireSecret(c.get("config"), "PARTNER_API_KEY").length > 0 }));
      api.post("/settings", requireRole("admin"), async (c) => c.json(await readJson(c, z.object({ name: z.string().max(50) }))));
    },
  });
}

securityConformance({ createApp: sampleApp, paths: ["/api/stats"] });

describe("baseline internals", () => {
  const app = sampleApp();

  it("unexpected errors → generic 500, details only in the server log", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const r = await app.request(DEV_ORIGIN + "/api/boom", undefined, devEnv());
    expect(r.status).toBe(500);
    const body = await r.text();
    expect(body).not.toMatch(/hunter2|srv|Error/);
    expect(JSON.parse(body)).toMatchObject({ error: "internal_error" });
    spy.mockRestore();
  });

  it("missing feature key fails closed with 503", async () => {
    expect((await app.request(DEV_ORIGIN + "/api/partner", undefined, devEnv())).status).toBe(503);
    expect((await app.request(DEV_ORIGIN + "/api/partner", undefined, devEnv({ PARTNER_API_KEY: "abcdefghijkl" }))).status).toBe(200);
  });

  async function post(env: Record<string, unknown>, body: unknown) {
    const s = await app.request(DEV_ORIGIN + "/api/csrf", undefined, env);
    const { token } = (await s.json()) as { token: string };
    return app.request(
      DEV_ORIGIN + "/api/settings",
      { method: "POST", headers: { "Content-Type": "application/json", Origin: DEV_ORIGIN, "X-CSRF-Token": token, Cookie: cookieFrom(s) }, body: JSON.stringify(body) },
      env,
    );
  }

  it("admin-only route: admin allowed, viewer refused", async () => {
    expect((await post(devEnv(), { name: "x" })).status).toBe(200);
    // Dev sign-in uses the first ALLOWED_EMAILS entry; make that a viewer.
    expect((await post(devEnv({ ALLOWED_EMAILS: VIEWER, ADMIN_EMAILS: "" }), { name: "x" })).status).toBe(403);
  });

  it("invalid input → 400 with field issues", async () => {
    const r = await post(devEnv(), { name: "x".repeat(60) });
    expect(r.status).toBe(400);
    expect(await r.json()).toMatchObject({ error: "invalid_input" });
  });

  it("CSP additions must be exact https origins", () => {
    expect(() => validateCspAllow({ connect: ["https://api.example.com"] })).not.toThrow();
    for (const bad of ["*", "https://*.example.com", "'unsafe-inline'", "http://api.example.com", "https://x.com/path", "data:"]) {
      expect(() => validateCspAllow({ connect: [bad] }), bad).toThrow();
    }
    expect(() => createSecureApp({ config, csp: { img: ["*"] }, api: () => {} })).toThrow();
    expect(buildCsp(true, { connect: ["https://api.example.com"] })).toContain("connect-src 'self' https://api.example.com");
    expect(buildCsp(true)).toContain("frame-src 'none'");
  });

  it("log redaction masks secrets by key and by shape", () => {
    const out = JSON.stringify(
      redact({ apiKey: "x", note: "used sk-ant-abcdefghijklmnop and ghp_abcdefghijklmnopqrstuvwxyz123", nested: { password: "p" } }),
    );
    expect(out).not.toMatch(/sk-ant-|ghp_|"x"|"p"/);
  });
});
