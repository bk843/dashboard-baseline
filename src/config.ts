import { z } from "zod";
import { b64ToBytes } from "./crypto";

/**
 * Config validation. Every request validates config first. If anything required is missing,
 * malformed, or still a REPLACE_ME placeholder, the app refuses to serve (generic 503; the
 * names of the broken fields go to the server log, never their values).
 *
 * Each dashboard extends the base schema with its own fields:
 *   export const appConfig = defineConfig({ STRIPE_API_KEY: secretString(20).optional() });
 */

export const notPlaceholder = (s: string) => !/REPLACE_ME/i.test(s);

/** A secret value: at least `min` characters and not a placeholder. */
export const secretString = (min: number) => z.string().min(min).refine(notPlaceholder, "placeholder value");

/** Comma-separated email list → lowercased array. */
const emailList = (min: number) =>
  z
    .string()
    .default("")
    .transform((s) =>
      s
        .split(",")
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean),
    )
    .pipe(z.array(z.email()).min(min));

export const baseShape = {
  ENVIRONMENT: z.enum(["development", "production"]),
  APP_ORIGIN: z.url().refine(notPlaceholder, "placeholder value"),
  AUTH_MODE: z.enum(["access", "dev"]),
  ACCESS_TEAM_DOMAIN: z.string().optional().default(""),
  ACCESS_AUD: z.string().optional().default(""),
  /** Staff allowed in, comma-separated. Must match the Cloudflare Access policy (the app checks it too). */
  ALLOWED_EMAILS: emailList(1),
  /** Subset of ALLOWED_EMAILS who get the "admin" role. Everyone else is "viewer". */
  ADMIN_EMAILS: emailList(0),
  /** HMAC key for CSRF tokens. 32+ random bytes, base64. */
  CSRF_SECRET: secretString(32),

  /**
   * Where the authenticator-app step happens:
   *  "access" — Cloudflare Access enforces it (needs a plan with Access independent MFA).
   *  "app"    — this Worker enforces it (works on any plan; needs MFA_DB + the two keys below).
   */
  MFA_MODE: z.enum(["access", "app"]).default("access"),
  /** AES-256 key for authenticator secrets at rest. 32 random bytes, base64. (MFA_MODE=app) */
  MFA_ENCRYPTION_KEY: secretString(40).optional(),
  /** HMAC key for the verified-session cookie. 32+ random bytes, base64. (MFA_MODE=app) */
  MFA_SESSION_SECRET: secretString(32).optional(),
  /** How long a verified session lasts before asking for a new code. */
  MFA_SESSION_HOURS: z.coerce.number().int().min(1).max(24).default(12),
  /** Name shown in the authenticator app. Defaults to the dashboard's hostname. */
  MFA_ISSUER: z.string().max(60).optional(),
};

export interface BaseConfig {
  ENVIRONMENT: "development" | "production";
  APP_ORIGIN: string;
  AUTH_MODE: "access" | "dev";
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ALLOWED_EMAILS: string[];
  ADMIN_EMAILS: string[];
  CSRF_SECRET: string;
  MFA_MODE: "access" | "app";
  MFA_ENCRYPTION_KEY?: string | undefined;
  MFA_SESSION_SECRET?: string | undefined;
  MFA_SESSION_HOURS: number;
  MFA_ISSUER?: string | undefined;
}

function isKey32(b64: string): boolean {
  try {
    return b64ToBytes(b64).length === 32;
  } catch {
    return false;
  }
}

function baseRules(c: BaseConfig, ctx: z.RefinementCtx) {
  const issue = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
  if (c.ENVIRONMENT === "production") {
    if (c.AUTH_MODE !== "access") issue("AUTH_MODE", "must be 'access' in production");
    if (!c.APP_ORIGIN.startsWith("https://")) issue("APP_ORIGIN", "must be https in production");
  }
  if (c.AUTH_MODE === "access") {
    if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(c.ACCESS_TEAM_DOMAIN) || !notPlaceholder(c.ACCESS_TEAM_DOMAIN))
      issue("ACCESS_TEAM_DOMAIN", "must be https://<team>.cloudflareaccess.com");
    if (c.ACCESS_AUD.length < 32 || !notPlaceholder(c.ACCESS_AUD)) issue("ACCESS_AUD", "must be the Access application AUD tag");
  }
  if (c.AUTH_MODE === "dev" && c.ENVIRONMENT !== "development") issue("AUTH_MODE", "dev auth is only allowed in development");
  if (c.MFA_MODE === "app") {
    if (!c.MFA_ENCRYPTION_KEY) issue("MFA_ENCRYPTION_KEY", "required when MFA_MODE=app");
    else if (!isKey32(c.MFA_ENCRYPTION_KEY)) issue("MFA_ENCRYPTION_KEY", "must be 32 random bytes, base64");
    if (!c.MFA_SESSION_SECRET) issue("MFA_SESSION_SECRET", "required when MFA_MODE=app");
    if (c.MFA_ENCRYPTION_KEY && c.MFA_ENCRYPTION_KEY === c.MFA_SESSION_SECRET) issue("MFA_SESSION_SECRET", "must differ from MFA_ENCRYPTION_KEY");
  }
  for (const a of c.ADMIN_EMAILS) if (!c.ALLOWED_EMAILS.includes(a)) issue("ADMIN_EMAILS", "every admin must also be in ALLOWED_EMAILS");
}

/** Base schema plus the dashboard's own fields. */
export function defineConfig<Extra extends z.ZodRawShape = Record<never, never>>(extra?: Extra) {
  return z.object({ ...baseShape, ...(extra ?? ({} as Extra)) }).superRefine((c, ctx) => baseRules(c as unknown as BaseConfig, ctx));
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super("Invalid configuration");
  }
}

/** Always required: the static UI and the API rate limiter. */
export const BASE_BINDINGS = ["ASSETS", "RL_API"] as const;

/** Parse config from the Worker env. Throws ConfigError listing field names (never values). */
export function loadConfig<C>(schema: z.ZodType<C>, env: Record<string, unknown>, requiredBindings: readonly string[] = []): C {
  const r = schema.safeParse(env);
  if (!r.success) throw new ConfigError(r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`));
  const mfaBindings = (r.data as { MFA_MODE?: string }).MFA_MODE === "app" ? ["MFA_DB"] : [];
  for (const b of [...BASE_BINDINGS, ...mfaBindings, ...requiredBindings]) if (!env[b]) throw new ConfigError([`${b}: binding missing`]);
  return r.data;
}
