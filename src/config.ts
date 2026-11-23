import { z } from "zod";

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
  for (const b of [...BASE_BINDINGS, ...requiredBindings]) if (!env[b]) throw new ConfigError([`${b}: binding missing`]);
  return r.data;
}
