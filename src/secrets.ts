import { HttpError } from "./errors";

/**
 * The ONLY way feature code should read an API key. Rules for every outbound call:
 *  - Keys come from Worker secrets (local: .env, production: `wrangler secret put`). Never
 *    from code, the database, or the browser.
 *  - Send keys in a request HEADER, never in a URL (URLs end up in logs).
 *  - Never return, log, or audit a key, and never forward a provider's raw error to the browser.
 * If a key is missing, the feature fails closed with a generic 503.
 * The lint preset blocks reading names ending in _API_KEY/_SECRET/_TOKEN/_PASSWORD anywhere else.
 */
export function requireSecret<C extends object>(cfg: C, name: keyof C & string): string {
  const v = (cfg as Record<string, unknown>)[name];
  if (typeof v !== "string" || v.length === 0) throw new HttpError(503, "feature_not_configured");
  return v;
}
