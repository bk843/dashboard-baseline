/**
 * Logs must never contain secrets. All server logging goes through log(). Sensitive keys are
 * dropped, and values that look like credentials are masked even under an innocent key.
 */

const SENSITIVE_KEY = /(key|secret|token|password|passwd|authorization|cookie|jwt|assertion|credential|session)/i;
const SENSITIVE_VALUE: RegExp[] = [
  /sk-ant-[A-Za-z0-9_-]{8,}/g, // Anthropic
  /sk-[A-Za-z0-9_-]{20,}/g, // OpenAI-style
  /AIza[0-9A-Za-z_-]{20,}/g, // Google
  /\b(sk|rk)_(live|test)_[0-9A-Za-z]{10,}/g, // Stripe
  /\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}/g, // GitHub
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, // Slack
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
];
const MAX_STRING = 500;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[depth]";
  if (typeof value === "string") {
    let s = value;
    for (const re of SENSITIVE_VALUE) s = s.replace(re, "[redacted]");
    return s.length > MAX_STRING ? s.slice(0, MAX_STRING) + "…[truncated]" : s;
  }
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : redact(v, depth + 1);
    return out;
  }
  return value;
}

type Level = "info" | "warn" | "error";

export function log(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, event, at: new Date().toISOString(), ...(redact(fields) as object) });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}
