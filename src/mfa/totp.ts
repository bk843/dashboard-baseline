/**
 * Authenticator-app codes (TOTP, RFC 6238): HMAC-SHA1, 30-second steps, 6 digits —
 * the settings Google Authenticator, Microsoft Authenticator and Authy all use.
 */
import type { Bytes } from "../crypto";

export const STEP_SECONDS = 30;
export const DIGITS = 6;

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Bytes): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Bytes {
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) throw new Error("invalid base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** A new random 160-bit secret (the size RFC 4226 recommends). */
export function newSecret(): Bytes {
  return crypto.getRandomValues(new Uint8Array(20));
}

export function stepAt(ms: number): number {
  return Math.floor(ms / 1000 / STEP_SECONDS);
}

/** The code for one time step. `digits` is 6 for apps; 8 is used for the RFC test vectors. */
export async function codeForStep(secret: Bytes, step: number, digits = DIGITS): Promise<string> {
  const msg = new Uint8Array(8);
  let s = step;
  for (let i = 7; i >= 0; i--) {
    msg[i] = s & 0xff;
    s = Math.floor(s / 256);
  }
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const off = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[off]! & 0x7f) << 24) | (mac[off + 1]! << 16) | (mac[off + 2]! << 8) | mac[off + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/**
 * Checks a code against the current step and one step either side (clock drift), and only
 * accepts steps AFTER `lastStep`, so a code can never be used twice. Returns the matched step.
 */
export async function matchCode(secret: Bytes, code: string, nowMs: number, lastStep: number): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const now = stepAt(nowMs);
  let found: number | null = null;
  // Check every candidate (no early exit) so timing doesn't reveal which step matched.
  for (const step of [now - 1, now, now + 1]) {
    const expected = await codeForStep(secret, step);
    let diff = 0;
    for (let i = 0; i < DIGITS; i++) diff |= expected.charCodeAt(i) ^ code.charCodeAt(i);
    if (diff === 0 && step > lastStep && found === null) found = step;
  }
  return found;
}

export function otpauthUri(issuer: string, account: string, secretB32: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({ secret: secretB32, issuer, algorithm: "SHA1", digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}
