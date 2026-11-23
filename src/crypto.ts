export type Bytes = Uint8Array<ArrayBuffer>;

/**
 * Web Crypto helpers. AES-256-GCM for anything that must be stored encrypted (backups,
 * a third-party credential that can't be a Worker secret). Format: base64url("v1" | IV | ct+tag).
 */

const VERSION = new TextEncoder().encode("v1");

export function b64ToBytes(b64: string): Bytes {
  const norm = b64.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm + "=".repeat((4 - (norm.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function bytesToB64url(bytes: Bytes): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function importAesKey(b64Key: string): Promise<CryptoKey> {
  const raw = b64ToBytes(b64Key);
  if (raw.length !== 32) throw new Error("encryption key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptBytes(key: CryptoKey, plain: Bytes, aad: string): Promise<Bytes> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, plain));
  const out = new Uint8Array(VERSION.length + iv.length + ct.length);
  out.set(VERSION, 0);
  out.set(iv, VERSION.length);
  out.set(ct, VERSION.length + iv.length);
  return out;
}

export async function decryptBytes(key: CryptoKey, data: Bytes, aad: string): Promise<Bytes> {
  if (data[0] !== VERSION[0] || data[1] !== VERSION[1]) throw new Error("unknown ciphertext version");
  const iv = data.subarray(2, 14);
  const ct = data.subarray(14);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, ct));
}

export async function encryptString(key: CryptoKey, plain: string, aad = "field"): Promise<string> {
  return bytesToB64url(await encryptBytes(key, new TextEncoder().encode(plain), aad));
}

export async function decryptString(key: CryptoKey, token: string, aad = "field"): Promise<string> {
  return new TextDecoder().decode(await decryptBytes(key, b64ToBytes(token), aad));
}

/** HMAC-SHA256, base64url. */
export async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToB64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))));
}

/** Constant-time string compare. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
