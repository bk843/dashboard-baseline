/**
 * 2FA records in D1. Authenticator secrets are encrypted (AES-256-GCM) with a key that lives
 * only in Worker secrets, and each ciphertext is bound to its owner's email, so a database leak
 * alone reveals nothing and rows can't be swapped between users.
 */
import { decryptString, encryptString, importAesKey } from "../crypto";

export interface MfaRow {
  email: string;
  secret: string | null;
  pending_secret: string | null;
  pending_at: number | null;
  enrolled_at: number | null;
  last_step: number;
  failures: number;
  locked_until: number;
}

const ready = new WeakSet<D1Database>();

const CREATE = `CREATE TABLE IF NOT EXISTS mfa_users (
  email TEXT PRIMARY KEY,
  secret TEXT,
  pending_secret TEXT,
  pending_at INTEGER,
  enrolled_at INTEGER,
  last_step INTEGER NOT NULL DEFAULT 0,
  failures INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
)`;

export class MfaStore {
  constructor(
    private readonly db: D1Database,
    private readonly keyB64: string,
  ) {}

  private async init() {
    if (ready.has(this.db)) return;
    await this.db.prepare(CREATE).run();
    ready.add(this.db);
  }

  private aad(email: string) {
    return `mfa|${email}`;
  }

  async get(email: string): Promise<MfaRow | null> {
    await this.init();
    return (await this.db.prepare("SELECT * FROM mfa_users WHERE email = ?").bind(email).first<MfaRow>()) ?? null;
  }

  async list(): Promise<MfaRow[]> {
    await this.init();
    return (await this.db.prepare("SELECT * FROM mfa_users").all<MfaRow>()).results ?? [];
  }

  async encrypt(email: string, secretB32: string) {
    return encryptString(await importAesKey(this.keyB64), secretB32, this.aad(email));
  }

  async decrypt(email: string, token: string) {
    return decryptString(await importAesKey(this.keyB64), token, this.aad(email));
  }

  async setPending(email: string, encrypted: string, now: number) {
    await this.init();
    await this.db
      .prepare(
        "INSERT INTO mfa_users (email, pending_secret, pending_at) VALUES (?, ?, ?) ON CONFLICT(email) DO UPDATE SET pending_secret = excluded.pending_secret, pending_at = excluded.pending_at",
      )
      .bind(email, encrypted, now)
      .run();
  }

  /** Atomically records a used step. Returns false if another request already used it (replay). */
  async useStep(email: string, step: number): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE mfa_users SET last_step = ?, failures = 0, locked_until = 0 WHERE email = ? AND last_step < ?")
      .bind(step, email, step)
      .run();
    return (r.meta?.changes ?? 0) === 1;
  }

  async confirm(email: string, now: number) {
    await this.db
      .prepare("UPDATE mfa_users SET secret = pending_secret, pending_secret = NULL, pending_at = NULL, enrolled_at = ? WHERE email = ?")
      .bind(now, email)
      .run();
  }

  async recordFailure(email: string, failures: number, lockedUntil: number) {
    await this.db.prepare("UPDATE mfa_users SET failures = ?, locked_until = ? WHERE email = ?").bind(failures, lockedUntil, email).run();
  }

  /** Removes the user's authenticator. Their next sign-in asks them to set up a new one. */
  async reset(email: string) {
    await this.init();
    await this.db.prepare("DELETE FROM mfa_users WHERE email = ?").bind(email).run();
  }
}
