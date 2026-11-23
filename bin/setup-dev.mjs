// Creates .env from .env.example with fresh random secrets. Never overwrites an existing .env.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { createInterface } from "node:readline/promises";

if (existsSync(".env")) {
  console.log(".env already exists — leaving it alone.");
  process.exit(0);
}
if (!existsSync(".env.example")) {
  console.error("No .env.example here. Run this from the dashboard's folder.");
  process.exit(1);
}
const rl = createInterface({ input: process.stdin, output: process.stdout });
const email = (await rl.question("Your email (you'll be signed in as this locally): ")).trim().toLowerCase();
rl.close();
if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
  console.error("That doesn't look like an email address.");
  process.exit(1);
}
let env = readFileSync(".env.example", "utf8");
env = env
  .replace(/^ALLOWED_EMAILS=.*$/m, `ALLOWED_EMAILS="${email}"`)
  .replace(/^ADMIN_EMAILS=.*$/m, `ADMIN_EMAILS="${email}"`)
  // Any line ending in =GENERATE gets a fresh 32-byte random value. Quoted: a # would end an unquoted value.
  .replace(/^([A-Z0-9_]+)=GENERATE\s*$/gm, (_, k) => `${k}="${randomBytes(32).toString("base64")}"`);
writeFileSync(".env", env, { mode: 0o600 });
console.log("Created .env (readable only by you). Local secrets are random and separate from production.");
