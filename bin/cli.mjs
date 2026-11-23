#!/usr/bin/env node
// dashboard-security-kit <command>   — security checks shared by every dashboard.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const COMMANDS = {
  "setup-dev": ["setup-dev.mjs", "Create a local .env with fresh random secrets"],
  "check-bundle": ["check-bundle.mjs", "Scan the built browser files for leaked secrets"],
  "check-live": ["check-live.mjs", "Probe a deployed URL from the outside, as a stranger would"],
  "check-cloudflare": ["check-cloudflare.mjs", "Audit the Cloudflare account settings (read-only token)"],
  "harden-github": ["harden-github.mjs", "Apply the GitHub repo security settings (needs gh)"],
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmd || !COMMANDS[cmd]) {
  console.log("Usage: dashboard-security-kit <command>\n");
  for (const [k, [, d]] of Object.entries(COMMANDS)) console.log(`  ${k.padEnd(18)} ${d}`);
  process.exit(cmd ? 1 : 0);
}
process.argv = [process.argv[0], process.argv[1], ...args];
await import(join(dirname(fileURLToPath(import.meta.url)), COMMANDS[cmd][0]));
