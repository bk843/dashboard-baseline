// Fails if anything secret-looking ended up in the browser bundle.  Usage: check-bundle [dist/client]
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, extname } from "node:path";

const ROOT = process.argv[2] ?? "dist/client";
if (!existsSync(ROOT)) {
  console.error(`${ROOT} not found — build the web app first.`);
  process.exit(1);
}

const PATTERNS = [
  [/sk-ant-[A-Za-z0-9_-]{10,}/, "Anthropic key"],
  [/\bsk-[A-Za-z0-9_-]{32,}/, "OpenAI-style key"],
  [/AIza[0-9A-Za-z_-]{30,}/, "Google API key"],
  [/\b(sk|rk)_live_[0-9A-Za-z]{10,}/, "Stripe live key"],
  [/\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}/, "GitHub token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS access key"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/, "Slack token"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "JWT"],
];

// Secret variable NAMES from .env.example must not appear in browser code either.
const SECRET_NAME = /^([A-Z][A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD))\s*=/;
const names = existsSync(".env.example")
  ? readFileSync(".env.example", "utf8").split("\n").map((l) => l.match(SECRET_NAME)?.[1]).filter(Boolean)
  : [];
// And real values from a local .env, if present.
const values = existsSync(".env")
  ? readFileSync(".env", "utf8")
      .split("\n")
      .map((l) => l.match(/^\s*([A-Z0-9_]+)\s*=\s*"?([^"#\s]+)"?/))
      .filter(Boolean)
      .filter(([, k, v]) => /KEY|SECRET|TOKEN|PASSWORD/.test(k) && v.length >= 12 && !/REPLACE_ME|GENERATE/.test(v))
      .map(([, k, v]) => [k, v])
  : [];

const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(ROOT);

let bad = 0;
for (const f of files) {
  if (extname(f) === ".map") {
    console.error(`✗ ${f}: source map in the bundle (it publishes your source code)`);
    bad++;
    continue;
  }
  const text = readFileSync(f, "latin1");
  const problems = [
    ...PATTERNS.filter(([re]) => re.test(text)).map(([, what]) => `contains a ${what}`),
    ...names.filter((n) => new RegExp(`\\b${n}\\b`).test(text)).map((n) => `mentions secret variable ${n}`),
    ...values.filter(([, v]) => text.includes(v)).map(([k]) => `contains the value of ${k}`),
  ];
  for (const p of problems) console.error(`✗ ${f}: ${p}`);
  bad += problems.length;
}
if (bad) process.exit(1);
console.log(`✓ No secrets found in ${files.length} browser bundle files.`);
