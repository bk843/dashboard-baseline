// Applies the baseline GitHub security settings to a dashboard repo. Safe to re-run.
//   dashboard-security-kit harden-github <owner/repo> [--strict]
// Needs the GitHub CLI, signed in as the repo owner:  brew install gh && gh auth login
// --strict also requires a pull request + passing checks before anything lands on main.
// Some settings need a paid GitHub plan on PRIVATE repos; the script says which ones were skipped.
import { spawnSync } from "node:child_process";

const repo = process.argv[2];
const strict = process.argv.includes("--strict");
if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) {
  console.error("usage: dashboard-security-kit harden-github <owner/repo> [--strict]");
  process.exit(1);
}
if (spawnSync("gh", ["--version"]).status !== 0) {
  console.error("The GitHub CLI isn't installed. Run: brew install gh && gh auth login");
  process.exit(1);
}

function gh(method, path, body) {
  const args = ["api", "-X", method, "-H", "Accept: application/vnd.github+json", path];
  if (body !== undefined) args.push("--input", "-");
  const r = spawnSync("gh", args, { input: body !== undefined ? JSON.stringify(body) : undefined, encoding: "utf8" });
  if (r.status !== 0) {
    let msg = (r.stdout || r.stderr || "").trim();
    try {
      msg = JSON.parse(r.stdout).message ?? msg;
    } catch {
      /* keep raw */
    }
    throw new Error(msg.split("\n")[0]);
  }
  return r.stdout.trim() ? JSON.parse(r.stdout) : null;
}

const results = [];
function step(name, fn, { paidOnPrivate = false } = {}) {
  try {
    const info = fn();
    results.push(["✓", name, info ?? ""]);
  } catch (e) {
    const plan = paidOnPrivate && /upgrade|plan|not available|Advanced Security|403|must have/i.test(e.message);
    results.push([plan ? "!" : "✗", name, plan ? `needs a paid GitHub plan on private repos (${e.message})` : e.message]);
  }
}

const info = gh("GET", `/repos/${repo}`);
const me = gh("GET", "/user");
if (!info.private) results.push(["!", "Repo is private", "this repo is PUBLIC — client dashboards should be private"]);
else results.push(["✓", "Repo is private", ""]);

step("Dependabot vulnerability alerts", () => gh("PUT", `/repos/${repo}/vulnerability-alerts`));
step("Dependabot security fixes", () => gh("PUT", `/repos/${repo}/automated-security-fixes`));
step(
  "Secret scanning + push protection",
  () =>
    gh("PATCH", `/repos/${repo}`, {
      security_and_analysis: { secret_scanning: { status: "enabled" }, secret_scanning_push_protection: { status: "enabled" } },
    }) && "on",
  { paidOnPrivate: true },
);
step("Repo hygiene (delete merged branches, no wiki)", () => gh("PATCH", `/repos/${repo}`, { delete_branch_on_merge: true, has_wiki: false }) && "done");
step("Workflow token is read-only by default", () =>
  gh("PUT", `/repos/${repo}/actions/permissions/workflow`, { default_workflow_permissions: "read", can_approve_pull_request_reviews: false }),
);

step(
  `Protect the default branch${strict ? " (strict: PR + checks)" : " (no force-push, no delete)"}`,
  () => {
    const rules = [{ type: "deletion" }, { type: "non_fast_forward" }];
    if (strict) {
      rules.push(
        { type: "pull_request", parameters: { required_approving_review_count: 0, dismiss_stale_reviews_on_push: true, require_code_owner_review: false, require_last_push_approval: false, required_review_thread_resolution: false } },
        { type: "required_status_checks", parameters: { strict_required_status_checks_policy: true, required_status_checks: [{ context: "baseline / verify" }, { context: "baseline / secrets" }] } },
      );
    }
    const body = { name: "Baseline: protect main", target: "branch", enforcement: "active", conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } }, rules };
    const existing = (gh("GET", `/repos/${repo}/rulesets`) ?? []).find((r) => r.name === body.name);
    if (existing) gh("PUT", `/repos/${repo}/rulesets/${existing.id}`, body);
    else gh("POST", `/repos/${repo}/rulesets`, body);
    return existing ? "updated" : "created";
  },
  { paidOnPrivate: true },
);

step(
  "Production environment: deploys only from main, you approve each one",
  () => {
    const base = { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } };
    let note = "";
    try {
      gh("PUT", `/repos/${repo}/environments/production`, { ...base, reviewers: [{ type: "User", id: me.id }], prevent_self_review: false });
    } catch {
      gh("PUT", `/repos/${repo}/environments/production`, base);
      note = " (approval rule needs a paid plan on private repos — deploys stay manual via the Run workflow button)";
    }
    const policies = gh("GET", `/repos/${repo}/environments/production/deployment-branch-policies`)?.branch_policies ?? [];
    if (!policies.some((p) => p.name === "main")) gh("POST", `/repos/${repo}/environments/production/deployment-branch-policies`, { name: "main", type: "branch" });
    return "main only" + note;
  },
  { paidOnPrivate: true },
);

let fails = 0;
for (const [s, name, i] of results) {
  console.log(`${s} ${name}${i ? `  — ${i}` : ""}`);
  if (s === "✗") fails++;
}
console.log(
  `\nNext (by hand, once per client) — see CLIENT-SETUP.md for where each value comes from:\n` +
    `  gh secret set CLOUDFLARE_API_TOKEN --env production --repo ${repo}   # deploy token: production environment only\n` +
    `  gh secret set ALLOWED_EMAILS --env production --repo ${repo}         # staff emails, comma-separated\n` +
    `  gh secret set ADMIN_EMAILS --env production --repo ${repo}\n` +
    `  openssl rand -base64 32 | gh secret set CSRF_SECRET --env production --repo ${repo}\n` +
    `  # Only if 2FA runs in the dashboard (MFA_MODE=app):\n` +
    `  openssl rand -base64 32 | gh secret set MFA_ENCRYPTION_KEY --env production --repo ${repo}\n` +
    `  openssl rand -base64 32 | gh secret set MFA_SESSION_SECRET --env production --repo ${repo}\n` +
    `  gh secret set CF_AUDIT_TOKEN --repo ${repo}                          # read-only audit token\n` +
    `  gh variable set CF_ACCOUNT_ID --repo ${repo}\n` +
    `  gh variable set CF_ZONE_ID --repo ${repo}\n` +
    `  gh variable set APP_HOSTNAME --repo ${repo}\n` +
    `  gh variable set WORKER_NAME --repo ${repo}\n` +
    `  gh variable set MFA_MODE --repo ${repo}                               # "app" or "access"\n` +
    `(each command prompts for the value, so secrets never land in your shell history)`,
);
process.exit(fails ? 1 : 0);
