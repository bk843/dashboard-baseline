// Shared security lint rules. A dashboard's eslint.config.js spreads these in:
//   import { securityLint } from "dashboard-baseline/eslint";
//   export default tseslint.config(...tseslint.configs.recommended, ...securityLint());

const SECRET_NAME = "/^[A-Z][A-Z0-9_]*_(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)$/";

/**
 * @param {{ webDir?: string, workerDir?: string, secretsFile?: string }} [o]
 */
export function securityLint(o = {}) {
  const webDir = o.webDir ?? "src/web";
  const workerDir = o.workerDir ?? "src/worker";
  const secretsFile = o.secretsFile ?? `${workerDir}/secrets.ts`;
  return [
    { ignores: ["dist", "node_modules", ".wrangler", "coverage", "migrations"] },
    {
      files: ["**/*.{ts,tsx}"],
      rules: {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
        "no-restricted-syntax": [
          "error",
          // SQL injection: no raw SQL strings. Use a query builder (Drizzle) or bound parameters.
          { selector: "CallExpression[callee.object.name='sql'][callee.property.name='raw']", message: "sql.raw() builds SQL from strings. Not allowed." },
          { selector: "CallExpression[callee.property.name='exec'][callee.object.name=/^(db|DB|d1)$/]", message: "No raw SQL exec(). Use the query builder." },
          { selector: "CallExpression[callee.property.name='exec'][callee.object.property.name='DB']", message: "No raw SQL exec(). Use the query builder." },
          { selector: "CallExpression[callee.property.name='prepare'] > TemplateLiteral[expressions.length>0]", message: "Never build SQL with template strings. Use bound parameters." },
          // XSS: never inject raw HTML.
          { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Never render raw HTML. Render text instead." },
          { selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]", message: "Never assign raw HTML." },
          { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "Never insert raw HTML." },
          { selector: "CallExpression[callee.object.name='document'][callee.property.name='write']", message: "Never use document.write." },
          // Keys never go in URLs (they'd be logged). Send them in a header.
          { selector: "Literal[value=/[?&](key|api_key|apikey|token|access_token)=/i]", message: "Never put a key or token in a URL. Use a header." },
          { selector: "TemplateElement[value.raw=/[?&](key|api_key|apikey|token|access_token)=/i]", message: "Never put a key or token in a URL. Use a header." },
          // Feature code reads secrets only through requireSecret().
          { selector: `MemberExpression[property.name=${SECRET_NAME}]`, message: "Read secrets only via requireSecret() (see src/worker/secrets.ts)." },
          // Opening links in a new tab must not hand the opener to the other site.
          { selector: "JSXOpeningElement[name.name='a']:has(JSXAttribute[name.name='target'][value.value='_blank']):not(:has(JSXAttribute[name.name='rel']))", message: 'Add rel="noopener noreferrer" to target="_blank" links.' },
        ],
      },
    },
    {
      files: [secretsFile],
      rules: { "no-restricted-syntax": "off" },
    },
    {
      // Browser code must never import server code (it could pull secrets into the bundle).
      files: [`${webDir}/**/*.{ts,tsx}`],
      rules: {
        "no-restricted-imports": [
          "error",
          {
            patterns: [
              { group: ["**/worker/**", "dashboard-baseline", "dashboard-baseline/*"], message: "Browser code must not import server code." },
            ],
          },
        ],
      },
    },
    {
      files: ["test/**/*.ts"],
      rules: { "no-restricted-syntax": "off" },
    },
  ];
}
