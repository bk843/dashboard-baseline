import js from "@eslint/js";
import tseslint from "typescript-eslint";
import { securityLint } from "./eslint/index.js";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...securityLint({ workerDir: "src" }),
  // The modules that own these keys (CSRF, 2FA, config checks) read them directly.
  { files: ["src/csrf.ts", "src/mfa/index.ts", "src/config.ts"], rules: { "no-restricted-syntax": "off" } },
  {
    files: ["bin/**/*.mjs", "eslint/**/*.js", "vite/**/*.js"],
    languageOptions: {
      globals: { console: "readonly", process: "readonly", Buffer: "readonly", fetch: "readonly", URL: "readonly", TextEncoder: "readonly" },
    },
  },
);
