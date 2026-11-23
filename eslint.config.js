import js from "@eslint/js";
import tseslint from "typescript-eslint";
import { securityLint } from "./eslint/index.js";

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...securityLint({ workerDir: "src" }),
  // The CSRF module is the one place that reads the CSRF key directly.
  { files: ["src/csrf.ts"], rules: { "no-restricted-syntax": "off" } },
  {
    files: ["bin/**/*.mjs", "eslint/**/*.js", "vite/**/*.js"],
    languageOptions: {
      globals: { console: "readonly", process: "readonly", Buffer: "readonly", fetch: "readonly", URL: "readonly", TextEncoder: "readonly" },
    },
  },
);
