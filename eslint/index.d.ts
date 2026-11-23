import type { Linter } from "eslint";
export function securityLint(o?: { webDir?: string; workerDir?: string; secretsFile?: string }): Linter.Config[];
