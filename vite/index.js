// Shared Vite settings for the browser bundle. A dashboard's vite.config.ts:
//   import { secureVite } from "dashboard-baseline/vite";
//   export default defineConfig(secureVite({ plugins: [react()] }));

/**
 * @param {import("vite").UserConfig} [overrides]
 * @returns {import("vite").UserConfig}
 */
export function secureVite(overrides = {}) {
  const { build = {}, ...rest } = overrides;
  return {
    root: "src/web",
    publicDir: "../../public",
    // Only variables prefixed PUBLIC_ could ever reach the browser. Never name a secret PUBLIC_*.
    envPrefix: "PUBLIC_",
    ...rest,
    build: {
      outDir: "../../dist/client",
      emptyOutDir: true,
      // No source maps in production: they'd publish your source code.
      sourcemap: false,
      // Keep everything as external files so the strict CSP (no inline scripts/styles) works.
      assetsInlineLimit: 0,
      modulePreload: { polyfill: false },
      ...build,
    },
  };
}
