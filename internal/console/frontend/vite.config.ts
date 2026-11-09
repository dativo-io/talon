import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The console is served by the talon binary from internal/console/web/static
// (embedded with go:embed). Assets live under /static/ and hashed file names
// make the output deterministic for a given lockfile, so CI can rebuild and
// diff against the committed copy. No inline script or style is emitted, so
// the console's strict CSP (script-src 'self'; style-src 'self') holds.
export default defineConfig({
  plugins: [react()],
  base: "/static/",
  build: {
    outDir: fileURLToPath(new URL("../web/static", import.meta.url)),
    emptyOutDir: true,
    assetsDir: "assets",
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: "es2020",
    cssCodeSplit: false,
    chunkSizeWarningLimit: 400,
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
