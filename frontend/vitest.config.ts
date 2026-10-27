import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Frontend test runner. Hermetic: every test runs against a stubbed `fetch`
// (see src/test/setup.ts) — no network, no backend. A page that renders under
// these conditions renders its honest offline/empty state, which is exactly
// the contract the console promises.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
    testTimeout: 20000,
    coverage: {
      provider: "v8",
      reporter: ["text-summary", "lcov"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/test/**", "src/**/*.test.{ts,tsx}"],
    },
  },
});
