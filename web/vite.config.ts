/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development the Vite server proxies the API to a local EasyRMM server
// started in offload mode with EASYRMM_DEV_INSECURE_COOKIES=true, e.g.
//   EASYRMM_PUBLIC_URL=https://rmm.localhost EASYRMM_TLS_MODE=offload ...
const apiTarget = process.env.EASYRMM_DEV_API ?? "http://127.0.0.1:18080";
const publicHost = process.env.EASYRMM_DEV_HOST ?? "rmm.localhost";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // Keep every asset as a file so the strict CSP (no inline scripts or styles) holds.
    assetsInlineLimit: 0,
    target: "es2022",
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: apiTarget,
        headers: { Host: publicHost, Origin: `https://${publicHost}` },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    css: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test/**", "src/main.tsx"],
      reporter: ["text-summary", "lcov"],
      // Floors just under the current numbers, so coverage can only ratchet up.
      thresholds: { lines: 78, statements: 74, branches: 73, functions: 63 },
    },
  },
});
