/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const backend = process.env.EASYPATCH_API_URL ?? 'http://localhost:8080';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: backend, changeOrigin: false },
      '/downloads': { target: backend, changeOrigin: false },
      '/health': { target: backend, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // Keep every asset as a file so the strict CSP (no inline scripts/styles) holds.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1200,
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
