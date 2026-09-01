import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The browser never calls localhost: the dev server proxies /api to the
// backend when it is running, and the app falls back to demo data otherwise.
// Ports match the Docker contract: frontend 3003, backend 8010.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 3003,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8010",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
