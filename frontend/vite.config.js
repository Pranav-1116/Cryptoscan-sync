import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The browser never calls localhost: the dev server proxies /api to the
// backend when it is running. There is no demo/fallback dataset — when the
// backend is unreachable the pages render honest empty/offline states.
// Ports match the Docker contract: frontend 3003, backend 8010.
export default defineConfig({
  plugins: [react()],
  // The dev server binds loopback and keeps Vite's Host-header check on.
  // It previously defaulted to 0.0.0.0 with allowedHosts:true, which put a
  // development server — and the authenticated /api proxy below, which
  // forwards to the backend with the operator's session — on every network
  // the machine is attached to, with DNS-rebinding protection disabled.
  // Several open advisories against vite/esbuild are reachable only by
  // talking to the dev server, so that pairing is what made them exploitable
  // rather than theoretical. Neither flag is needed to run locally:
  // scripts/run_local_stack.sh already passes --host 127.0.0.1.
  //
  // Set VITE_DEV_HOST to expose it deliberately (a container needs 0.0.0.0
  // to be reachable from its host), and VITE_DEV_ALLOWED_HOSTS to a
  // comma-separated hostname list when doing so.
  server: {
    host: process.env.VITE_DEV_HOST || "127.0.0.1",
    port: 3003,
    strictPort: true,
    ...(process.env.VITE_DEV_ALLOWED_HOSTS
      ? { allowedHosts: process.env.VITE_DEV_ALLOWED_HOSTS.split(",").map((h) => h.trim()) }
      : {}),
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8010",
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // The pages already code-split via React.lazy; what stayed in one
        // 588 kB entry chunk was the dependency floor every route pays
        // before anything renders. Splitting it by cache lifetime means a
        // console deploy re-downloads the app chunk while React, the
        // router and the icon set stay in the browser cache -- they only
        // change when a dependency is actually upgraded.
        //
        // Grouped rather than one-chunk-per-package on purpose: dozens of
        // tiny chunks cost a request each on a cold load, which is worse
        // on the sort of locked-down bank network this runs on.
        manualChunks: {
          "vendor-react": ["react", "react-dom", "react-router-dom"],
          "vendor-motion": ["framer-motion", "@formkit/auto-animate"],
          "vendor-icons": ["@phosphor-icons/react"],
        },
      },
    },
  },
});
