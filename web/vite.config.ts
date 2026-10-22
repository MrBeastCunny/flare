import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const apiTarget = process.env.FLARE_API_URL ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../server/internal/web/dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/echarts") || id.includes("node_modules/zrender")) return "charts";
          if (id.includes("node_modules/@cloudflare/kumo") || id.includes("node_modules/@base-ui")) return "kumo";
          if (id.includes("node_modules/@phosphor-icons")) return "icons";
          if (id.includes("node_modules/react") || id.includes("node_modules/scheduler")) return "react";
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: apiTarget, changeOrigin: false, xfwd: true },
      "/scim": { target: apiTarget, changeOrigin: false, xfwd: true },
      "/healthz": { target: apiTarget },
      "/nic": { target: apiTarget, xfwd: true },
    },
  },
});
