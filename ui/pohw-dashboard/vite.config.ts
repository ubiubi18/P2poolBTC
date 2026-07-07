import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  cacheDir: process.env.POHW_DASHBOARD_UI_CACHE_DIR || "node_modules/.vite",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5176,
    strictPort: true
  }
});
