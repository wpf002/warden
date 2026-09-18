import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built into warden/static/console and served by FastAPI at "/".
// `npm run dev` proxies the API to a local `warden serve` on :8000.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: { outDir: "../warden/static/console", emptyOutDir: true, sourcemap: false },
  server: { proxy: { "/api": "http://127.0.0.1:8000", "/metrics": "http://127.0.0.1:8000" } },
});
