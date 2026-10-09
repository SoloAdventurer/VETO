import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In dev the UI runs on :5173 and proxies the API to the gateway on :8000.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/v1": "http://127.0.0.1:8000", "/healthz": "http://127.0.0.1:8000" } },
});
