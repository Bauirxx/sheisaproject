import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// A API corre em 127.0.0.1:8099 (ver backend/scripts/api.sh). O proxy evita
// depender de CORS em desenvolvimento e mantem os caminhos identicos aos de
// producao, onde a interface e servida pela mesma origem da API.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8099",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
