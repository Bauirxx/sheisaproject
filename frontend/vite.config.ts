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
    // Porta 5500 e nao a 5173 habitual do Vite.
    //
    // O Windows reserva intervalos de portas para o Hyper-V/WSL e a 5173 cai
    // dentro de um deles nesta maquina (5141-5240), o que faz o arranque
    // rebentar com `EACCES: permission denied ::1:5173` — um erro que parece
    // de permissoes do processo mas e do sistema operativo.
    // Confirmar os intervalos com:
    //   netsh interface ipv4 show excludedportrange protocol=tcp
    // A 5500 esta fora de todos eles. `SHEISA_PORTA_UI` permite mudar sem
    // editar este ficheiro.
    port: Number(process.env.SHEISA_PORTA_UI ?? 5500),
    strictPort: true,
    // Apenas IPv4: o `EACCES` acima manifestou-se primeiro em `::1`.
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8099",
        changeOrigin: true,
      },
    },
  },
  build: { outDir: "dist", sourcemap: true },
});
