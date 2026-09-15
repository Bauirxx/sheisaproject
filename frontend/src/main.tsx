import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "@/App";
import "@/estilos/tokens.css";
import "@/estilos/base.css";
import "@/estilos/disposicao.css";

// Tema escolhido pelo utilizador, aplicado antes da primeira pintura para nao
// haver um clarao entre o modo claro e o escuro ao recarregar.
try {
  const guardado = window.localStorage.getItem("sheisa.tema");
  if (guardado) document.documentElement.setAttribute("data-tema", guardado);
} catch {
  // Sem armazenamento: fica o modo escuro, que e o principal.
}

const raiz = document.getElementById("raiz");
if (!raiz) throw new Error("Elemento #raiz nao encontrado no documento.");

createRoot(raiz).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
