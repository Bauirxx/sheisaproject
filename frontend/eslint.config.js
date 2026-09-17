/**
 * Análise estática do frontend.
 *
 * Até aqui a única verificação era o `tsc`, que garante tipos mas deixa passar
 * duas classes de defeito que numa interface React são as mais comuns:
 *
 * * **dependências de `useEffect` em falta** — o efeito lê um valor antigo e a
 *   interface mostra dados de outro incidente, sem erro nenhum;
 * * **regras dos hooks violadas** — um hook chamado condicionalmente funciona
 *   até ao dia em que a condição muda, e então rebenta de forma difícil de
 *   reproduzir.
 *
 * O `tsc` não vê nenhuma das duas. O `eslint-plugin-react-hooks` vê ambas.
 */

import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["dist", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // Um componente e as constantes que ele usa podem conviver no mesmo
      // ficheiro sem estragar o recarregamento a quente.
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // O prefixo `_` marca um parâmetro que a assinatura exige mas o corpo
      // não usa — por exemplo o `_` das dependências de `require()`.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" },
      ],
    },
  },
);
