/**
 * O instante actual como entrada do render, e não como leitura dentro dele.
 *
 * **O defeito que isto corrige.** Os prazos das filas de incidentes e do centro
 * de operações calculavam "expirado" e "faltam 12 min" com `Date.now()` durante
 * o render. Um render só volta a acontecer quando algo muda — e o React Query,
 * ao receber num refetch os mesmos dados, mantém o objecto anterior e não
 * provoca render nenhum. O resultado: um prazo que expirasse com a fila aberta
 * **não ficava vermelho**, e uma contagem decrescente ficava parada em
 * "faltam 3 min" depois de o prazo ter passado. O vermelho do prazo é
 * precisamente o sinal que essas páginas prometem ao analista.
 *
 * O `eslint-plugin-react-hooks` apanhou um dos dois casos (`react-hooks/purity`).
 * O outro estava dentro de uma função auxiliar, onde a regra não vê — pelo que
 * uma procura por `Date.now()` continua a valer mais do que confiar só no linter.
 *
 * **Porque um relógio partilhado.** Um `setInterval` por componente daria um
 * temporizador por linha da tabela, e linhas vizinhas a actualizar em instantes
 * diferentes. Com `useSyncExternalStore` há um único intervalo para a aplicação
 * inteira, activo só enquanto houver quem o use, e todas as linhas mudam em
 * conjunto.
 */

import { useSyncExternalStore } from "react";

/**
 * Resolução do relógio. Os prazos são mostrados ao minuto; actualizar a cada 30
 * segundos garante que nenhum fica mais de meio minuto desactualizado, sem
 * provocar renders que ninguém veria.
 */
const INTERVALO_MS = 30_000;

let agora = Date.now();
let temporizador: number | undefined;
const ouvintes = new Set<() => void>();

function subscrever(ouvinte: () => void): () => void {
  ouvintes.add(ouvinte);

  if (temporizador === undefined) {
    // Refresca ao arrancar: o valor do módulo pode ter ficado parado desde a
    // última vez que alguém o usou. O `useSyncExternalStore` volta a ler o
    // instante depois de subscrever e re-renderiza se mudou, pelo que o
    // primeiro ecrã já sai com a hora certa.
    agora = Date.now();
    temporizador = window.setInterval(() => {
      agora = Date.now();
      for (const avisar of ouvintes) avisar();
    }, INTERVALO_MS);
  }

  return () => {
    ouvintes.delete(ouvinte);
    if (ouvintes.size === 0 && temporizador !== undefined) {
      window.clearInterval(temporizador);
      temporizador = undefined;
    }
  };
}

function lerInstante(): number {
  return agora;
}

/** Instante actual em milissegundos, actualizado a cada 30 segundos. */
export function useAgora(): number {
  return useSyncExternalStore(subscrever, lerInstante);
}
