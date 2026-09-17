// Verifica a logica de src/componentes/relogio.ts com um relogio falso.
//
//   node scripts/verificar-relogio.mjs      (corre tambem em `npm run verificar`)
//
// Protege a correccao dos prazos que nao ficavam vermelhos com a fila aberta.
// Foi verificado por reversao: tirar o refrescamento ao subscrever faz falhar
// 3 verificacoes, e tirar a paragem do intervalo faz falhar 2.
//
// O hook `useAgora` e so um invólucro sobre `useSyncExternalStore`; o que pode
// estar errado e o armazém por baixo (arrancar, refrescar, notificar, parar).
// Substitui-se o `react` por um duplo que devolve as funcoes que o hook lhe
// passa, e o `window` por temporizadores controlados a mao.

import { build } from "esbuild";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const RAIZ = process.argv[2] ?? process.cwd();
const pasta = mkdtempSync(join(tmpdir(), "relogio-"));

writeFileSync(
  join(pasta, "react-duplo.js"),
  "export function useSyncExternalStore(subscrever, ler) { return { subscrever, ler }; }",
);

const saida = join(pasta, "relogio.mjs");
await build({
  entryPoints: [join(RAIZ, "src/componentes/relogio.ts")],
  bundle: true,
  format: "esm",
  platform: "neutral",
  outfile: saida,
  alias: { react: join(pasta, "react-duplo.js") },
  logLevel: "silent",
});

// ------------------------------------------------------------ relogio falso
let instanteFalso = 1_000_000;
const temporizadores = new Map();
let proximoId = 1;
globalThis.Date.now = () => instanteFalso;
globalThis.window = {
  setInterval(fn, ms) {
    const id = proximoId++;
    temporizadores.set(id, { fn, ms });
    return id;
  },
  clearInterval(id) {
    temporizadores.delete(id);
  },
};

function avancar(ms) {
  instanteFalso += ms;
  for (const { fn, ms: periodo } of [...temporizadores.values()]) {
    if (ms >= periodo) fn();
  }
}

const { useAgora } = await import(pathToFileURL(saida).href);
const { subscrever, ler } = useAgora();

let falhas = 0;
function afirmar(condicao, descricao) {
  console.log(`  ${condicao ? "ok " : "FALHA"}  ${descricao}`);
  if (!condicao) falhas++;
}

// 1. Sem ninguem a ouvir, nao ha temporizador nenhum.
afirmar(temporizadores.size === 0, "sem subscritores nao existe intervalo");

// 2. O valor do modulo pode estar parado: ao subscrever tem de ser refrescado.
instanteFalso += 20 * 60_000; // 20 minutos sem ninguem a usar
let avisosA = 0;
const cancelarA = subscrever(() => avisosA++);
afirmar(ler() === instanteFalso, "ao subscrever, o instante e refrescado (nao fica 20 min atrasado)");
afirmar(temporizadores.size === 1, "o primeiro subscritor arranca exactamente um intervalo");

// 3. O segundo subscritor partilha o mesmo intervalo.
let avisosB = 0;
const cancelarB = subscrever(() => avisosB++);
afirmar(temporizadores.size === 1, "um segundo subscritor nao cria outro intervalo");

// 4. A cada tique, todos sao avisados e o instante avanca — e isto que faz o
//    prazo ficar vermelho sem que os dados mudem.
const antes = ler();
avancar(30_000);
afirmar(ler() === antes + 30_000, "o instante avanca 30 s a cada tique");
afirmar(avisosA === 1 && avisosB === 1, "todos os subscritores sao avisados em conjunto");

// 5. Um prazo que expira entre dois tiques passa a expirado so com o tempo.
const prazo = ler() + 10_000; // expira daqui a 10 s
const expiradoAntes = prazo < ler();
avancar(30_000);
const expiradoDepois = prazo < ler();
afirmar(!expiradoAntes && expiradoDepois, "um prazo passa a expirado sem nenhuma alteracao dos dados");

// 6. Ao sair o ultimo subscritor, o intervalo para.
cancelarA();
afirmar(temporizadores.size === 1, "enquanto houver subscritores o intervalo mantem-se");
cancelarB();
afirmar(temporizadores.size === 0, "sem subscritores o intervalo e parado (nao fica a correr em fundo)");

// 7. Um novo subscritor depois disso volta a arrancar tudo, com hora certa.
instanteFalso += 5 * 60_000;
const cancelarC = subscrever(() => {});
afirmar(temporizadores.size === 1 && ler() === instanteFalso, "voltar a subscrever rearranca com o instante actual");
cancelarC();

console.log();
console.log(falhas === 0 ? "Relogio verificado." : `${falhas} verificacao(oes) falhada(s).`);
process.exit(falhas === 0 ? 0 : 1);
