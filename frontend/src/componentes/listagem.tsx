/**
 * Peças partilhadas pelas listagens: paginação e filtros ligados ao URL.
 *
 * Os filtros vivem na *query string*, não no estado do componente. A diferença
 * importa numa sala de operações: um analista que encontra alguma coisa precisa
 * de poder colar o endereço no chat da equipa e que a pessoa do outro lado veja
 * exactamente a mesma fila. Guardar os filtros só em memória transformaria
 * cada partilha numa descrição verbal do que filtrar.
 */

import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

import type { Pagina } from "@/api/tipos";

/** Lê e escreve filtros na query string, preservando os restantes. */
export function useFiltros() {
  const [parametros, definirParametros] = useSearchParams();

  const ler = useCallback(
    (chave: string, omissao = "") => parametros.get(chave) ?? omissao,
    [parametros],
  );

  const definir = useCallback(
    (alteracoes: Record<string, string | number | null | undefined>) => {
      const novos = new URLSearchParams(parametros);
      for (const [chave, valor] of Object.entries(alteracoes)) {
        if (valor === null || valor === undefined || valor === "") {
          novos.delete(chave);
        } else {
          novos.set(chave, String(valor));
        }
      }
      // Qualquer alteração de filtro volta à primeira página: manter a página
      // corrente daria uma lista vazia sempre que o novo filtro devolvesse
      // menos resultados, o que se lê como "não há nada" em vez de "está na
      // página errada".
      if (!("page" in alteracoes)) novos.delete("page");
      definirParametros(novos, { replace: true });
    },
    [parametros, definirParametros],
  );

  const limpar = useCallback(() => {
    definirParametros(new URLSearchParams(), { replace: true });
  }, [definirParametros]);

  return { ler, definir, limpar, parametros };
}

export function Paginacao<T>({
  pagina,
  aoMudar,
}: {
  pagina: Pagina<T>;
  aoMudar: (numero: number) => void;
}) {
  const { pagina: actual, total_paginas: total, total: registos, tamanho } = pagina;
  if (registos === 0) return null;

  const primeiro = (actual - 1) * tamanho + 1;
  const ultimo = Math.min(actual * tamanho, registos);

  return (
    <div className="paginacao">
      <span>
        {primeiro}–{ultimo} de {registos}
      </span>
      <div className="linha">
        <button
          type="button"
          className="botao botao--pequeno"
          disabled={actual <= 1}
          onClick={() => aoMudar(actual - 1)}
        >
          Anterior
        </button>
        <span className="terciario">
          Página {actual} de {Math.max(total, 1)}
        </span>
        <button
          type="button"
          className="botao botao--pequeno"
          disabled={actual >= total}
          onClick={() => aoMudar(actual + 1)}
        >
          Seguinte
        </button>
      </div>
    </div>
  );
}

export function CampoDeSelecao({
  etiqueta,
  valor,
  opcoes,
  aoMudar,
  todos = "Todos",
}: {
  etiqueta: string;
  valor: string;
  opcoes: { valor: string; rotulo: string }[];
  aoMudar: (valor: string) => void;
  todos?: string;
}) {
  return (
    <div className="campo">
      <label className="campo__etiqueta">{etiqueta}</label>
      <select
        className="selector"
        value={valor}
        onChange={(e) => aoMudar(e.target.value)}
      >
        <option value="">{todos}</option>
        {opcoes.map((o) => (
          <option key={o.valor} value={o.valor}>
            {o.rotulo}
          </option>
        ))}
      </select>
    </div>
  );
}

export const SEVERIDADES = [
  { valor: "CRITICA", rotulo: "Crítica" },
  { valor: "ALTA", rotulo: "Alta" },
  { valor: "MEDIA", rotulo: "Média" },
  { valor: "BAIXA", rotulo: "Baixa" },
  { valor: "INFO", rotulo: "Informativa" },
];

export const ESTADOS_DO_INCIDENTE = [
  { valor: "NOVO", rotulo: "Novo" },
  { valor: "ABERTO", rotulo: "Aberto" },
  { valor: "TRIAGEM", rotulo: "Triagem" },
  { valor: "INVESTIGACAO", rotulo: "Investigação" },
  { valor: "CONTENCAO", rotulo: "Contenção" },
  { valor: "ERRADICACAO", rotulo: "Erradicação" },
  { valor: "RECUPERACAO", rotulo: "Recuperação" },
  { valor: "RESOLVIDO", rotulo: "Resolvido" },
  { valor: "ENCERRADO", rotulo: "Encerrado" },
  { valor: "SUSPENSO", rotulo: "Suspenso" },
  { valor: "ESCALADO", rotulo: "Escalado" },
  { valor: "FALSO_POSITIVO", rotulo: "Falso positivo" },
  { valor: "DUPLICADO", rotulo: "Duplicado" },
];

export const ESTADOS_DO_ALERTA = [
  { valor: "NOVO", rotulo: "Novo" },
  { valor: "EM_TRIAGEM", rotulo: "Em triagem" },
  { valor: "CORRELACIONADO", rotulo: "Correlacionado" },
  { valor: "PROMOVIDO", rotulo: "Promovido" },
  { valor: "DESCARTADO", rotulo: "Descartado" },
  { valor: "FALSO_POSITIVO", rotulo: "Falso positivo" },
  { valor: "DUPLICADO", rotulo: "Duplicado" },
];

export const CATEGORIAS = [
  { valor: "CONTEUDO_ABUSIVO", rotulo: "Conteúdo abusivo" },
  { valor: "CODIGO_MALICIOSO", rotulo: "Código malicioso" },
  { valor: "RECOLHA_INFORMACAO", rotulo: "Recolha de informação" },
  { valor: "TENTATIVA_INTRUSAO", rotulo: "Tentativa de intrusão" },
  { valor: "INTRUSAO", rotulo: "Intrusão" },
  { valor: "DISPONIBILIDADE", rotulo: "Disponibilidade" },
  { valor: "SEGURANCA_INFORMACAO", rotulo: "Segurança da informação" },
  { valor: "FRAUDE", rotulo: "Fraude" },
  { valor: "VULNERABILIDADE", rotulo: "Vulnerabilidade" },
  { valor: "OUTRO", rotulo: "Outro" },
];
