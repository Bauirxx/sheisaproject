/**
 * Fila de alertas (§4.5.4 · §6 do briefing).
 *
 * A coluna que manda é a pontuação de triagem, e ela é **clicável**: abre a
 * decomposição que a produziu. É a diferença entre um número que o analista
 * tem de aceitar e um número que ele pode verificar. Um motor determinístico
 * que não mostrasse a conta seria indistinguível de um que a inventa.
 *
 * `eventos` mostra quantos sinais equivalentes foram agregados no alerta. É o
 * que transforma 4000 tentativas de força bruta numa linha em vez de 4000.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Alerta, AlertaResumo, FactoresDeTriagem, Pagina } from "@/api/tipos";
import {
  Carregando,
  DistintivoDeEstadoDoAlerta,
  DistintivoDeSeveridade,
  Erro,
  instante,
  MarcaDeDemonstracao,
  Vazio,
} from "@/componentes/comuns";
import {
  CampoDeSelecao,
  ESTADOS_DO_ALERTA,
  Paginacao,
  SEVERIDADES,
  useFiltros,
} from "@/componentes/listagem";

/**
 * Decomposição da pontuação: um factor por linha, com pontos e razão.
 *
 * O total bruto e o final aparecem os dois, porque diferem quando a soma sai
 * fora de 0–100 — e esconder essa diferença faria a conta parecer errada a
 * quem a somasse à mão.
 */
export function DecomposicaoDaTriagem({
  factores,
  racional,
}: {
  factores: FactoresDeTriagem | Record<string, never> | null | undefined;
  racional?: string;
}) {
  if (!factores || !("factores" in factores) || !factores.factores) {
    return (
      <p className="secundario">
        Este alerta ainda não foi pontuado, pelo que não há decomposição a
        mostrar.
      </p>
    );
  }

  const entradas = Object.entries(factores.factores).sort(
    (a, b) => Math.abs(b[1].pontos) - Math.abs(a[1].pontos),
  );

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      {racional ? <p className="secundario">{racional}</p> : null}
      <div className="tabela-envolvente">
        <table className="tabela">
          <thead>
            <tr>
              <th style={{ width: "72px" }}>Pontos</th>
              <th>Factor</th>
              <th>Razão</th>
            </tr>
          </thead>
          <tbody>
            {entradas.map(([nome, factor]) => (
              <tr key={nome}>
                <td
                  className="mono"
                  style={{
                    fontWeight: 600,
                    color:
                      factor.pontos > 0
                        ? "var(--texto)"
                        : factor.pontos < 0
                          ? "var(--sucesso)"
                          : "var(--texto-terciario)",
                  }}
                >
                  {factor.pontos > 0 ? `+${factor.pontos}` : factor.pontos}
                </td>
                <td className="secundario">{nome.replace(/_/g, " ")}</td>
                <td>{factor.razao}</td>
              </tr>
            ))}
            <tr>
              <td className="mono" style={{ fontWeight: 700 }}>
                {factores.total_final}
              </td>
              <td colSpan={2} className="terciario">
                Soma dos factores: {factores.total_bruto}
                {factores.total_bruto !== factores.total_final
                  ? ` · limitada ao intervalo 0–100 → ${factores.total_final}`
                  : " · dentro do intervalo, sem ajuste"}
                {" · "}
                motor {factores.motor} v{factores.versao}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Carrega o detalhe do alerta para mostrar a decomposição.
 *
 * A listagem não a traz, e é assim que deve ser: o dicionário de factores de 25
 * alertas seria muitas vezes maior do que a lista inteira, para dados que só
 * são lidos quando alguém pergunta por um alerta em concreto.
 */
function DetalheDaPontuacao({ id }: { id: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["alerta", id],
    queryFn: () => pedir<Alerta>(`/alerts/${id}`),
  });

  if (isPending) return <Carregando texto="A carregar a decomposição…" />;
  if (error) return <Erro erro={error} />;

  return (
    <DecomposicaoDaTriagem
      factores={data.triage_factors}
      racional={data.triage_rationale}
    />
  );
}

function Pontuacao({ alerta, aoAbrir }: { alerta: AlertaResumo; aoAbrir: () => void }) {
  const cor =
    alerta.triage_score >= 65
      ? "var(--sev-alta)"
      : alerta.triage_score >= 40
        ? "var(--sev-media)"
        : "var(--texto-secundario)";

  return (
    <button
      type="button"
      className="botao botao--discreto"
      onClick={(e) => {
        e.stopPropagation();
        aoAbrir();
      }}
      title="Ver a decomposição que produziu esta pontuação"
      style={{ padding: "2px 6px" }}
    >
      <span className="mono" style={{ color: cor, fontWeight: 700 }}>
        {alerta.triage_score}
      </span>
      <span className="terciario">/100</span>
    </button>
  );
}

export function Alertas() {
  const { ler, definir, limpar } = useFiltros();
  // Guarda-se apenas o identificador: a decomposicao vem do detalhe, que a
  // listagem nao traz de proposito (seria um dicionario de factores por linha).
  const [aberto, definirAberto] = useState<AlertaResumo | null>(null);

  const parametros = {
    estado: ler("estado"),
    severidade: ler("severidade"),
    page: ler("page", "1"),
    size: "25",
    sort: ler("sort", "-triage_score"),
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["alertas", parametros],
    queryFn: () => pedir<Pagina<AlertaResumo>>(`/alerts${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const temFiltros = ler("estado") !== "" || ler("severidade") !== "";

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Alertas</h1>
          <p className="pagina__descricao">
            Ordenados pela pontuação de triagem, que é determinística e
            verificável: carregue no número para ver a decomposição que o
            produziu.
          </p>
        </div>
      </div>

      <div className="filtros">
        <CampoDeSelecao
          etiqueta="Estado"
          valor={ler("estado")}
          opcoes={ESTADOS_DO_ALERTA}
          aoMudar={(v) => definir({ estado: v })}
        />
        <CampoDeSelecao
          etiqueta="Severidade"
          valor={ler("severidade")}
          opcoes={SEVERIDADES}
          aoMudar={(v) => definir({ severidade: v })}
        />
        {temFiltros ? (
          <button type="button" className="botao botao--discreto" onClick={limpar}>
            Limpar filtros
          </button>
        ) : null}
        {isFetching ? <span className="carregando" aria-hidden="true" /> : null}
      </div>

      {error ? <Erro erro={error} /> : null}

      {isPending ? (
        <Carregando />
      ) : data && data.total === 0 ? (
        <div className="tabela-envolvente">
          <Vazio
            titulo={temFiltros ? "Nenhum alerta corresponde aos filtros" : "Sem alertas"}
            detalhe={
              temFiltros
                ? "Ajuste os filtros para ver mais resultados."
                : "Os alertas aparecem aqui à medida que as fontes de detecção enviam sinais."
            }
          />
        </div>
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Referência</th>
                <th>Título</th>
                <th>Fonte</th>
                <th>Severidade</th>
                <th>Pontuação</th>
                <th>Risco FP</th>
                <th>Eventos</th>
                <th>Estado</th>
                <th>Último sinal</th>
                <th>Incidente</th>
              </tr>
            </thead>
            <tbody>
              {data.itens.map((alerta) => (
                <tr key={alerta.id}>
                  <td className="mono">{alerta.reference}</td>
                  <td>
                    <div className="linha" style={{ gap: "var(--espaco-2)" }}>
                      <span className="truncar" style={{ maxWidth: "36ch" }}>
                        {alerta.title}
                      </span>
                      {alerta.is_demo_data ? <MarcaDeDemonstracao /> : null}
                    </div>
                    {alerta.rule_id ? (
                      <div className="terciario mono">regra {alerta.rule_id}</div>
                    ) : null}
                  </td>
                  <td className="secundario">{alerta.source_kind}</td>
                  <td>
                    <DistintivoDeSeveridade valor={alerta.severity} />
                  </td>
                  <td>
                    <Pontuacao alerta={alerta} aoAbrir={() => definirAberto(alerta)} />
                  </td>
                  <td className="secundario mono">
                    {alerta.false_positive_score > 0
                      ? `${alerta.false_positive_score}%`
                      : "—"}
                  </td>
                  <td className="mono">{alerta.event_count}</td>
                  <td>
                    <DistintivoDeEstadoDoAlerta valor={alerta.status} />
                  </td>
                  <td className="secundario">{instante(alerta.last_event_at)}</td>
                  <td>
                    {alerta.incident_id ? (
                      <Link to={`/incidentes/${alerta.incident_id}`}>Abrir</Link>
                    ) : (
                      <span className="terciario">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(numero) => definir({ page: numero })} />
        </div>
      ) : null}

      {aberto ? (
        <div
          className="sobreposicao"
          role="dialog"
          aria-modal="true"
          aria-label={`Decomposição da pontuação de ${aberto.reference}`}
          onClick={() => definirAberto(null)}
        >
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
              <div className="pilha" style={{ gap: 0 }}>
                <h2>Como se chegou a {aberto.triage_score}/100</h2>
                <span className="terciario mono">{aberto.reference}</span>
              </div>
              <button
                type="button"
                className="botao botao--discreto"
                onClick={() => definirAberto(null)}
              >
                Fechar
              </button>
            </div>
            <DetalheDaPontuacao id={aberto.id} />
          </div>
        </div>
      ) : null}
    </>
  );
}
