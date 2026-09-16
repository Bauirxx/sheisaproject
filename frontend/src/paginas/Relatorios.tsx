/**
 * Relatórios (§4.13, tela 6 · §4.5.8 · RF18 · §67 do briefing).
 *
 * O relatório de incidente responde às oito perguntas que a API organiza: o que
 * aconteceu, quando, como foi detectado, quem investigou, que evidências
 * existem, que decisões foram tomadas, que acções foram executadas e qual foi o
 * resultado. O conteúdo é reconstituído da base de dados no momento da geração
 * — não há texto guardado à espera de ser mostrado.
 *
 * A exportação em PDF pode não estar disponível (depende do `reportlab` estar
 * instalado). Quando não está, a API responde 503 com explicação e a interface
 * mostra-a. O que **não** acontece é descarregar um ficheiro vazio a fingir que
 * correu bem.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { consulta, descarregar, ErroDaApi, pedir } from "@/api/cliente";
import type {
  IncidenteResumo,
  Pagina,
  Relatorio,
  RelatorioDetalhado,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";
import { Paginacao, useFiltros } from "@/componentes/listagem";

/** Apresenta o conteúdo do relatório sem despejar JSON em bruto. */
function Conteudo({ conteudo }: { conteudo: Record<string, unknown> }) {
  const secoes = Object.entries(conteudo).filter(
    ([chave]) => !["tipo", "gerado_em"].includes(chave),
  );

  return (
    <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
      {secoes.map(([chave, valor]) => (
        <div key={chave}>
          <h3 style={{ marginBottom: "var(--espaco-2)" }}>{legivel(chave)}</h3>
          {typeof valor === "string" || typeof valor === "number" ? (
            <p className="secundario" style={{ whiteSpace: "pre-wrap" }}>
              {String(valor)}
            </p>
          ) : Array.isArray(valor) ? (
            valor.length === 0 ? (
              <p className="terciario">Nada registado.</p>
            ) : (
              <ul className="pilha" style={{ gap: "var(--espaco-2)", paddingLeft: "18px" }}>
                {valor.map((item, indice) => (
                  <li key={indice} className="secundario">
                    {typeof item === "object" && item !== null
                      ? Object.entries(item as Record<string, unknown>)
                          .filter(([, v]) => v !== null && v !== "")
                          .map(([k, v]) => `${legivel(k)}: ${String(v)}`)
                          .join(" · ")
                      : String(item)}
                  </li>
                ))}
              </ul>
            )
          ) : valor === null ? (
            <p className="terciario">Nada registado.</p>
          ) : (
            <div className="propriedades">
              {Object.entries(valor as Record<string, unknown>).map(([k, v]) => (
                <div key={k} className="propriedade">
                  <span className="propriedade__rotulo">{legivel(k)}</span>
                  <span className="propriedade__valor secundario">
                    {v === null || v === "" ? "—" : String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function Visualizador({ id, aoFechar }: { id: string; aoFechar: () => void }) {
  const [erroPdf, definirErroPdf] = useState<string | null>(null);

  const { data, isPending, error } = useQuery({
    queryKey: ["relatorio", id],
    queryFn: () => pedir<RelatorioDetalhado>(`/reports/${id}`),
  });

  const exportar = async () => {
    definirErroPdf(null);
    try {
      // `descarregar` e não `fetch`: a rota exige `reports:read` e o token de
      // acesso vive em memória, pelo que um pedido sem o cabeçalho
      // `Authorization` recebia sempre 401 — e o utilizador via "não
      // disponível neste servidor" quando o problema era autenticação.
      await descarregar(
        `/reports/${id}/pdf`,
        `${data?.reference ?? "relatorio"}.pdf`,
      );
    } catch (erro) {
      // A API responde 503 com explicação quando o `reportlab` não está
      // instalado. Mostrar essa mensagem é mais útil do que um genérico.
      definirErroPdf(
        erro instanceof ErroDaApi
          ? erro.message
          : "Não foi possível contactar o servidor.",
      );
    }
  };

  return (
    <div className="sobreposicao" role="dialog" aria-modal="true" onClick={aoFechar}>
      <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
        <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
          <div className="pilha" style={{ gap: 0 }}>
            <h2>{data?.title ?? "Relatório"}</h2>
            <span className="terciario mono">{data?.reference}</span>
          </div>
          <div className="linha">
            <button type="button" className="botao botao--pequeno" onClick={() => void exportar()}>
              Exportar PDF
            </button>
            <button type="button" className="botao botao--discreto" onClick={aoFechar}>
              Fechar
            </button>
          </div>
        </div>

        {erroPdf ? (
          <div className="mensagem mensagem--aviso" style={{ marginBottom: "var(--espaco-4)" }}>
            <div className="pilha" style={{ gap: 2 }}>
              <strong>PDF indisponível</strong>
              <span>{erroPdf}</span>
              <span className="terciario">
                O relatório continua disponível aqui e em JSON — o servidor diz
                que não consegue produzir o PDF em vez de entregar um ficheiro
                vazio.
              </span>
            </div>
          </div>
        ) : null}

        {isPending ? <Carregando /> : error ? <Erro erro={error} /> : (
          <Conteudo conteudo={data.content} />
        )}
      </div>
    </div>
  );
}

function Gerar() {
  const clienteDeDados = useQueryClient();
  const [incidente, definirIncidente] = useState("");
  const [inicio, definirInicio] = useState("");
  const [fim, definirFim] = useState("");

  const { data: incidentes } = useQuery({
    queryKey: ["incidentes-para-relatorio"],
    queryFn: () =>
      pedir<Pagina<IncidenteResumo>>(`/incidents${consulta({ size: 100, sort: "-detected_at" })}`),
  });

  const doIncidente = useMutation({
    mutationFn: () =>
      pedir<RelatorioDetalhado>("/reports/incident", {
        metodo: "POST",
        corpo: { incident_id: incidente },
      }),
    onSuccess: () => clienteDeDados.invalidateQueries({ queryKey: ["relatorios"] }),
  });

  const doPeriodo = useMutation({
    mutationFn: () =>
      pedir<RelatorioDetalhado>("/reports/period", {
        metodo: "POST",
        corpo: {
          start: new Date(inicio).toISOString(),
          end: new Date(fim).toISOString(),
        },
      }),
    onSuccess: () => clienteDeDados.invalidateQueries({ queryKey: ["relatorios"] }),
  });

  return (
    <div className="grelha grelha--2">
      <div className="cartao pilha">
        <h3>Relatório de incidente</h3>
        <p className="secundario">
          Reconstitui um incidente: o que aconteceu, quando, como foi detectado,
          quem investigou, que evidências e decisões existem, e o resultado.
        </p>
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="incidente">
            Incidente
          </label>
          <select
            id="incidente"
            className="selector"
            value={incidente}
            onChange={(e) => definirIncidente(e.target.value)}
          >
            <option value="">Escolha um incidente…</option>
            {incidentes?.itens.map((i) => (
              <option key={i.id} value={i.id}>
                {i.reference} — {i.title}
              </option>
            ))}
          </select>
        </div>
        {doIncidente.error ? <Erro erro={doIncidente.error} /> : null}
        <div>
          <button
            type="button"
            className="botao botao--primario"
            disabled={!incidente || doIncidente.isPending}
            onClick={() => doIncidente.mutate()}
          >
            {doIncidente.isPending ? "A gerar…" : "Gerar"}
          </button>
        </div>
      </div>

      <div className="cartao pilha">
        <h3>Relatório de período</h3>
        <p className="secundario">
          Agrega os incidentes de um intervalo: volumes por severidade, por
          categoria e tempos médios de resposta.
        </p>
        <div className="grelha grelha--2">
          <div className="campo">
            <label className="campo__etiqueta" htmlFor="inicio">
              Início
            </label>
            <input
              id="inicio"
              className="entrada"
              type="date"
              value={inicio}
              onChange={(e) => definirInicio(e.target.value)}
            />
          </div>
          <div className="campo">
            <label className="campo__etiqueta" htmlFor="fim">
              Fim
            </label>
            <input
              id="fim"
              className="entrada"
              type="date"
              value={fim}
              onChange={(e) => definirFim(e.target.value)}
            />
          </div>
        </div>
        {doPeriodo.error ? <Erro erro={doPeriodo.error} /> : null}
        <div>
          <button
            type="button"
            className="botao botao--primario"
            disabled={!inicio || !fim || doPeriodo.isPending}
            onClick={() => doPeriodo.mutate()}
          >
            {doPeriodo.isPending ? "A gerar…" : "Gerar"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Relatorios() {
  const { ler, definir } = useFiltros();
  const { pode } = useSessao();
  const [aberto, definirAberto] = useState<string | null>(null);

  const parametros = { page: ler("page", "1"), size: "20" };

  const { data, isPending, error } = useQuery({
    queryKey: ["relatorios", parametros],
    queryFn: () => pedir<Pagina<Relatorio>>(`/reports${consulta(parametros)}`),
  });

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Relatórios</h1>
          <p className="pagina__descricao">
            Gerados a partir da base de dados no momento do pedido. O conteúdo
            fica guardado tal como foi produzido, o que permite mostrar mais
            tarde o que o relatório dizia na altura.
          </p>
        </div>
      </div>

      <div className="pilha" style={{ gap: "var(--espaco-5)" }}>
        {pode("reports:generate") ? <Gerar /> : null}

        <div>
          <h2 style={{ marginBottom: "var(--espaco-3)" }}>Gerados</h2>
          {error ? <Erro erro={error} /> : null}
          {isPending ? (
            <Carregando />
          ) : data && data.total === 0 ? (
            <div className="tabela-envolvente">
              <Vazio
                titulo="Ainda não há relatórios"
                detalhe="Gere o primeiro a partir de um incidente ou de um período."
              />
            </div>
          ) : data ? (
            <div className="tabela-envolvente">
              <table className="tabela">
                <thead>
                  <tr>
                    <th>Referência</th>
                    <th>Título</th>
                    <th>Tipo</th>
                    <th>Registos</th>
                    <th>Gerado em</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.itens.map((relatorio) => (
                    <tr
                      key={relatorio.id}
                      className="clicavel"
                      onClick={() => definirAberto(relatorio.id)}
                    >
                      <td className="mono">{relatorio.reference}</td>
                      <td>{relatorio.title}</td>
                      <td className="secundario">{legivel(relatorio.kind)}</td>
                      <td className="mono">{relatorio.record_count}</td>
                      <td className="secundario">{instante(relatorio.created_at)}</td>
                      <td>
                        <span className="terciario">Abrir</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
            </div>
          ) : null}
        </div>
      </div>

      {aberto ? <Visualizador id={aberto} aoFechar={() => definirAberto(null)} /> : null}
    </>
  );
}
