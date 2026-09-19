/**
 * Fila de comunicações recebidas de fora (§5 · §37 · RTIR).
 *
 * É a fila que o RTIR chama *Incident Reports*, e a distinção que ele acerta está
 * aqui inteira: **a comunicação não é o incidente.** É matéria-prima. Por isso
 * esta página não edita incidentes — decide o que fazer com o que chegou.
 *
 * Três coisas que o ecrã torna visíveis de propósito:
 *
 * **O que quem comunicou afirmou fica marcado como afirmação.** A gravidade e o
 * tipo aparecem com a etiqueta "afirma", e não como se fossem a avaliação da
 * equipa. Fundir as duas faria uma opinião de terceiros passar por conclusão
 * própria, que é o que o §4 proíbe.
 *
 * **Aceitar exige um incidente.** O formulário não deixa aceitar sem escolher
 * entre ligar a um existente e criar um novo, porque o servidor recusa — e um
 * botão que produz sempre um erro é pior do que um botão que não existe.
 *
 * **Quantas vezes quem comunicou foi ver o estado.** Um número alto numa
 * comunicação ainda por avaliar é uma pessoa à espera, e é a única forma de o
 * saber sem que ela volte a escrever.
 */

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type {
  Comunicacao,
  ComunicacaoResumo,
  IncidenteResumo,
  Pagina,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import {
  Carregando,
  DistintivoDeSeveridade,
  Erro,
  instante,
  legivel,
  Vazio,
} from "@/componentes/comuns";
import {
  ateISO,
  CampoDeSelecao,
  CATEGORIAS,
  desdeISO,
  FiltroDePeriodo,
  Paginacao,
  SEVERIDADES,
  useFiltros,
} from "@/componentes/listagem";

const ESTADOS = [
  { valor: "RECEBIDA", rotulo: "Recebida" },
  { valor: "EM_TRIAGEM", rotulo: "Em avaliação" },
  { valor: "ACEITE", rotulo: "Aceite" },
  { valor: "RECUSADA", rotulo: "Recusada" },
  { valor: "DUPLICADA", rotulo: "Duplicada" },
];

const CANAIS = [
  { valor: "PORTAL", rotulo: "Portal externo" },
  { valor: "EMAIL", rotulo: "Correio electrónico" },
  { valor: "API", rotulo: "API" },
  { valor: "MANUAL", rotulo: "Registada por um analista" },
];

const APARENCIA_DO_ESTADO: Record<string, string> = {
  RECEBIDA: "distintivo--aviso",
  EM_TRIAGEM: "distintivo--neutro",
  ACEITE: "distintivo--sucesso",
  RECUSADA: "distintivo--neutro",
  DUPLICADA: "distintivo--neutro",
};

/** Etiqueta que distingue o que foi afirmado do que foi avaliado. */
function Afirmado({
  severidade,
  categoria,
}: {
  severidade: string | null;
  categoria: string | null;
}) {
  if (!severidade && !categoria) {
    return (
      <span className="terciario" title="Quem comunicou não classificou.">
        não classificou
      </span>
    );
  }
  return (
    <span
      className="terciario"
      title="Classificação indicada por quem comunicou, não avaliação da equipa."
    >
      afirma{" "}
      {severidade ? (
        <DistintivoDeSeveridade valor={severidade as never} />
      ) : null}{" "}
      {categoria ? legivel(categoria) : ""}
    </span>
  );
}

// ------------------------------------------------------------------ decisões
function PainelDeDecisao({
  comunicacao,
  aoFechar,
}: {
  comunicacao: ComunicacaoResumo;
  aoFechar: () => void;
}) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [acto, definirActo] = useState<"aceitar" | "recusar" | "duplicar" | null>(null);
  const [nota, definirNota] = useState("");
  const [comoAceitar, definirComoAceitar] = useState<"novo" | "existente">("novo");
  const [incidenteAlvo, definirIncidenteAlvo] = useState("");
  const [categoria, definirCategoria] = useState("");
  const [severidade, definirSeveridade] = useState("");
  const [originalAlvo, definirOriginalAlvo] = useState("");
  const [pesquisa, definirPesquisa] = useState("");

  const detalhe = useQuery({
    queryKey: ["comunicacao", comunicacao.id],
    queryFn: () => pedir<Comunicacao>(`/reports-inbox/${comunicacao.id}`),
  });

  const candidatos = useQuery({
    queryKey: ["incidentes-para-comunicacao", pesquisa],
    queryFn: () =>
      pedir<Pagina<IncidenteResumo>>(
        `/incidents${consulta({ q: pesquisa, size: 30, sort: "-detected_at" })}`,
      ),
    enabled: acto === "aceitar" && comoAceitar === "existente",
  });

  const outras = useQuery({
    queryKey: ["comunicacoes-para-duplicar"],
    queryFn: () =>
      pedir<Pagina<ComunicacaoResumo>>("/reports-inbox?size=50"),
    enabled: acto === "duplicar",
  });

  const invalidar = async () => {
    await clienteDeDados.invalidateQueries({ queryKey: ["comunicacoes"] });
    await clienteDeDados.invalidateQueries({ queryKey: ["comunicacao", comunicacao.id] });
  };

  const assumir = useMutation({
    mutationFn: () =>
      pedir<Comunicacao>(`/reports-inbox/${comunicacao.id}/triage`, { metodo: "POST" }),
    onSuccess: invalidar,
  });

  const decidir = useMutation({
    mutationFn: () => {
      if (acto === "aceitar") {
        return pedir<Comunicacao>(`/reports-inbox/${comunicacao.id}/accept`, {
          metodo: "POST",
          corpo: {
            criar_incidente: comoAceitar === "novo",
            incident_id: comoAceitar === "existente" ? incidenteAlvo : null,
            categoria: categoria || null,
            severidade: severidade || null,
            nota,
          },
        });
      }
      if (acto === "recusar") {
        return pedir<Comunicacao>(`/reports-inbox/${comunicacao.id}/reject`, {
          metodo: "POST",
          corpo: { nota },
        });
      }
      return pedir<Comunicacao>(`/reports-inbox/${comunicacao.id}/duplicate`, {
        metodo: "POST",
        corpo: { original_id: originalAlvo, nota },
      });
    },
    onSuccess: async () => {
      await invalidar();
      definirActo(null);
      definirNota("");
    },
  });

  const d = detalhe.data;
  const podeTriar = pode("reports_inbox:triage");

  return (
    <div
      className="sobreposicao"
      role="dialog"
      aria-modal="true"
      aria-label={`Comunicação ${comunicacao.reference}`}
      onClick={aoFechar}
    >
      <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
        <div
          className="linha linha--espalhada"
          style={{ marginBottom: "var(--espaco-4)" }}
        >
          <div className="pilha" style={{ gap: 0 }}>
            <h2>{comunicacao.subject}</h2>
            <span className="terciario mono">
              {comunicacao.reference} · {legivel(comunicacao.channel)}
            </span>
          </div>
          <button type="button" className="botao botao--discreto" onClick={aoFechar}>
            Fechar
          </button>
        </div>

        {detalhe.error ? <Erro erro={detalhe.error} /> : null}
        {detalhe.isPending ? <Carregando /> : null}

        {d ? (
          <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
            <div className="linha linha--espalhada">
              <span
                className={`distintivo ${APARENCIA_DO_ESTADO[d.status] ?? "distintivo--neutro"}`}
              >
                {legivel(d.status)}
              </span>
              <Afirmado
                severidade={d.claimed_severity}
                categoria={d.claimed_category}
              />
            </div>

            <div className="propriedades">
              <div className="propriedade">
                <span className="propriedade__rotulo">Quem comunicou</span>
                <span className="propriedade__valor">{d.reporter_name}</span>
              </div>
              <div className="propriedade">
                <span className="propriedade__rotulo">Endereço</span>
                <span className="propriedade__valor mono">{d.reporter_email}</span>
              </div>
              {d.reporter_organisation ? (
                <div className="propriedade">
                  <span className="propriedade__rotulo">Organização</span>
                  <span className="propriedade__valor">{d.reporter_organisation}</span>
                </div>
              ) : null}
              {d.reporter_phone ? (
                <div className="propriedade">
                  <span className="propriedade__rotulo">Telefone</span>
                  <span className="propriedade__valor mono">{d.reporter_phone}</span>
                </div>
              ) : null}
              <div className="propriedade">
                <span className="propriedade__rotulo">Recebida</span>
                <span className="propriedade__valor">{instante(d.received_at)}</span>
              </div>
              <div className="propriedade">
                <span className="propriedade__rotulo">Consultas do estado</span>
                <span
                  className="propriedade__valor mono"
                  title="Quantas vezes quem comunicou foi ver o estado."
                >
                  {d.tracking_views}
                </span>
              </div>
              {d.submitted_from_ip ? (
                <div className="propriedade">
                  <span className="propriedade__rotulo">Origem da submissão</span>
                  <span className="propriedade__valor mono">{d.submitted_from_ip}</span>
                </div>
              ) : null}
              {d.triaged_by_email ? (
                <div className="propriedade">
                  <span className="propriedade__rotulo">Avaliada por</span>
                  <span className="propriedade__valor">{d.triaged_by_email}</span>
                </div>
              ) : null}
            </div>

            <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
              <strong>Relato, como foi escrito</strong>
              <pre className="bloco-bruto">{d.description}</pre>
            </div>

            {d.reported_indicators.trim() ? (
              <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
                <strong>Indicadores indicados por quem comunicou</strong>
                <pre className="bloco-bruto">{d.reported_indicators}</pre>
                <p className="terciario">
                  Não estão no catálogo. Um valor não verificado contaminaria a
                  triagem de tudo o que o tocasse — verifique antes de o registar
                  como indicador.
                </p>
              </div>
            ) : null}

            {d.incidents.length > 0 ? (
              <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
                <strong>Incidentes ligados</strong>
                {d.incidents.map((i) => (
                  <div key={i.id} className="linha linha--espalhada">
                    <Link to={`/incidentes/${i.id}`} className="mono">
                      {i.reference}
                    </Link>
                    <span className="secundario truncar" style={{ maxWidth: "28ch" }}>
                      {i.title}
                    </span>
                    <span className="distintivo distintivo--neutro">
                      {legivel(i.status)}
                    </span>
                  </div>
                ))}
              </div>
            ) : null}

            {d.duplicate_of_reference ? (
              <p className="secundario">
                Duplicada de{" "}
                <span className="mono">{d.duplicate_of_reference}</span>. Continua
                a existir, com o seu histórico — não foi fundida nem apagada.
              </p>
            ) : null}

            {d.triage_note ? (
              <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
                <strong>Nota de avaliação</strong>
                <p className="secundario">{d.triage_note}</p>
                <p className="terciario">
                  Interna. Quem comunicou não a vê — só vê em que ponto está.
                </p>
              </div>
            ) : null}

            {podeTriar ? (
              <>
                <div className="separador" />
                {d.status === "RECEBIDA" ? (
                  <div className="linha">
                    <button
                      type="button"
                      className="botao botao--pequeno"
                      disabled={assumir.isPending}
                      onClick={() => assumir.mutate()}
                    >
                      {assumir.isPending ? "A assumir…" : "Assumir a avaliação"}
                    </button>
                  </div>
                ) : null}
                {assumir.error ? <Erro erro={assumir.error} /> : null}

                {acto === null ? (
                  <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="botao botao--primario botao--pequeno"
                      onClick={() => definirActo("aceitar")}
                    >
                      Aceitar
                    </button>
                    <button
                      type="button"
                      className="botao botao--pequeno"
                      onClick={() => definirActo("duplicar")}
                    >
                      Marcar duplicada
                    </button>
                    <button
                      type="button"
                      className="botao botao--perigo botao--pequeno"
                      onClick={() => definirActo("recusar")}
                    >
                      Recusar
                    </button>
                  </div>
                ) : (
                  <form
                    className="cartao pilha"
                    style={{ gap: "var(--espaco-3)" }}
                    onSubmit={(e) => {
                      e.preventDefault();
                      decidir.mutate();
                    }}
                  >
                    {acto === "aceitar" ? (
                      <>
                        <strong>Aceitar a comunicação</strong>
                        <p className="terciario">
                          Aceitar exige um incidente. Sem ligação, a comunicação
                          saía da fila sem aparecer em incidente nenhum.
                        </p>
                        <CampoDeSelecao
                          etiqueta="Como"
                          valor={comoAceitar}
                          opcoes={[
                            { valor: "novo", rotulo: "Criar um incidente novo" },
                            { valor: "existente", rotulo: "Ligar a um existente" },
                          ]}
                          aoMudar={(v) =>
                            definirComoAceitar(v === "existente" ? "existente" : "novo")
                          }
                          todos="Criar um incidente novo"
                        />

                        {comoAceitar === "existente" ? (
                          <>
                            <label className="campo">
                              <span className="campo__etiqueta">Procurar incidente</span>
                              <input
                                type="search"
                                value={pesquisa}
                                placeholder="Referência ou título…"
                                onChange={(e) => definirPesquisa(e.target.value)}
                              />
                            </label>
                            <label className="campo">
                              <span className="campo__etiqueta">Incidente</span>
                              <select
                                className="selector"
                                required
                                value={incidenteAlvo}
                                onChange={(e) => definirIncidenteAlvo(e.target.value)}
                              >
                                <option value="">— escolher —</option>
                                {candidatos.data?.itens.map((i) => (
                                  <option key={i.id} value={i.id}>
                                    {i.reference} · {i.title.slice(0, 60)}
                                  </option>
                                ))}
                              </select>
                            </label>
                            {candidatos.error ? <Erro erro={candidatos.error} /> : null}
                          </>
                        ) : (
                          <>
                            <p className="terciario">
                              Sem escolher, o incidente herda o que quem comunicou
                              afirmou — mas passa a constar como avaliação da
                              equipa.
                            </p>
                            <div
                              className="linha"
                              style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}
                            >
                              <CampoDeSelecao
                                etiqueta="Categoria da equipa"
                                valor={categoria}
                                opcoes={CATEGORIAS}
                                aoMudar={definirCategoria}
                                todos={
                                  d.claimed_category
                                    ? `Herdar (${legivel(d.claimed_category)})`
                                    : "Outro"
                                }
                              />
                              <CampoDeSelecao
                                etiqueta="Gravidade da equipa"
                                valor={severidade}
                                opcoes={SEVERIDADES}
                                aoMudar={definirSeveridade}
                                todos={
                                  d.claimed_severity
                                    ? `Herdar (${legivel(d.claimed_severity)})`
                                    : "Média"
                                }
                              />
                            </div>
                          </>
                        )}
                      </>
                    ) : null}

                    {acto === "duplicar" ? (
                      <>
                        <strong>Marcar como duplicada</strong>
                        <p className="terciario">
                          As duas continuam a existir. Quem comunicou esta vê que
                          está a ser tratada na outra.
                        </p>
                        <label className="campo">
                          <span className="campo__etiqueta">Comunicação original</span>
                          <select
                            className="selector"
                            required
                            value={originalAlvo}
                            onChange={(e) => definirOriginalAlvo(e.target.value)}
                          >
                            <option value="">— escolher —</option>
                            {outras.data?.itens
                              .filter(
                                (o) => o.id !== d.id && o.status !== "DUPLICADA",
                              )
                              .map((o) => (
                                <option key={o.id} value={o.id}>
                                  {o.reference} · {o.subject.slice(0, 60)}
                                </option>
                              ))}
                          </select>
                          <span className="campo__ajuda">
                            Um duplicado de um duplicado é recusado: a cadeia não
                            levaria a nada.
                          </span>
                        </label>
                        {outras.error ? <Erro erro={outras.error} /> : null}
                      </>
                    ) : null}

                    {acto === "recusar" ? (
                      <>
                        <strong>Recusar a comunicação</strong>
                        <p className="terciario">
                          A justificação é obrigatória. Quem comunicou vai ler o
                          estado, e uma recusa sem motivo é indistinguível de uma
                          comunicação esquecida.
                        </p>
                      </>
                    ) : null}

                    <label className="campo">
                      <span className="campo__etiqueta">
                        {acto === "duplicar" ? "Nota (opcional)" : "Justificação"}
                      </span>
                      <textarea
                        className="area-texto"
                        rows={3}
                        required={acto !== "duplicar"}
                        minLength={acto !== "duplicar" ? 3 : 0}
                        maxLength={2000}
                        value={nota}
                        onChange={(e) => definirNota(e.target.value)}
                      />
                    </label>

                    {decidir.error ? <Erro erro={decidir.error} /> : null}

                    <div className="linha" style={{ gap: "var(--espaco-2)" }}>
                      <button
                        className={`botao botao--pequeno ${
                          acto === "recusar" ? "botao--perigo" : "botao--primario"
                        }`}
                        disabled={
                          decidir.isPending ||
                          (acto === "aceitar" &&
                            comoAceitar === "existente" &&
                            !incidenteAlvo) ||
                          (acto === "duplicar" && !originalAlvo) ||
                          (acto !== "duplicar" && nota.trim().length < 3)
                        }
                      >
                        {decidir.isPending ? "A registar…" : "Confirmar"}
                      </button>
                      <button
                        type="button"
                        className="botao botao--discreto botao--pequeno"
                        onClick={() => definirActo(null)}
                      >
                        Cancelar
                      </button>
                    </div>
                  </form>
                )}
              </>
            ) : (
              <p className="terciario">
                Não tem permissão para avaliar comunicações. A leitura serve para
                acompanhar a fila.
              </p>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------- listagem
export function Comunicacoes() {
  const { ler, definir, limpar } = useFiltros();
  const [aberta, definirAberta] = useState<ComunicacaoResumo | null>(null);

  const parametros = {
    estado: ler("estado"),
    canal: ler("canal"),
    q: ler("q"),
    severidade_afirmada: ler("severidade_afirmada"),
    categoria_afirmada: ler("categoria_afirmada"),
    desde: desdeISO(ler("desde")),
    ate: ateISO(ler("ate")),
    page: ler("page", "1"),
    size: "25",
    sort: ler("sort", "-received_at"),
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["comunicacoes", parametros],
    queryFn: () =>
      pedir<Pagina<ComunicacaoResumo>>(`/reports-inbox${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const temFiltros = [
    "estado", "canal", "q", "severidade_afirmada", "categoria_afirmada",
    "desde", "ate",
  ].some((c) => ler(c) !== "");

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Comunicações recebidas</h1>
          <p className="pagina__descricao">
            O que chegou de fora — do portal externo, por correio electrónico ou
            por API. Uma comunicação <strong>não é</strong> um incidente: é
            matéria-prima. Várias podem descrever o mesmo incidente, e uma pode
            não descrever incidente nenhum.
          </p>
        </div>
      </div>

      <div className="filtros">
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="pesquisa-comunicacoes">
            Pesquisa
          </label>
          <input
            id="pesquisa-comunicacoes"
            className="entrada"
            type="search"
            placeholder="Referência, assunto ou quem comunicou…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <CampoDeSelecao
          etiqueta="Estado"
          valor={ler("estado")}
          opcoes={ESTADOS}
          aoMudar={(v) => definir({ estado: v })}
          todos="Por decidir"
        />
        <CampoDeSelecao
          etiqueta="Canal"
          valor={ler("canal")}
          opcoes={CANAIS}
          aoMudar={(v) => definir({ canal: v })}
        />
        <CampoDeSelecao
          etiqueta="Gravidade afirmada"
          valor={ler("severidade_afirmada")}
          opcoes={SEVERIDADES}
          aoMudar={(v) => definir({ severidade_afirmada: v })}
        />
        <FiltroDePeriodo desde={ler("desde")} ate={ler("ate")} aoMudar={definir} />
        {temFiltros ? (
          <button type="button" className="botao botao--discreto" onClick={limpar}>
            Limpar filtros
          </button>
        ) : null}
        {isFetching ? <span className="carregando" aria-hidden="true" /> : null}
      </div>

      {error ? <Erro erro={error} /> : null}
      {isPending ? <Carregando /> : null}

      {data && data.itens.length === 0 ? (
        <Vazio
          titulo="Nenhuma comunicação"
          detalhe={
            temFiltros
              ? "Nenhuma comunicação corresponde a estes filtros."
              : "Não há comunicações por decidir. As já decididas aparecem escolhendo um estado."
          }
        />
      ) : null}

      {data && data.itens.length > 0 ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Referência</th>
                <th>Assunto</th>
                <th>Quem comunicou</th>
                <th>Canal</th>
                <th>Afirma</th>
                <th>Recebida</th>
                <th>Consultas</th>
                <th>Estado</th>
                <th>Incidentes</th>
              </tr>
            </thead>
            <tbody>
              {data.itens.map((c) => (
                <tr key={c.id}>
                  <td>
                    <button
                      type="button"
                      className="botao botao--discreto botao--pequeno mono"
                      onClick={() => definirAberta(c)}
                    >
                      {c.reference}
                    </button>
                  </td>
                  <td>
                    <span className="truncar" style={{ maxWidth: "32ch" }} title={c.subject}>
                      {c.subject}
                    </span>
                  </td>
                  <td className="secundario">
                    <div className="truncar" style={{ maxWidth: "22ch" }}>
                      {c.reporter_name}
                    </div>
                    <div className="terciario truncar" style={{ maxWidth: "22ch" }}>
                      {c.reporter_organisation || c.reporter_email}
                    </div>
                  </td>
                  <td className="secundario">{legivel(c.channel)}</td>
                  <td>
                    <Afirmado
                      severidade={c.claimed_severity}
                      categoria={c.claimed_category}
                    />
                  </td>
                  <td className="secundario">{instante(c.received_at)}</td>
                  <td
                    className="mono secundario"
                    title="Quantas vezes quem comunicou foi ver o estado."
                  >
                    {c.tracking_views}
                  </td>
                  <td>
                    <span
                      className={`distintivo ${APARENCIA_DO_ESTADO[c.status] ?? "distintivo--neutro"}`}
                    >
                      {legivel(c.status)}
                    </span>
                  </td>
                  <td>
                    {c.incidents.length === 0 ? (
                      <span className="terciario">—</span>
                    ) : (
                      c.incidents.map((i) => (
                        <Link key={i.id} to={`/incidentes/${i.id}`} className="mono">
                          {i.reference}{" "}
                        </Link>
                      ))
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(numero) => definir({ page: numero })} />
        </div>
      ) : null}

      {aberta ? (
        <PainelDeDecisao comunicacao={aberta} aoFechar={() => definirAberta(null)} />
      ) : null}
    </>
  );
}
