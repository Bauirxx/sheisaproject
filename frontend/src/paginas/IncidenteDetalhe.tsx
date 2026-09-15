/**
 * Detalhe do incidente (§4.13, tela 5 · §81 do briefing).
 *
 * Duas decisões governam esta página:
 *
 * **O ciclo de vida vem do servidor.** Os botões de transição são construídos a
 * partir de `transicoes_permitidas`, que a API devolve em cada incidente.
 * Reimplementar o grafo aqui daria duas versões da mesma regra, e a do cliente
 * ficaria desactualizada na primeira vez que alguém editasse
 * `INCIDENT_TRANSITIONS` no servidor — com o sintoma de a interface oferecer
 * botões que devolvem 409.
 *
 * **As técnicas MITRE distinguem afirmado de inferido.** Uma técnica que a
 * fonte declarou e uma que o motor sugeriu não são a mesma coisa, e apresentá-
 * las igual seria transformar hipótese em facto — que é precisamente o que o
 * §11 proíbe.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import {
  consulta,
  descarregar,
  enviarFormulario,
  ErroDaApi,
  pedir,
} from "@/api/cliente";
import type {
  Accao,
  Alerta,
  Comentario,
  EntradaDaLinhaTemporal,
  EstadoIncidente,
  Evidencia,
  Incidente,
  Grafo,
  Observacao,
  Pagina,
  UtilizadorResumo,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import {
  Carregando,
  DistintivoDeEstado,
  DistintivoDeEstadoDoAlerta,
  DistintivoDeSeveridade,
  duracao,
  Erro,
  instante,
  legivel,
  MarcaDeDemonstracao,
  tamanhoDeFicheiro,
  Vazio,
} from "@/componentes/comuns";
import { GrafoInvestigativo } from "@/componentes/GrafoInvestigativo";

type Aba =
  | "visao"
  | "linha"
  | "alertas"
  | "observacoes"
  | "evidencias"
  | "accoes"
  | "tecnicas"
  | "grafo";

const ABAS: { chave: Aba; rotulo: string }[] = [
  { chave: "visao", rotulo: "Visão geral" },
  { chave: "linha", rotulo: "Linha temporal" },
  { chave: "alertas", rotulo: "Alertas" },
  { chave: "observacoes", rotulo: "Observações" },
  { chave: "evidencias", rotulo: "Evidências" },
  { chave: "accoes", rotulo: "Acções" },
  { chave: "tecnicas", rotulo: "Técnicas" },
  { chave: "grafo", rotulo: "Grafo" },
];

const ROTULO_DO_ESTADO: Record<string, string> = {
  ABERTO: "Abrir",
  TRIAGEM: "Iniciar triagem",
  INVESTIGACAO: "Investigar",
  CONTENCAO: "Conter",
  ERRADICACAO: "Erradicar",
  RECUPERACAO: "Recuperar",
  RESOLVIDO: "Resolver",
  ENCERRADO: "Encerrar",
  SUSPENSO: "Suspender",
  ESCALADO: "Escalar",
  FALSO_POSITIVO: "Marcar falso positivo",
  DUPLICADO: "Marcar duplicado",
};

function Propriedade({ rotulo, children }: { rotulo: string; children: React.ReactNode }) {
  return (
    <div className="propriedade">
      <span className="propriedade__rotulo">{rotulo}</span>
      <span className="propriedade__valor">{children}</span>
    </div>
  );
}

/**
 * Transição de estado.
 *
 * Resolver exige resumo e marcar falso positivo exige motivo — não por
 * formalismo, mas porque a API recusa sem eles, e porque é desse texto que o
 * relatório e o detector de falsos positivos se alimentam. Pedi-los no
 * formulário evita um 422 que o utilizador teria de decifrar.
 */
function Transicoes({ incidente }: { incidente: Incidente }) {
  const clienteDeDados = useQueryClient();
  const [destino, definirDestino] = useState<EstadoIncidente | null>(null);
  const [nota, definirNota] = useState("");

  const exigeResumo = destino === "RESOLVIDO";
  const exigeMotivo = destino === "FALSO_POSITIVO";
  const exigeTexto = exigeResumo || exigeMotivo;

  const transicao = useMutation({
    mutationFn: async () => {
      if (!destino) return;
      await pedir(`/incidents/${incidente.id}/transition`, {
        metodo: "POST",
        corpo: {
          status: destino,
          ...(exigeResumo ? { resolution_summary: nota } : {}),
          ...(exigeMotivo ? { false_positive_reason: nota } : {}),
          ...(!exigeTexto && nota ? { note: nota } : {}),
        },
      });
    },
    onSuccess: async () => {
      definirDestino(null);
      definirNota("");
      await clienteDeDados.invalidateQueries({ queryKey: ["incidente", incidente.id] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidente.id] });
    },
  });

  if (incidente.transicoes_permitidas.length === 0) {
    return (
      <p className="terciario">
        {incidente.status === "ENCERRADO"
          ? "Estado terminal. Reabrir exige registar um incidente relacionado, o que preserva o histórico."
          : "Não há transições disponíveis a partir deste estado."}
      </p>
    );
  }

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="linha" style={{ flexWrap: "wrap", gap: "var(--espaco-2)" }}>
        {incidente.transicoes_permitidas.map((estado) => (
          <button
            key={estado}
            type="button"
            className={`botao botao--pequeno${destino === estado ? " botao--primario" : ""}`}
            onClick={() => {
              definirDestino(destino === estado ? null : estado);
              definirNota("");
            }}
          >
            {ROTULO_DO_ESTADO[estado] ?? estado}
          </button>
        ))}
      </div>

      {destino ? (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          <label className="campo__etiqueta" htmlFor="nota-transicao">
            {exigeResumo
              ? "Resumo da resolução (obrigatório)"
              : exigeMotivo
                ? "Motivo do falso positivo (obrigatório)"
                : "Nota (opcional)"}
          </label>
          <textarea
            id="nota-transicao"
            className="area-texto"
            value={nota}
            onChange={(e) => definirNota(e.target.value)}
            placeholder={
              exigeResumo
                ? "O que foi feito e qual foi o desfecho. Este texto entra no relatório."
                : exigeMotivo
                  ? "Porque é que não era um incidente. Alimenta o detector de falsos positivos."
                  : ""
            }
          />
          {transicao.error ? <Erro erro={transicao.error} /> : null}
          <div className="linha">
            <button
              type="button"
              className="botao botao--primario botao--pequeno"
              disabled={transicao.isPending || (exigeTexto && nota.trim().length === 0)}
              onClick={() => transicao.mutate()}
            >
              {transicao.isPending ? "A aplicar…" : `Confirmar: ${ROTULO_DO_ESTADO[destino] ?? destino}`}
            </button>
            <button
              type="button"
              className="botao botao--discreto botao--pequeno"
              onClick={() => definirDestino(null)}
            >
              Cancelar
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/**
 * Atribuição de responsável.
 *
 * A lista de utilizadores exige `users:read`, que os perfis operacionais têm
 * mas o OPERADOR não. Quando falta, mostramos o responsável actual sem o
 * selector, em vez de deixar um controlo que produziria 403 ao ser usado.
 */
function Atribuicao({ incidente }: { incidente: Incidente }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const podeAtribuir = pode("incidents:assign") && pode("users:read");

  const utilizadores = useQuery({
    queryKey: ["utilizadores-atribuiveis"],
    queryFn: () =>
      pedir<{ itens: UtilizadorResumo[] }>(
        `/users${consulta({ apenas_activos: true, size: 200, sort: "full_name" })}`,
      ),
    enabled: podeAtribuir,
    staleTime: 5 * 60 * 1000,
  });

  const atribuir = useMutation({
    mutationFn: (assignee_id: string | null) =>
      pedir(`/incidents/${incidente.id}/assign`, {
        metodo: "POST",
        corpo: { assignee_id },
      }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["incidente", incidente.id] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidente.id] });
    },
  });

  if (!podeAtribuir) {
    return (
      <p className="secundario">
        {incidente.assignee?.nome ?? (
          <span className="terciario">Sem responsável atribuído.</span>
        )}
      </p>
    );
  }

  return (
    <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
      <select
        className="selector"
        value={incidente.assignee?.id ?? ""}
        disabled={atribuir.isPending || utilizadores.isPending}
        onChange={(e) => atribuir.mutate(e.target.value || null)}
      >
        <option value="">— sem responsável —</option>
        {utilizadores.data?.itens.map((u) => (
          <option key={u.id} value={u.id}>
            {u.full_name} ({u.role?.name ?? "?"})
          </option>
        ))}
      </select>
      {atribuir.isPending ? <span className="terciario">A atribuir…</span> : null}
      {atribuir.error ? <Erro erro={atribuir.error} /> : null}
      {utilizadores.error ? <Erro erro={utilizadores.error} /> : null}
      <p className="terciario">
        Atribuir marca o reconhecimento do incidente, que é o instante a partir
        do qual o tempo de resposta passa a contar.
      </p>
    </div>
  );
}

function Comentarios({ incidenteId }: { incidenteId: string }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [texto, definirTexto] = useState("");

  const { data, isPending, error } = useQuery({
    queryKey: ["comentarios", incidenteId],
    queryFn: () => pedir<Comentario[]>(`/incidents/${incidenteId}/comments`),
  });

  const criar = useMutation({
    mutationFn: () =>
      pedir(`/incidents/${incidenteId}/comments`, {
        metodo: "POST",
        corpo: { body: texto },
      }),
    onSuccess: async () => {
      definirTexto("");
      await clienteDeDados.invalidateQueries({ queryKey: ["comentarios", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidenteId] });
    },
  });

  return (
    <div className="pilha">
      {pode("comments:create") ? (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          <textarea
            className="area-texto"
            placeholder="Observação sobre a investigação…"
            value={texto}
            onChange={(e) => definirTexto(e.target.value)}
          />
          {criar.error ? <Erro erro={criar.error} /> : null}
          <div>
            <button
              type="button"
              className="botao botao--primario botao--pequeno"
              disabled={criar.isPending || texto.trim().length === 0}
              onClick={() => criar.mutate()}
            >
              {criar.isPending ? "A registar…" : "Comentar"}
            </button>
          </div>
        </div>
      ) : null}

      {error ? <Erro erro={error} /> : null}
      {isPending ? (
        <Carregando />
      ) : data && data.length === 0 ? (
        <p className="terciario">Ainda não há comentários neste incidente.</p>
      ) : (
        <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
          {data?.map((comentario) => (
            <div key={comentario.id} className="cartao" style={{ padding: "var(--espaco-4)" }}>
              <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-2)" }}>
                <strong>{comentario.author?.nome ?? "Sistema"}</strong>
                <span className="terciario">{instante(comentario.created_at)}</span>
              </div>
              <p style={{ whiteSpace: "pre-wrap" }}>{comentario.body}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function LinhaTemporal({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["linha", incidenteId],
    queryFn: () =>
      pedir<EntradaDaLinhaTemporal[]>(`/incidents/${incidenteId}/timeline`),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.length === 0) {
    return <Vazio titulo="Sem entradas na linha temporal" />;
  }

  return (
    <div className="linha-temporal">
      {data.map((evento, indice) => (
        <div key={`${evento.instante}-${indice}`} className="evento">
          <span className="evento__instante">{instante(evento.instante)}</span>
          <span className="evento__marca">
            <span className="evento__ponto" />
            <span className="evento__linha" />
          </span>
          <div className="evento__corpo">
            <span className="evento__titulo">{evento.titulo}</span>
            {evento.detalhe ? (
              <span className="evento__detalhe">{evento.detalhe}</span>
            ) : null}
            <span className="evento__autor">
              {evento.autor ?? "Sistema"}
              {evento.referencia ? ` · ${evento.referencia}` : ""}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function AlertasDoIncidente({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["alertas-do-incidente", incidenteId],
    queryFn: () =>
      pedir<Pagina<Alerta>>(`/alerts${consulta({ incidente_id: incidenteId, size: 100 })}`),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.total === 0) {
    return (
      <Vazio
        titulo="Nenhum alerta associado"
        detalhe="Este incidente foi registado manualmente, sem origem numa detecção automática."
      />
    );
  }

  return (
    <div className="tabela-envolvente">
      <table className="tabela">
        <thead>
          <tr>
            <th>Referência</th>
            <th>Título</th>
            <th>Fonte</th>
            <th>Severidade</th>
            <th>Pontuação</th>
            <th>Eventos</th>
            <th>Estado</th>
          </tr>
        </thead>
        <tbody>
          {data.itens.map((alerta) => (
            <tr key={alerta.id}>
              <td className="mono">{alerta.reference}</td>
              <td>{alerta.title}</td>
              <td className="secundario">{alerta.source_kind}</td>
              <td>
                <DistintivoDeSeveridade valor={alerta.severity} />
              </td>
              <td className="mono">{alerta.triage_score}/100</td>
              <td className="mono">{alerta.event_count}</td>
              <td>
                <DistintivoDeEstadoDoAlerta valor={alerta.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Observacoes({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["observacoes", incidenteId],
    queryFn: () => pedir<Observacao[]>(`/incidents/${incidenteId}/observations`),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.length === 0) {
    return (
      <Vazio
        titulo="Sem observações"
        detalhe="Uma observação é um avistamento concreto de um indicador neste incidente — é o que dá arestas ao grafo investigativo."
      />
    );
  }

  return (
    <div className="tabela-envolvente">
      <table className="tabela">
        <thead>
          <tr>
            <th>Indicador</th>
            <th>Tipo</th>
            <th>Papel</th>
            <th>Reputação</th>
            <th>Observado em</th>
            <th>Contexto</th>
          </tr>
        </thead>
        <tbody>
          {data.map((observacao) => (
            <tr key={observacao.id}>
              <td className="mono">{observacao.ioc.value}</td>
              <td className="secundario">{legivel(observacao.ioc.ioc_type)}</td>
              <td className="secundario">{legivel(observacao.role)}</td>
              <td className="secundario">{legivel(observacao.ioc.reputation)}</td>
              <td className="secundario">{instante(observacao.observed_at)}</td>
              <td className="secundario">{observacao.context ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Carregamento de evidência. Só aparece a quem tem `evidence:upload`. */
function CarregarEvidencia({ incidenteId }: { incidenteId: string }) {
  const clienteDeConsultas = useQueryClient();
  const [ficheiro, definirFicheiro] = useState<File | null>(null);
  const [descricao, definirDescricao] = useState("");
  const [tipo, definirTipo] = useState("LOG");
  const [aberto, definirAberto] = useState(false);

  const enviar = useMutation({
    mutationFn: async () => {
      if (!ficheiro) throw new Error("Escolha um ficheiro.");
      const formulario = new FormData();
      // Os nomes dos campos são os que a API declara no formulário
      // (ver app/api/v1/investigation.py).
      formulario.append("incident_id", incidenteId);
      formulario.append("ficheiro", ficheiro);
      formulario.append("descricao", descricao);
      formulario.append("tipo", tipo);
      return enviarFormulario<Evidencia>("/evidence", formulario);
    },
    onSuccess: () => {
      clienteDeConsultas.invalidateQueries({ queryKey: ["evidencias", incidenteId] });
      // A chave da linha temporal é "linha" (ver `LinhaTemporal`); usar outro
      // nome invalidaria uma consulta inexistente e a nova evidência só
      // apareceria depois de recarregar a página.
      clienteDeConsultas.invalidateQueries({ queryKey: ["linha", incidenteId] });
      definirFicheiro(null);
      definirDescricao("");
      definirAberto(false);
    },
  });

  if (!aberto) {
    return (
      <div className="linha">
        <button className="botao botao--pequeno" onClick={() => definirAberto(true)}>
          Carregar evidência
        </button>
      </div>
    );
  }

  return (
    <form
      className="cartao pilha"
      style={{ gap: "var(--espaco-3)" }}
      onSubmit={(e) => {
        e.preventDefault();
        enviar.mutate();
      }}
    >
      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo">
          <span className="campo__etiqueta">Ficheiro</span>
          <input
            type="file"
            required
            onChange={(e) => definirFicheiro(e.target.files?.[0] ?? null)}
          />
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Tipo</span>
          <select value={tipo} onChange={(e) => definirTipo(e.target.value)}>
            <option value="LOG">Registo (log)</option>
            <option value="CAPTURA_ECRA">Captura de ecrã</option>
            <option value="CAPTURA_REDE">Captura de rede</option>
            <option value="FICHEIRO">Ficheiro</option>
            <option value="RELATORIO">Relatório</option>
            <option value="ARTEFACTO">Artefacto</option>
            <option value="OUTRO">Outro</option>
          </select>
        </label>
      </div>
      <label className="campo">
        <span className="campo__etiqueta">Descrição</span>
        <input
          type="text"
          value={descricao}
          maxLength={2000}
          placeholder="O que é e de onde veio."
          onChange={(e) => definirDescricao(e.target.value)}
        />
      </label>
      <p className="terciario">
        O SHA-256 é calculado sobre os bytes recebidos e passa a ser a
        referência para verificações de integridade posteriores.
      </p>
      {enviar.error ? <Erro erro={enviar.error} /> : null}
      <div className="linha">
        <button className="botao botao--primario" disabled={enviar.isPending}>
          {enviar.isPending ? "A carregar…" : "Carregar"}
        </button>
        <button
          type="button"
          className="botao botao--pequeno"
          onClick={() => definirAberto(false)}
          disabled={enviar.isPending}
        >
          Cancelar
        </button>
      </div>
    </form>
  );
}

function Evidencias({ incidenteId }: { incidenteId: string }) {
  const { pode } = useSessao();
  const [erroDeDescarga, definirErroDeDescarga] = useState<unknown>(null);
  const { data, isPending, error } = useQuery({
    queryKey: ["evidencias", incidenteId],
    queryFn: () => pedir<Evidencia[]>(`/evidence${consulta({ incident_id: incidenteId })}`),
  });

  const podeCarregar = pode("evidence:upload");

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.length === 0) {
    return (
      <>
        {podeCarregar ? <CarregarEvidencia incidenteId={incidenteId} /> : null}
        <Vazio
          titulo="Sem evidências"
          detalhe="As evidências carregadas são registadas com SHA-256, o que permite demonstrar mais tarde que não foram alteradas."
        />
      </>
    );
  }

  return (
    <div className="tabela-envolvente">
      {podeCarregar ? <CarregarEvidencia incidenteId={incidenteId} /> : null}
      {erroDeDescarga ? <Erro erro={erroDeDescarga} /> : null}
      <table className="tabela">
        <thead>
          <tr>
            <th>Nome</th>
            <th>Tipo</th>
            <th>Ficheiro</th>
            <th>Tamanho</th>
            <th>SHA-256</th>
            <th>Recolhida por</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.map((evidencia) => (
            <tr key={evidencia.id}>
              <td>{evidencia.name}</td>
              <td className="secundario">{legivel(evidencia.evidence_type)}</td>
              <td className="secundario mono">{evidencia.original_filename}</td>
              <td className="secundario mono">{tamanhoDeFicheiro(evidencia.size_bytes)}</td>
              <td
                className="terciario mono truncar"
                style={{ maxWidth: "16ch" }}
                title={evidencia.sha256}
              >
                {evidencia.sha256}
              </td>
              <td className="secundario">{evidencia.uploaded_by?.nome ?? "—"}</td>
              <td>
                {/*
                  Botão e não `<a href>`: o token de acesso vive em memória e
                  uma navegação do navegador não leva o cabeçalho
                  `Authorization`, pelo que a descarga daria 401.
                */}
                <button
                  className="botao botao--pequeno"
                  onClick={() => {
                    definirErroDeDescarga(null);
                    descarregar(
                      `/evidence/${evidencia.id}/download`,
                      evidencia.original_filename,
                    ).catch(definirErroDeDescarga);
                  }}
                >
                  Descarregar
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Accoes({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["accoes", incidenteId],
    queryFn: () =>
      pedir<Pagina<Accao>>(`/actions${consulta({ incident_id: incidenteId, size: 50 })}`),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.total === 0) {
    return (
      <Vazio
        titulo="Sem acções de resposta"
        detalhe="Acções disruptivas exigem aprovação de outra pessoa que não quem as propôs."
      />
    );
  }

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      {data.itens.map((accao) => (
        <div key={accao.id} className="cartao" style={{ padding: "var(--espaco-4)" }}>
          <div className="linha linha--espalhada">
            <div className="pilha" style={{ gap: 2 }}>
              <div className="linha" style={{ gap: "var(--espaco-2)" }}>
                <span className="mono terciario">{accao.reference}</span>
                <strong>{accao.title}</strong>
              </div>
              <span className="terciario">
                {legivel(accao.action_kind)} · risco {legivel(accao.risk_level)} ·
                proposta por {accao.proposed_by?.nome ?? "—"}
              </span>
            </div>
            <span className="distintivo distintivo--neutro">{legivel(accao.status)}</span>
          </div>

          <p className="secundario" style={{ marginTop: "var(--espaco-3)" }}>
            {accao.rationale}
          </p>

          {/* §4: se não é executável, a interface diz porquê em vez de deixar
              um botão que falharia em silêncio. */}
          {!accao.executavel && accao.motivo_nao_executavel ? (
            <div className="mensagem mensagem--aviso" style={{ marginTop: "var(--espaco-3)" }}>
              Não executável: {accao.motivo_nao_executavel}
            </div>
          ) : null}

          {accao.approvals.length > 0 ? (
            <div className="pilha" style={{ gap: 2, marginTop: "var(--espaco-3)" }}>
              {accao.approvals.map((aprovacao) => (
                <span key={aprovacao.id} className="terciario">
                  {legivel(aprovacao.decision)}
                  {aprovacao.decided_by ? ` por ${aprovacao.decided_by.nome}` : ""}
                  {aprovacao.decided_at ? ` · ${instante(aprovacao.decided_at)}` : ""}
                  {aprovacao.justification ? ` · «${aprovacao.justification}»` : ""}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function GrafoDoIncidente({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["grafo", incidenteId],
    queryFn: () => pedir<Grafo>(`/graph/incident/${incidenteId}`),
  });

  if (isPending) return <Carregando texto="A construir o grafo…" />;
  if (error) return <Erro erro={error} />;
  return <GrafoInvestigativo grafo={data} />;
}

function Tecnicas({ incidente }: { incidente: Incidente }) {
  const tecnicas = incidente.tecnicas ?? [];
  if (tecnicas.length === 0) {
    return (
      <Vazio
        titulo="Sem técnicas associadas"
        detalhe="As técnicas declaradas pela fonte entram como afirmadas; as que o motor deduz entram como inferidas, e só depois de alguém as aceitar."
      />
    );
  }

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      {tecnicas.map((associacao) => (
        <div key={associacao.id} className="cartao" style={{ padding: "var(--espaco-4)" }}>
          <div className="linha linha--espalhada">
            <div className="linha" style={{ gap: "var(--espaco-3)" }}>
              <span className="mono" style={{ fontWeight: 700 }}>
                {associacao.technique.technique_id}
              </span>
              <span>{associacao.technique.name}</span>
            </div>
            <span
              className={`distintivo ${
                associacao.is_asserted ? "distintivo--sucesso" : "distintivo--aviso"
              }`}
              title={
                associacao.is_asserted
                  ? "Facto: declarado pela fonte ou afirmado por um analista."
                  : "Hipótese do motor, aceite por decisão humana. Não é um facto confirmado."
              }
            >
              {associacao.is_asserted ? "afirmada" : "inferida"}
            </span>
          </div>
          <p className="secundario" style={{ marginTop: "var(--espaco-2)" }}>
            {associacao.rationale}
          </p>
          <p className="terciario" style={{ marginTop: "var(--espaco-1)" }}>
            Confiança: {legivel(associacao.confidence)}
            {associacao.technique.tactic_shortnames.length > 0
              ? ` · tácticas: ${associacao.technique.tactic_shortnames.join(", ")}`
              : ""}
          </p>
        </div>
      ))}
    </div>
  );
}

export function IncidenteDetalhe() {
  const { id = "" } = useParams();
  const [aba, definirAba] = useState<Aba>("visao");

  const { data, isPending, error } = useQuery({
    queryKey: ["incidente", id],
    queryFn: () => pedir<Incidente>(`/incidents/${id}`),
    enabled: id !== "",
  });

  if (isPending) return <Carregando />;
  if (error) {
    if (error instanceof ErroDaApi && error.estado === 404) {
      return (
        <Vazio
          titulo="Incidente não encontrado"
          detalhe="A referência pode ter sido removida ou o endereço estar errado."
          accao={
            <Link to="/incidentes" className="botao">
              Voltar à lista
            </Link>
          }
        />
      );
    }
    return <Erro erro={error} />;
  }

  const m = data.metricas;

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <div className="linha" style={{ gap: "var(--espaco-3)" }}>
            <span className="mono terciario" style={{ fontSize: "var(--texto-md)" }}>
              {data.reference}
            </span>
            <DistintivoDeSeveridade valor={data.severity} />
            <DistintivoDeEstado valor={data.status} />
            {data.is_demo_data ? <MarcaDeDemonstracao /> : null}
          </div>
          <h1>{data.title}</h1>
          <p className="pagina__descricao">
            Detectado em {instante(data.detected_at)} · origem {legivel(data.origin)}
            {data.source_detail ? ` · ${data.source_detail}` : ""}
          </p>
        </div>
      </div>

      <div className="separadores" role="tablist">
        {ABAS.map((entrada) => (
          <button
            key={entrada.chave}
            type="button"
            role="tab"
            aria-selected={aba === entrada.chave}
            className={`separador${aba === entrada.chave ? " separador--activo" : ""}`}
            onClick={() => definirAba(entrada.chave)}
          >
            {entrada.rotulo}
            {entrada.chave === "alertas" && m.alertas_associados > 0 ? (
              <span className="separador__contador">{m.alertas_associados}</span>
            ) : null}
            {entrada.chave === "observacoes" && m.observacoes > 0 ? (
              <span className="separador__contador">{m.observacoes}</span>
            ) : null}
            {entrada.chave === "evidencias" && m.evidencias > 0 ? (
              <span className="separador__contador">{m.evidencias}</span>
            ) : null}
            {entrada.chave === "tecnicas" && (data.tecnicas?.length ?? 0) > 0 ? (
              <span className="separador__contador">{data.tecnicas?.length}</span>
            ) : null}
          </button>
        ))}
      </div>

      <div className="detalhe">
        <div className="pilha" style={{ gap: "var(--espaco-5)" }}>
          {aba === "visao" ? (
            <>
              {data.description ? (
                <div className="cartao">
                  <h3 style={{ marginBottom: "var(--espaco-3)" }}>Descrição</h3>
                  <p style={{ whiteSpace: "pre-wrap" }}>{data.description}</p>
                </div>
              ) : null}

              {data.resolution_summary ? (
                <div className="cartao">
                  <h3 style={{ marginBottom: "var(--espaco-3)" }}>Resolução</h3>
                  <p style={{ whiteSpace: "pre-wrap" }}>{data.resolution_summary}</p>
                </div>
              ) : null}

              {data.false_positive_reason ? (
                <div className="cartao">
                  <h3 style={{ marginBottom: "var(--espaco-3)" }}>
                    Motivo do falso positivo
                  </h3>
                  <p style={{ whiteSpace: "pre-wrap" }}>{data.false_positive_reason}</p>
                </div>
              ) : null}

              {data.lessons_learned ? (
                <div className="cartao">
                  <h3 style={{ marginBottom: "var(--espaco-3)" }}>Lições aprendidas</h3>
                  <p style={{ whiteSpace: "pre-wrap" }}>{data.lessons_learned}</p>
                </div>
              ) : null}

              <div className="cartao">
                <h3 style={{ marginBottom: "var(--espaco-3)" }}>Comentários</h3>
                <Comentarios incidenteId={data.id} />
              </div>
            </>
          ) : null}

          {aba === "linha" ? (
            <div className="cartao">
              <LinhaTemporal incidenteId={data.id} />
            </div>
          ) : null}
          {aba === "alertas" ? <AlertasDoIncidente incidenteId={data.id} /> : null}
          {aba === "observacoes" ? <Observacoes incidenteId={data.id} /> : null}
          {aba === "evidencias" ? <Evidencias incidenteId={data.id} /> : null}
          {aba === "accoes" ? <Accoes incidenteId={data.id} /> : null}
          {aba === "tecnicas" ? <Tecnicas incidente={data} /> : null}
          {aba === "grafo" ? (
            <div className="cartao">
              <GrafoDoIncidente incidenteId={data.id} />
            </div>
          ) : null}
        </div>

        <aside className="pilha" style={{ gap: "var(--espaco-4)" }}>
          <div className="cartao">
            <h3 style={{ marginBottom: "var(--espaco-4)" }}>Estado</h3>
            <Transicoes incidente={data} />
          </div>

          <div className="cartao">
            <h3 style={{ marginBottom: "var(--espaco-4)" }}>Responsável</h3>
            <Atribuicao incidente={data} />
          </div>

          <div className="cartao">
            <h3 style={{ marginBottom: "var(--espaco-4)" }}>Classificação</h3>
            <div className="propriedades">
              <Propriedade rotulo="Categoria">{legivel(data.category)}</Propriedade>
              <Propriedade rotulo="Prioridade">{data.priority}</Propriedade>
              <Propriedade rotulo="Confiança">{legivel(data.confidence)}</Propriedade>
              <Propriedade rotulo="Responsável">
                {data.assignee?.nome ?? <span className="terciario">Sem responsável</span>}
              </Propriedade>
              <Propriedade rotulo="Reportado por">
                {data.reporter?.nome ?? "—"}
              </Propriedade>
            </div>
          </div>

          <div className="cartao">
            <h3 style={{ marginBottom: "var(--espaco-4)" }}>Tempos de resposta</h3>
            <div className="propriedades">
              <Propriedade rotulo="Até reconhecimento">
                {duracao(m.tempo_ate_reconhecimento_segundos)}
              </Propriedade>
              <Propriedade rotulo="Até contenção">
                {duracao(m.tempo_ate_contencao_segundos)}
              </Propriedade>
              <Propriedade rotulo="Até resolução">
                {duracao(m.tempo_ate_resolucao_segundos)}
              </Propriedade>
              <Propriedade rotulo="Dentro do prazo">
                {m.dentro_do_prazo === null ? (
                  <span className="terciario">Sem prazo definido</span>
                ) : m.dentro_do_prazo ? (
                  <span style={{ color: "var(--sucesso)" }}>Sim</span>
                ) : (
                  <span style={{ color: "var(--critico)" }}>Não</span>
                )}
              </Propriedade>
            </div>
          </div>

          <div className="cartao">
            <h3 style={{ marginBottom: "var(--espaco-4)" }}>Marcos</h3>
            <div className="propriedades">
              <Propriedade rotulo="Detectado">{instante(data.detected_at)}</Propriedade>
              <Propriedade rotulo="Reconhecido">{instante(data.acknowledged_at)}</Propriedade>
              <Propriedade rotulo="Contido">{instante(data.contained_at)}</Propriedade>
              <Propriedade rotulo="Erradicado">{instante(data.eradicated_at)}</Propriedade>
              <Propriedade rotulo="Resolvido">{instante(data.resolved_at)}</Propriedade>
              <Propriedade rotulo="Encerrado">{instante(data.closed_at)}</Propriedade>
            </div>
          </div>
        </aside>
      </div>
    </>
  );
}
