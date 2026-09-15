/**
 * Triagem de um alerta: o gesto central da plataforma.
 *
 * É aqui que se decide se um sinal de detecção se torna uma ocorrência que a
 * organização vai investigar. A separação alerta/incidente só tem valor se a
 * passagem de um ao outro for uma **decisão registada** — com autor, instante e
 * justificação — e não um automatismo. Este painel é a forma humana de a tomar.
 *
 * Três desfechos, que são os do próprio modelo:
 *
 * - **Promover** — o alerta origina um incidente novo;
 * - **Ligar** — junta-se a um incidente que já existe, porque é a mesma
 *   actividade;
 * - **Descartar / falso positivo** — não merece investigação, e essa decisão
 *   alimenta o histórico que o motor usa para estimar o ruído de cada regra.
 *
 * Os estados oferecidos vêm de `transicoes_permitidas`, que a API calcula a
 * partir do ciclo de vida. Reimplementar essas regras aqui daria duas versões
 * da mesma verdade.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Alerta, Incidente, Pagina } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro } from "@/componentes/comuns";
import { CATEGORIAS, SEVERIDADES } from "@/componentes/listagem";

type Modo = null | "promover" | "ligar" | "descartar";

const ROTULO_DO_ESTADO: Record<string, string> = {
  EM_TRIAGEM: "Marcar em triagem",
  DESCARTADO: "Descartar",
  FALSO_POSITIVO: "Marcar falso positivo",
  DUPLICADO: "Marcar duplicado",
};

export function TriagemDeAlerta({ alertaId }: { alertaId: string }) {
  const clienteDeDados = useQueryClient();
  const navegar = useNavigate();
  const { pode } = useSessao();
  const [modo, definirModo] = useState<Modo>(null);

  // Campos da promoção.
  const [titulo, definirTitulo] = useState("");
  const [categoria, definirCategoria] = useState("");
  const [severidade, definirSeveridade] = useState("");
  const [justificacao, definirJustificacao] = useState("");
  // Campos da ligação e do descarte.
  const [incidenteAlvo, definirIncidenteAlvo] = useState("");
  const [estadoAlvo, definirEstadoAlvo] = useState("");

  const alerta = useQuery({
    queryKey: ["alerta", alertaId],
    queryFn: () => pedir<Alerta>(`/alerts/${alertaId}`),
  });

  // Só carrega a lista de incidentes quando o analista escolhe ligar.
  const incidentes = useQuery({
    queryKey: ["incidentes-ligaveis"],
    queryFn: () =>
      pedir<Pagina<Incidente>>(
        `/incidents${consulta({ apenas_activos: true, size: 50, sort: "-detected_at" })}`,
      ),
    enabled: modo === "ligar",
  });

  const invalidar = async () => {
    await clienteDeDados.invalidateQueries({ queryKey: ["alertas"] });
    await clienteDeDados.invalidateQueries({ queryKey: ["alerta", alertaId] });
  };

  const promover = useMutation({
    mutationFn: () =>
      pedir<Incidente>(`/alerts/${alertaId}/promote`, {
        metodo: "POST",
        corpo: {
          ...(titulo.trim() ? { title: titulo.trim() } : {}),
          ...(categoria ? { category: categoria } : {}),
          ...(severidade ? { severity: severidade } : {}),
          rationale: justificacao,
        },
      }),
    onSuccess: async (incidente) => {
      await invalidar();
      // Levar o analista ao incidente que acabou de criar é o passo seguinte
      // natural: ele promoveu para investigar, não para voltar à fila.
      navegar(`/incidentes/${incidente.id}`);
    },
  });

  const ligar = useMutation({
    mutationFn: () =>
      pedir(`/alerts/${alertaId}/link`, {
        metodo: "POST",
        corpo: { incident_id: incidenteAlvo, rationale: justificacao },
      }),
    onSuccess: async () => {
      await invalidar();
      navegar(`/incidentes/${incidenteAlvo}`);
    },
  });

  const triar = useMutation({
    mutationFn: () =>
      pedir(`/alerts/${alertaId}/triage`, {
        metodo: "POST",
        corpo: {
          status: estadoAlvo,
          ...(justificacao.trim() ? { note: justificacao.trim() } : {}),
        },
      }),
    onSuccess: async () => {
      await invalidar();
      definirModo(null);
      definirJustificacao("");
    },
  });

  const recalcular = useMutation({
    mutationFn: () => pedir(`/alerts/${alertaId}/rescore`, { metodo: "POST" }),
    onSuccess: invalidar,
  });

  if (alerta.isPending) return <Carregando />;
  if (alerta.error) return <Erro erro={alerta.error} />;
  if (!alerta.data) return null;

  const a = alerta.data;
  const podePromover = pode("alerts:promote");
  const podeTriar = pode("alerts:triage");

  // Estados de triagem "negativos": os que não passam por incidente.
  const estadosDeDescarte = a.transicoes_permitidas.filter((e) =>
    ["DESCARTADO", "FALSO_POSITIVO", "DUPLICADO", "EM_TRIAGEM"].includes(e),
  );

  if (a.incident_id) {
    return (
      <div className="mensagem mensagem--info">
        Este alerta já pertence ao incidente{" "}
        <a href={`/incidentes/${a.incident_id}`} className="mono">
          {a.incident_reference ?? "—"}
        </a>
        .
      </div>
    );
  }

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="linha" style={{ flexWrap: "wrap", gap: "var(--espaco-2)" }}>
        {podePromover ? (
          <button
            type="button"
            className={`botao botao--pequeno${modo === "promover" ? " botao--primario" : ""}`}
            onClick={() => definirModo(modo === "promover" ? null : "promover")}
          >
            Promover a incidente
          </button>
        ) : null}
        {podePromover ? (
          <button
            type="button"
            className={`botao botao--pequeno${modo === "ligar" ? " botao--primario" : ""}`}
            onClick={() => definirModo(modo === "ligar" ? null : "ligar")}
          >
            Ligar a incidente
          </button>
        ) : null}
        {podeTriar && estadosDeDescarte.length > 0 ? (
          <button
            type="button"
            className={`botao botao--pequeno${modo === "descartar" ? " botao--primario" : ""}`}
            onClick={() => {
              definirModo(modo === "descartar" ? null : "descartar");
              definirEstadoAlvo(estadosDeDescarte[0] ?? "");
            }}
          >
            Triar sem incidente
          </button>
        ) : null}
        {podeTriar ? (
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            disabled={recalcular.isPending}
            onClick={() => recalcular.mutate()}
            title="Reexecuta o motor determinístico com o contexto actual (activos registados, reputação de indicadores, histórico da regra)."
          >
            {recalcular.isPending ? "A recalcular…" : "Recalcular pontuação"}
          </button>
        ) : null}
      </div>

      {recalcular.error ? <Erro erro={recalcular.error} /> : null}

      {modo === "promover" ? (
        <form
          className="pilha"
          style={{ gap: "var(--espaco-3)" }}
          onSubmit={(e) => {
            e.preventDefault();
            promover.mutate();
          }}
        >
          <label className="campo">
            <span className="campo__etiqueta">Título do incidente</span>
            <input
              type="text"
              value={titulo}
              maxLength={300}
              placeholder={a.title}
              onChange={(e) => definirTitulo(e.target.value)}
            />
            <span className="campo__ajuda">
              Em branco, usa o título do alerta.
            </span>
          </label>

          <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
            <label className="campo">
              <span className="campo__etiqueta">Categoria</span>
              <select
                className="selector"
                value={categoria}
                onChange={(e) => definirCategoria(e.target.value)}
              >
                <option value="">— inferir dos grupos de regra —</option>
                {CATEGORIAS.map((c) => (
                  <option key={c.valor} value={c.valor}>
                    {c.rotulo}
                  </option>
                ))}
              </select>
            </label>
            <label className="campo">
              <span className="campo__etiqueta">Severidade</span>
              <select
                className="selector"
                value={severidade}
                onChange={(e) => definirSeveridade(e.target.value)}
              >
                <option value="">— manter {a.severity} —</option>
                {SEVERIDADES.map((s) => (
                  <option key={s.valor} value={s.valor}>
                    {s.rotulo}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="campo">
            <span className="campo__etiqueta">Justificação</span>
            <textarea
              className="area-texto"
              value={justificacao}
              maxLength={2000}
              placeholder="Porque é que este alerta merece investigação."
              onChange={(e) => definirJustificacao(e.target.value)}
            />
            <span className="campo__ajuda">
              Fica no registo de auditoria e no relatório do incidente.
            </span>
          </label>

          {promover.error ? <Erro erro={promover.error} /> : null}
          <div className="linha">
            <button className="botao botao--primario botao--pequeno" disabled={promover.isPending}>
              {promover.isPending ? "A promover…" : "Criar incidente"}
            </button>
            <button
              type="button"
              className="botao botao--discreto botao--pequeno"
              onClick={() => definirModo(null)}
            >
              Cancelar
            </button>
          </div>
        </form>
      ) : null}

      {modo === "ligar" ? (
        <form
          className="pilha"
          style={{ gap: "var(--espaco-3)" }}
          onSubmit={(e) => {
            e.preventDefault();
            ligar.mutate();
          }}
        >
          <label className="campo">
            <span className="campo__etiqueta">Incidente</span>
            <select
              className="selector"
              required
              value={incidenteAlvo}
              onChange={(e) => definirIncidenteAlvo(e.target.value)}
            >
              <option value="">— escolher —</option>
              {incidentes.data?.itens.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.reference} · {i.title.slice(0, 60)}
                </option>
              ))}
            </select>
            <span className="campo__ajuda">
              Só incidentes activos. Ligar materializa as observações do alerta
              no incidente escolhido.
            </span>
          </label>
          {incidentes.isPending && modo === "ligar" ? <Carregando /> : null}
          {incidentes.error ? <Erro erro={incidentes.error} /> : null}

          <label className="campo">
            <span className="campo__etiqueta">Justificação</span>
            <textarea
              className="area-texto"
              value={justificacao}
              maxLength={2000}
              placeholder="Porque é que é a mesma actividade."
              onChange={(e) => definirJustificacao(e.target.value)}
            />
          </label>

          {ligar.error ? <Erro erro={ligar.error} /> : null}
          <div className="linha">
            <button
              className="botao botao--primario botao--pequeno"
              disabled={ligar.isPending || !incidenteAlvo}
            >
              {ligar.isPending ? "A ligar…" : "Ligar ao incidente"}
            </button>
            <button
              type="button"
              className="botao botao--discreto botao--pequeno"
              onClick={() => definirModo(null)}
            >
              Cancelar
            </button>
          </div>
        </form>
      ) : null}

      {modo === "descartar" ? (
        <form
          className="pilha"
          style={{ gap: "var(--espaco-3)" }}
          onSubmit={(e) => {
            e.preventDefault();
            triar.mutate();
          }}
        >
          <label className="campo">
            <span className="campo__etiqueta">Decisão</span>
            <select
              className="selector"
              value={estadoAlvo}
              onChange={(e) => definirEstadoAlvo(e.target.value)}
            >
              {estadosDeDescarte.map((e) => (
                <option key={e} value={e}>
                  {ROTULO_DO_ESTADO[e] ?? e}
                </option>
              ))}
            </select>
            <span className="campo__ajuda">
              Marcar como falso positivo alimenta o histórico que o motor usa
              para estimar o ruído desta regra.
            </span>
          </label>

          <label className="campo">
            <span className="campo__etiqueta">Nota</span>
            <textarea
              className="area-texto"
              value={justificacao}
              maxLength={2000}
              onChange={(e) => definirJustificacao(e.target.value)}
            />
          </label>

          {triar.error ? <Erro erro={triar.error} /> : null}
          <div className="linha">
            <button className="botao botao--primario botao--pequeno" disabled={triar.isPending}>
              {triar.isPending ? "A registar…" : "Registar decisão"}
            </button>
            <button
              type="button"
              className="botao botao--discreto botao--pequeno"
              onClick={() => definirModo(null)}
            >
              Cancelar
            </button>
          </div>
        </form>
      ) : null}
    </div>
  );
}
