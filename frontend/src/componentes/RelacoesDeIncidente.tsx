/**
 * Relações entre incidentes (§20).
 *
 * É aqui que a plataforma se separa do RTIR. Lá, juntar dois bilhetes é uma
 * **fusão irreversível** que consolida tudo num só e destrói o original; a
 * própria documentação avisa que não pode ser desfeita. Aqui, relacionar cria
 * uma **aresta tipada** e ambos os incidentes continuam a existir, cada um com
 * o seu histórico intacto — um duplicado permanece consultável.
 *
 * A aresta tem direcção e tipo, e ambos importam: `A CAUSADO_POR B` não é o
 * mesmo que `B CAUSADO_POR A`. Por isso a lista mostra de que lado está o
 * incidente que se está a ver.
 *
 * Marcar `DUPLICADO_DE` tem consequência real: o incidente de origem sai da
 * fila operacional, porque passa a estar representado pelo outro.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Incidente, IncidenteResumo, Pagina } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, legivel } from "@/componentes/comuns";

interface Relacao {
  id: string;
  relation_type: string;
  rationale: string;
  created_by_engine: boolean;
  confidence: string;
  created_at: string;
  incident_id: string;
  incident_reference: string;
  incident_title: string;
  incident_status: string;
  /** "saida" quando este incidente é a origem da aresta. */
  direction: string;
}

const TIPOS = [
  { valor: "RELACIONADO_COM", rotulo: "Relacionado com" },
  { valor: "DUPLICADO_DE", rotulo: "É duplicado de" },
  { valor: "CAUSADO_POR", rotulo: "Foi causado por" },
  { valor: "ORIGINOU", rotulo: "Originou" },
  { valor: "PARTE_DE_CAMPANHA", rotulo: "Faz parte da mesma campanha que" },
  { valor: "ESCALADO_DE", rotulo: "Foi escalado de" },
];

const CONFIANCAS = [
  { valor: "BAIXA", rotulo: "Baixa" },
  { valor: "MEDIA", rotulo: "Média" },
  { valor: "ALTA", rotulo: "Alta" },
  { valor: "CONFIRMADA", rotulo: "Confirmada" },
];

export function RelacoesDeIncidente({ incidente }: { incidente: Incidente }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [aberto, definirAberto] = useState(false);
  const [alvo, definirAlvo] = useState("");
  const [tipo, definirTipo] = useState("RELACIONADO_COM");
  const [confianca, definirConfianca] = useState("MEDIA");
  const [justificacao, definirJustificacao] = useState("");
  const [pesquisa, definirPesquisa] = useState("");

  const relacoes = useQuery({
    queryKey: ["relacoes", incidente.id],
    queryFn: () => pedir<Relacao[]>(`/incidents/${incidente.id}/relations`),
  });

  const candidatos = useQuery({
    queryKey: ["incidentes-relacionaveis", pesquisa],
    queryFn: () =>
      pedir<Pagina<IncidenteResumo>>(
        `/incidents${consulta({ q: pesquisa, size: 30, sort: "-detected_at" })}`,
      ),
    enabled: aberto,
  });

  const relacionar = useMutation({
    mutationFn: () =>
      pedir(`/incidents/${incidente.id}/relations`, {
        metodo: "POST",
        corpo: {
          target_incident_id: alvo,
          relation_type: tipo,
          rationale: justificacao,
          confidence: confianca,
        },
      }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["relacoes", incidente.id] });
      await clienteDeDados.invalidateQueries({ queryKey: ["incidente", incidente.id] });
      await clienteDeDados.invalidateQueries({ queryKey: ["grafo", incidente.id] });
      definirAberto(false);
      definirAlvo("");
      definirJustificacao("");
    },
  });

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      {pode("incidents:relate") ? (
        aberto ? (
          <form
            className="cartao pilha"
            style={{ gap: "var(--espaco-3)" }}
            onSubmit={(e) => {
              e.preventDefault();
              relacionar.mutate();
            }}
          >
            <label className="campo">
              <span className="campo__etiqueta">Procurar incidente</span>
              <input
                type="search"
                value={pesquisa}
                placeholder="Referência, título…"
                onChange={(e) => definirPesquisa(e.target.value)}
              />
            </label>

            <label className="campo">
              <span className="campo__etiqueta">Incidente</span>
              <select
                className="selector"
                required
                value={alvo}
                onChange={(e) => definirAlvo(e.target.value)}
              >
                <option value="">— escolher —</option>
                {candidatos.data?.itens
                  .filter((i) => i.id !== incidente.id)
                  .map((i) => (
                    <option key={i.id} value={i.id}>
                      {i.reference} · {i.title.slice(0, 60)}
                    </option>
                  ))}
              </select>
            </label>
            {candidatos.error ? <Erro erro={candidatos.error} /> : null}

            <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
              <label className="campo">
                <span className="campo__etiqueta">Relação</span>
                <select
                  className="selector"
                  value={tipo}
                  onChange={(e) => definirTipo(e.target.value)}
                >
                  {TIPOS.map((t) => (
                    <option key={t.valor} value={t.valor}>
                      {incidente.reference} {t.rotulo.toLowerCase()}…
                    </option>
                  ))}
                </select>
              </label>
              <label className="campo">
                <span className="campo__etiqueta">Confiança</span>
                <select
                  className="selector"
                  value={confianca}
                  onChange={(e) => definirConfianca(e.target.value)}
                >
                  {CONFIANCAS.map((c) => (
                    <option key={c.valor} value={c.valor}>
                      {c.rotulo}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {tipo === "DUPLICADO_DE" ? (
              <div className="mensagem mensagem--aviso">
                Marcar como duplicado retira {incidente.reference} da fila
                operacional. O incidente continua a existir e consultável — não
                é apagado nem fundido.
              </div>
            ) : null}

            <label className="campo">
              <span className="campo__etiqueta">Justificação</span>
              <textarea
                className="area-texto"
                value={justificacao}
                maxLength={2000}
                placeholder="Porque é que estes incidentes estão relacionados."
                onChange={(e) => definirJustificacao(e.target.value)}
              />
            </label>

            {relacionar.error ? <Erro erro={relacionar.error} /> : null}
            <div className="linha" style={{ gap: "var(--espaco-2)" }}>
              <button
                className="botao botao--primario botao--pequeno"
                disabled={relacionar.isPending || !alvo}
              >
                {relacionar.isPending ? "A relacionar…" : "Relacionar"}
              </button>
              <button
                type="button"
                className="botao botao--discreto botao--pequeno"
                onClick={() => definirAberto(false)}
              >
                Cancelar
              </button>
            </div>
          </form>
        ) : (
          <div className="linha">
            <button className="botao botao--pequeno" onClick={() => definirAberto(true)}>
              Relacionar com outro incidente
            </button>
          </div>
        )
      ) : null}

      {relacoes.error ? <Erro erro={relacoes.error} /> : null}
      {relacoes.isPending ? (
        <Carregando />
      ) : !relacoes.data || relacoes.data.length === 0 ? (
        <p className="terciario">
          Sem incidentes relacionados. Relacionar preserva ambos os registos —
          ao contrário de uma fusão, que destruiria um deles.
        </p>
      ) : (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          {relacoes.data.map((r) => (
            <div key={r.id} className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
              <div className="linha linha--espalhada">
                <span className="secundario">
                  {/* A direcção da aresta é apresentada por palavras: sem isso,
                      "causado por" seria ambíguo. */}
                  {r.direction === "saida"
                    ? `${incidente.reference} ${legivel(r.relation_type).toLowerCase()} `
                    : `${r.incident_reference} ${legivel(r.relation_type).toLowerCase()} ${incidente.reference}`}
                  {r.direction === "saida" ? (
                    <Link to={`/incidentes/${r.incident_id}`} className="mono">
                      {r.incident_reference}
                    </Link>
                  ) : null}
                </span>
                <span className="distintivo distintivo--neutro">
                  {legivel(r.incident_status)}
                </span>
              </div>
              {r.direction !== "saida" ? (
                <Link to={`/incidentes/${r.incident_id}`}>{r.incident_title}</Link>
              ) : (
                <span className="secundario">{r.incident_title}</span>
              )}
              {r.rationale ? <p className="terciario">{r.rationale}</p> : null}
              <span className="terciario">
                Confiança {legivel(r.confidence).toLowerCase()}
                {r.created_by_engine ? " · proposta pelo motor" : " · afirmada por um analista"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
