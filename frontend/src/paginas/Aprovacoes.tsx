/**
 * Fila de aprovação de acções de resposta (§4.5 · §32 do briefing).
 *
 * A regra que esta página serve é a mais importante do ponto de vista de
 * governo: **quem propõe não aprova**. A interface não a implementa — quem a
 * implementa é o servidor, que compara o proponente com o decisor e recusa com
 * 403 — mas mostra-a: o proponente aparece sempre, e quando a conta que está a
 * ver é a mesma que propôs, a interface di-lo em vez de oferecer um botão que
 * daria erro.
 *
 * Acções críticas exigem justificação escrita. O campo é obrigatório no
 * formulário porque o servidor recusa sem ele, e porque é esse texto que fica
 * na auditoria a explicar a decisão.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Accao, Pagina } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";
import { Paginacao, useFiltros } from "@/componentes/listagem";

const ASPECTO_DO_RISCO: Record<string, string> = {
  BAIXO: "distintivo--sucesso",
  MODERADO: "distintivo--aviso",
  CRITICO: "distintivo--perigo",
};

function Cartao({ accao }: { accao: Accao }) {
  const clienteDeDados = useQueryClient();
  const { utilizador, podeAlguma } = useSessao();
  const [justificacao, definirJustificacao] = useState("");

  const critica = accao.risk_level === "CRITICO";
  const proprio = accao.proposed_by?.id === utilizador?.id;
  const podeDecidir = podeAlguma("actions:approve", "actions:approve_critical");

  const pendente = accao.approvals.find((a) => a.decision === "PENDENTE");

  const decidir = useMutation({
    mutationFn: (aprovado: boolean) =>
      pedir(`/approvals/${accao.id}/decide`, {
        metodo: "POST",
        corpo: {
          approved: aprovado,
          justification: justificacao || null,
        },
      }),
    onSuccess: () => clienteDeDados.invalidateQueries({ queryKey: ["aprovacoes"] }),
  });

  return (
    <div className="cartao pilha">
      <div className="linha linha--espalhada">
        <div className="pilha" style={{ gap: 2 }}>
          <div className="linha" style={{ gap: "var(--espaco-2)" }}>
            <span className="mono terciario">{accao.reference}</span>
            <span className={`distintivo ${ASPECTO_DO_RISCO[accao.risk_level] ?? "distintivo--neutro"}`}>
              risco {accao.risk_level.toLowerCase()}
            </span>
            <span className="distintivo distintivo--neutro">{legivel(accao.status)}</span>
          </div>
          <strong>{accao.title}</strong>
          <span className="terciario">
            {legivel(accao.action_kind)} · proposta por{" "}
            {accao.proposed_by?.nome ?? "—"}
            {pendente ? ` · ${instante(pendente.requested_at)}` : ""}
          </span>
        </div>
        <Link to={`/incidentes/${accao.incident_id}`} className="botao botao--pequeno">
          Ver incidente
        </Link>
      </div>

      <p className="secundario">{accao.rationale}</p>

      {Object.keys(accao.target).length > 0 ? (
        <p className="terciario mono">
          Alvo: {JSON.stringify(accao.target)}
        </p>
      ) : null}

      {!accao.executavel && accao.motivo_nao_executavel ? (
        <div className="mensagem mensagem--aviso">
          <div className="pilha" style={{ gap: 2 }}>
            <strong>Aprovar não a torna executável</strong>
            <span>{accao.motivo_nao_executavel}</span>
          </div>
        </div>
      ) : null}

      {pendente ? (
        proprio ? (
          <div className="mensagem mensagem--info">
            Propôs esta acção, pelo que não a pode aprovar. A decisão cabe a
            outra pessoa — é a separação de funções.
          </div>
        ) : !podeDecidir ? (
          <p className="terciario">
            Aguarda decisão de quem tenha <code>{pendente.required_permission}</code>.
          </p>
        ) : (
          <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
            <div className="campo">
              <label className="campo__etiqueta">
                Justificação {critica ? "(obrigatória para acções críticas)" : "(opcional)"}
              </label>
              <textarea
                className="area-texto"
                style={{ minHeight: "64px" }}
                value={justificacao}
                onChange={(e) => definirJustificacao(e.target.value)}
                placeholder="Porque é que aprova ou recusa. Fica na auditoria."
              />
            </div>
            {decidir.error ? <Erro erro={decidir.error} /> : null}
            <div className="linha">
              <button
                type="button"
                className="botao botao--primario botao--pequeno"
                disabled={decidir.isPending || (critica && justificacao.trim() === "")}
                onClick={() => decidir.mutate(true)}
              >
                Aprovar
              </button>
              <button
                type="button"
                className="botao botao--perigo botao--pequeno"
                disabled={decidir.isPending || (critica && justificacao.trim() === "")}
                onClick={() => decidir.mutate(false)}
              >
                Rejeitar
              </button>
            </div>
          </div>
        )
      ) : (
        <div className="pilha" style={{ gap: 2 }}>
          {accao.approvals.map((aprovacao) => (
            <span key={aprovacao.id} className="terciario">
              {legivel(aprovacao.decision)}
              {aprovacao.decided_by ? ` por ${aprovacao.decided_by.nome}` : ""}
              {aprovacao.decided_at ? ` · ${instante(aprovacao.decided_at)}` : ""}
              {aprovacao.justification ? ` · «${aprovacao.justification}»` : ""}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function Aprovacoes() {
  const { ler, definir } = useFiltros();

  const apenasPendentes = ler("pendentes", "true") === "true";
  const parametros = {
    apenas_pendentes: apenasPendentes,
    page: ler("page", "1"),
    size: "20",
  };

  const { data, isPending, error } = useQuery({
    queryKey: ["aprovacoes", parametros],
    queryFn: () => pedir<Pagina<Accao>>(`/approvals${consulta(parametros)}`),
  });

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Aprovações</h1>
          <p className="pagina__descricao">
            Acções de resposta que aguardam decisão. Quem propõe não aprova, e
            acções críticas exigem justificação escrita — as duas regras são
            verificadas no servidor, não aqui.
          </p>
        </div>
        <div className="pagina__accoes">
          <button
            type="button"
            className="botao"
            onClick={() => definir({ pendentes: apenasPendentes ? "false" : "true" })}
          >
            {apenasPendentes ? "Mostrar todas" : "Apenas pendentes"}
          </button>
        </div>
      </div>

      {error ? <Erro erro={error} /> : null}

      {isPending ? (
        <Carregando />
      ) : data && data.total === 0 ? (
        <div className="cartao">
          <Vazio
            titulo={apenasPendentes ? "Nada à espera de decisão" : "Sem acções de resposta"}
            detalhe="As acções aparecem aqui quando um analista as propõe a partir de um incidente."
          />
        </div>
      ) : data ? (
        <div className="pilha">
          {data.itens.map((accao) => (
            <Cartao key={accao.id} accao={accao} />
          ))}
          <div className="tabela-envolvente">
            <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
          </div>
        </div>
      ) : null}
    </>
  );
}
