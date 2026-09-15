/**
 * Recomendações do motor determinístico (§12 · §49–§52 do briefing).
 *
 * Esta é a página onde a regra "não apresentar inferências como factos" (§50)
 * se joga toda. Cada recomendação mostra:
 *
 * * a **confiança**, e a decomposição que a produziu, cuja soma confere;
 * * a **alteração proposta**, em texto legível, antes de alguém a aceitar;
 * * o **efeito real** depois de decidir — porque aceitar nem sempre altera
 *   alguma coisa. Pode não haver alteração aplicável, ou quem decide pode não
 *   ter a permissão que a operação exigiria feita à mão. Dizer só "aceite"
 *   deixaria o analista a supor o resto.
 *
 * Rejeitar é tão importante como aceitar: uma proposta recusada não volta a ser
 * levantada, e é isso que impede o motor de discutir com o analista até este
 * desligar a lista.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type {
  DecisaoSobreRecomendacao,
  Pagina,
  Recomendacao,
  TipoDeRecomendacao,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante, Vazio } from "@/componentes/comuns";
import { CampoDeSelecao, Paginacao, useFiltros } from "@/componentes/listagem";

const TIPOS: { valor: TipoDeRecomendacao; rotulo: string }[] = [
  { valor: "TRIAGEM", rotulo: "Triagem" },
  { valor: "CLASSIFICACAO", rotulo: "Classificação" },
  { valor: "PRIORIZACAO", rotulo: "Priorização" },
  { valor: "TECNICA_MITRE", rotulo: "Técnica ATT&CK" },
  { valor: "PLAYBOOK", rotulo: "Playbook" },
  { valor: "FALSO_POSITIVO", rotulo: "Falso positivo" },
  { valor: "PROXIMO_PASSO", rotulo: "Próximo passo" },
  { valor: "CORRELACAO", rotulo: "Correlação" },
];

const ROTULO_DO_TIPO = Object.fromEntries(TIPOS.map((t) => [t.valor, t.rotulo]));

/** Descreve a alteração proposta em português, sem despejar JSON ao analista. */
function descreverProposta(proposta: Record<string, unknown>): string {
  const operacao = proposta["operacao"];
  if (!operacao) return "Sem alteração aplicável automaticamente.";

  switch (operacao) {
    case "ALTERAR_ESTADO_ALERTA":
      return `Passar o alerta de ${proposta["de"]} para ${proposta["para"]}.`;
    case "PROMOVER_ALERTA":
      return `Criar um incidente a partir do alerta, com severidade ${proposta["severidade"]}.`;
    case "TRANSICAO_ESTADO":
      return `Passar o incidente de ${proposta["de"]} para ${proposta["para"]}.`;
    case "ASSOCIAR_TECNICAS": {
      const tecnicas = proposta["tecnicas"];
      const lista = Array.isArray(tecnicas) ? tecnicas.join(", ") : "";
      return `Associar como inferida(s): ${lista}.`;
    }
    case "EXECUTAR_PLAYBOOK":
      return `Executar o playbook «${proposta["playbook"]}».`;
    case "ALTERAR_CAMPOS": {
      const alteracoes = proposta["alteracoes"];
      if (!Array.isArray(alteracoes)) return "Alterar campos do registo.";
      return alteracoes
        .map((a) => {
          const item = a as Record<string, unknown>;
          return `${item["campo"]}: ${item["de"]} → ${item["para"]}`;
        })
        .join(" · ");
    }
    default:
      return String(operacao);
  }
}

function Decomposicao({ recomendacao }: { recomendacao: Recomendacao }) {
  const factores = recomendacao.factors?.factores;
  if (!factores) return null;

  const entradas = Object.entries(factores).sort(
    (a, b) => Math.abs(b[1].pontos) - Math.abs(a[1].pontos),
  );
  const soma = entradas.reduce((total, [, f]) => total + f.pontos, 0);

  return (
    <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
      {entradas.map(([nome, factor]) => (
        <div key={nome} className="linha" style={{ alignItems: "flex-start" }}>
          <span
            className="mono"
            style={{
              width: "46px",
              flex: "none",
              textAlign: "right",
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
          </span>
          <span className="secundario">{factor.razao}</span>
        </div>
      ))}
      <p className="terciario" style={{ paddingLeft: "58px" }}>
        Soma: {soma}
        {soma !== recomendacao.confidence
          ? ` · limitada ao tecto do tipo → ${recomendacao.confidence}`
          : " · é exactamente a confiança apresentada"}
        {" · "}
        motor {recomendacao.engine} v{recomendacao.engine_version}
      </p>
    </div>
  );
}

function Cartao({ recomendacao }: { recomendacao: Recomendacao }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [expandida, definirExpansao] = useState(false);
  const [nota, definirNota] = useState("");
  const [efeito, definirEfeito] = useState<string | null>(null);

  const decidir = useMutation({
    mutationFn: (aceitar: boolean) =>
      pedir<DecisaoSobreRecomendacao>(`/recommendations/${recomendacao.id}/decide`, {
        metodo: "POST",
        corpo: { accept: aceitar, note: nota || null, aplicar_alteracao: true },
      }),
    onSuccess: async (resposta) => {
      // O efeito fica visível: aceitar nem sempre altera alguma coisa, e o
      // analista tem de saber o que aconteceu de facto ao alvo.
      definirEfeito(resposta.efeito);
      await clienteDeDados.invalidateQueries({ queryKey: ["recomendacoes"] });
    },
  });

  const proposta = descreverProposta(recomendacao.proposed_change);
  const semAlteracao = !recomendacao.proposed_change["operacao"];

  return (
    <div className="recomendacao">
      <div className="recomendacao__topo">
        <div className="pilha" style={{ gap: "var(--espaco-1)" }}>
          <div className="linha" style={{ gap: "var(--espaco-2)" }}>
            <span className="distintivo distintivo--neutro">
              {ROTULO_DO_TIPO[recomendacao.kind] ?? recomendacao.kind}
            </span>
            <Link
              to={
                recomendacao.target_type === "incident"
                  ? `/incidentes/${recomendacao.target_id}`
                  : `/alertas`
              }
              className="terciario"
            >
              {recomendacao.target_type === "incident" ? "incidente" : "alerta"} →
            </Link>
          </div>
          <strong>{recomendacao.title}</strong>
        </div>
        <div className="confianca">
          <span
            className="confianca__valor"
            style={{
              color:
                recomendacao.confidence >= 70
                  ? "var(--sev-alta)"
                  : recomendacao.confidence >= 50
                    ? "var(--sev-media)"
                    : "var(--texto-secundario)",
            }}
          >
            {recomendacao.confidence}
          </span>
          <span className="confianca__rotulo">confiança</span>
        </div>
      </div>

      <div className="barra">
        <div
          className="barra__preenchimento"
          style={{ width: `${recomendacao.confidence}%` }}
        />
      </div>

      <p className="secundario">{recomendacao.summary}</p>

      <div
        className="mensagem mensagem--info"
        style={{ fontSize: "var(--texto-sm)" }}
      >
        <div className="pilha" style={{ gap: 2 }}>
          <strong>Alteração proposta</strong>
          <span>{proposta}</span>
        </div>
      </div>

      <button
        type="button"
        className="botao botao--discreto botao--pequeno"
        onClick={() => definirExpansao(!expandida)}
        style={{ alignSelf: "flex-start" }}
      >
        {expandida ? "Esconder" : "Ver"} como se chegou a {recomendacao.confidence}
      </button>

      {expandida ? <Decomposicao recomendacao={recomendacao} /> : null}

      {efeito ? (
        <div className="mensagem mensagem--sucesso">
          <div className="pilha" style={{ gap: 2 }}>
            <strong>Decidida</strong>
            <span>{efeito}</span>
          </div>
        </div>
      ) : recomendacao.status === "PENDENTE" && pode("recommendations:decide") ? (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          <input
            className="entrada"
            placeholder="Nota sobre a decisão (opcional)"
            value={nota}
            onChange={(e) => definirNota(e.target.value)}
          />
          {decidir.error ? <Erro erro={decidir.error} /> : null}
          <div className="linha">
            <button
              type="button"
              className="botao botao--primario botao--pequeno"
              disabled={decidir.isPending}
              onClick={() => decidir.mutate(true)}
            >
              {semAlteracao ? "Concordo" : "Aceitar e aplicar"}
            </button>
            <button
              type="button"
              className="botao botao--pequeno"
              disabled={decidir.isPending}
              onClick={() => decidir.mutate(false)}
            >
              Rejeitar
            </button>
            <span className="terciario">
              {semAlteracao
                ? "Sem alteração aplicável: a acção é do analista."
                : "Rejeitar impede que volte a ser levantada."}
            </span>
          </div>
        </div>
      ) : recomendacao.status !== "PENDENTE" ? (
        <p className="terciario">
          {recomendacao.status.toLowerCase()}
          {recomendacao.decided_by ? ` por ${recomendacao.decided_by.nome}` : ""}
          {recomendacao.decided_at ? ` · ${instante(recomendacao.decided_at)}` : ""}
          {recomendacao.applied ? " · alteração aplicada" : " · sem alteração aplicada"}
        </p>
      ) : null}
    </div>
  );
}

export function Recomendacoes() {
  const { ler, definir } = useFiltros();
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();

  const parametros = {
    estado: ler("estado", "PENDENTE"),
    tipo: ler("tipo"),
    alvo: ler("alvo"),
    page: ler("page", "1"),
    size: "20",
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["recomendacoes", parametros],
    queryFn: () => pedir<Pagina<Recomendacao>>(`/recommendations${consulta(parametros)}`),
  });

  const gerar = useMutation({
    mutationFn: () => pedir("/recommendations/generate", { metodo: "POST" }),
    onSuccess: () => clienteDeDados.invalidateQueries({ queryKey: ["recomendacoes"] }),
  });

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Recomendações</h1>
          <p className="pagina__descricao">
            Propostas do motor determinístico, cada uma com a decomposição que a
            sustenta. Nenhuma é aplicada sem decisão humana, e nenhuma
            recomendação rejeitada volta a ser levantada.
          </p>
        </div>
        {pode("recommendations:decide") ? (
          <div className="pagina__accoes">
            <button
              type="button"
              className="botao"
              disabled={gerar.isPending}
              onClick={() => gerar.mutate()}
            >
              {gerar.isPending ? "A recalcular…" : "Recalcular"}
            </button>
          </div>
        ) : null}
      </div>

      <div className="filtros">
        <CampoDeSelecao
          etiqueta="Estado"
          valor={ler("estado", "PENDENTE")}
          opcoes={[
            { valor: "PENDENTE", rotulo: "Pendentes" },
            { valor: "ACEITE", rotulo: "Aceites" },
            { valor: "REJEITADA", rotulo: "Rejeitadas" },
            { valor: "EXPIRADA", rotulo: "Expiradas" },
          ]}
          aoMudar={(v) => definir({ estado: v || "PENDENTE" })}
          todos="Pendentes"
        />
        <CampoDeSelecao
          etiqueta="Tipo"
          valor={ler("tipo")}
          opcoes={TIPOS.map((t) => ({ valor: t.valor, rotulo: t.rotulo }))}
          aoMudar={(v) => definir({ tipo: v })}
        />
        <CampoDeSelecao
          etiqueta="Alvo"
          valor={ler("alvo")}
          opcoes={[
            { valor: "incident", rotulo: "Incidentes" },
            { valor: "alert", rotulo: "Alertas" },
          ]}
          aoMudar={(v) => definir({ alvo: v })}
        />
        {isFetching ? <span className="carregando" aria-hidden="true" /> : null}
      </div>

      {gerar.error ? <Erro erro={gerar.error} /> : null}
      {error ? <Erro erro={error} /> : null}

      {isPending ? (
        <Carregando />
      ) : data && data.total === 0 ? (
        <div className="cartao">
          <Vazio
            titulo="Sem recomendações pendentes"
            detalhe="O motor só levanta uma recomendação quando tem base para a sustentar. Uma lista vazia significa que não há nada a propor — não que o motor não correu."
            accao={
              pode("recommendations:decide") ? (
                <button
                  type="button"
                  className="botao"
                  onClick={() => gerar.mutate()}
                  disabled={gerar.isPending}
                >
                  Recalcular agora
                </button>
              ) : undefined
            }
          />
        </div>
      ) : data ? (
        <div className="pilha">
          <div className="grelha grelha--2">
            {data.itens.map((recomendacao) => (
              <Cartao key={recomendacao.id} recomendacao={recomendacao} />
            ))}
          </div>
          <div className="tabela-envolvente">
            <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
          </div>
        </div>
      ) : null}
    </>
  );
}
