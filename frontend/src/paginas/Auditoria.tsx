/**
 * Registo de auditoria (§4.5.7 · RF20 · §42 do briefing).
 *
 * Responde a "quem fez o quê e quando", que é a pergunta que o §4.5.7 põe. Duas
 * coisas que esta página torna visíveis e que são o ponto todo do registo:
 *
 * **As tentativas negadas aparecem.** Saber o que alguém tentou fazer sem
 * autorização vale tanto como saber o que fez. O filtro por resultado começa
 * sem restrição precisamente para que uma negação não passe despercebida por
 * estar escondida atrás de um filtro.
 *
 * **As linhas não são editáveis nem apagáveis.** Não por a interface não
 * oferecer os botões — isso seria uma convenção — mas porque o PostgreSQL
 * recusa UPDATE, DELETE e TRUNCATE nesta tabela através de gatilhos. A nota no
 * fim da página diz isso ao utilizador, porque uma garantia que ninguém conhece
 * não tranquiliza ninguém.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { consulta, pedir } from "@/api/cliente";
import type { Pagina } from "@/api/tipos";
import { Carregando, Erro, instante, Vazio } from "@/componentes/comuns";
import {
  ateISO,
  CampoDeSelecao,
  desdeISO,
  FiltroDePeriodo,
  Paginacao,
  useFiltros,
} from "@/componentes/listagem";

interface RegistoDeAuditoria {
  id: string;
  created_at: string;
  actor_email: string | null;
  actor_role: string | null;
  is_system_actor: boolean;
  action: string;
  resource_type: string;
  resource_id: string | null;
  resource_reference: string | null;
  description: string;
  old_value: Record<string, unknown> | null;
  new_value: Record<string, unknown> | null;
  changed_fields: string[];
  origin: string;
  ip_address: string | null;
  outcome: string;
  failure_reason: string | null;
  request_id: string | null;
}

const ASPECTO_DO_RESULTADO: Record<string, string> = {
  SUCESSO: "distintivo--sucesso",
  FALHA: "distintivo--aviso",
  NEGADO: "distintivo--perigo",
  PARCIAL: "distintivo--aviso",
};

function Detalhe({
  registo,
  aoFechar,
}: {
  registo: RegistoDeAuditoria;
  aoFechar: () => void;
}) {
  return (
    <div className="sobreposicao" role="dialog" aria-modal="true" onClick={aoFechar}>
      <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
        <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
          <div className="pilha" style={{ gap: 0 }}>
            <h2>{registo.action}</h2>
            <span className="terciario">{instante(registo.created_at)}</span>
          </div>
          <button type="button" className="botao botao--discreto" onClick={aoFechar}>
            Fechar
          </button>
        </div>

        <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
          <p>{registo.description}</p>

          <div className="propriedades">
            <div className="propriedade">
              <span className="propriedade__rotulo">Quem</span>
              <span className="propriedade__valor">
                {registo.is_system_actor
                  ? "Sistema"
                  : (registo.actor_email ?? "anónimo")}
                {registo.actor_role ? ` · ${registo.actor_role}` : ""}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Recurso</span>
              <span className="propriedade__valor">
                {registo.resource_type}
                {registo.resource_reference ? ` · ${registo.resource_reference}` : ""}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Origem</span>
              <span className="propriedade__valor">
                {registo.origin}
                {registo.ip_address ? ` · ${registo.ip_address}` : ""}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Resultado</span>
              <span className="propriedade__valor">{registo.outcome}</span>
            </div>
            {registo.failure_reason ? (
              <div className="propriedade">
                <span className="propriedade__rotulo">Motivo</span>
                <span className="propriedade__valor">{registo.failure_reason}</span>
              </div>
            ) : null}
            {registo.request_id ? (
              <div className="propriedade">
                <span className="propriedade__rotulo">Identificador do pedido</span>
                <span className="propriedade__valor mono">{registo.request_id}</span>
              </div>
            ) : null}
          </div>

          {registo.changed_fields.length > 0 ? (
            <div>
              <h3 style={{ marginBottom: "var(--espaco-2)" }}>
                Valor anterior e novo
              </h3>
              <div className="tabela-envolvente">
                <table className="tabela">
                  <thead>
                    <tr>
                      <th>Campo</th>
                      <th>Antes</th>
                      <th>Depois</th>
                    </tr>
                  </thead>
                  <tbody>
                    {registo.changed_fields.map((campo) => (
                      <tr key={campo}>
                        <td className="secundario">{campo}</td>
                        <td className="mono">
                          {String(registo.old_value?.[campo] ?? "—")}
                        </td>
                        <td className="mono">
                          {String(registo.new_value?.[campo] ?? "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function Auditoria() {
  const { ler, definir, limpar } = useFiltros();
  const [aberto, definirAberto] = useState<RegistoDeAuditoria | null>(null);

  const parametros = {
    q: ler("q"),
    resultado: ler("resultado"),
    accao: ler("accao"),
    actor: ler("actor"),
    tipo_recurso: ler("tipo_recurso"),
    // As datas vão em ISO; `ateISO` inclui o dia inteiro, senão um intervalo
    // "até hoje" excluía tudo o que aconteceu hoje.
    desde: desdeISO(ler("desde")),
    ate: ateISO(ler("ate")),
    page: ler("page", "1"),
    size: "30",
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["auditoria", parametros],
    queryFn: () => pedir<Pagina<RegistoDeAuditoria>>(`/audit${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const { data: accoes } = useQuery({
    queryKey: ["accoes-auditadas"],
    queryFn: () => pedir<string[]>("/audit/actions"),
    retry: false,
  });

  // Os tipos vêm do próprio registo. Uma lista fixa no código ofereceria
  // filtros para tipos que já ninguém escreve e faltaria os que aparecerem.
  const { data: tiposDeRecurso } = useQuery({
    queryKey: ["tipos-de-recurso-auditados"],
    queryFn: () => pedir<string[]>("/audit/resource-types"),
    retry: false,
  });

  const temFiltros = [
    "q", "resultado", "accao", "actor", "tipo_recurso", "desde", "ate",
  ].some((c) => ler(c) !== "");

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Auditoria</h1>
          <p className="pagina__descricao">
            Quem fez o quê e quando — incluindo o que foi tentado sem
            autorização, que fica registado como NEGADO.
          </p>
        </div>
      </div>

      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa-auditoria">
            Pesquisa
          </label>
          <input
            id="pesquisa-auditoria"
            className="entrada"
            type="search"
            placeholder="Utilizador, descrição ou referência…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <CampoDeSelecao
          etiqueta="Resultado"
          valor={ler("resultado")}
          opcoes={[
            { valor: "SUCESSO", rotulo: "Sucesso" },
            { valor: "FALHA", rotulo: "Falha" },
            { valor: "NEGADO", rotulo: "Negado" },
          ]}
          aoMudar={(v) => definir({ resultado: v })}
        />
        {accoes && accoes.length > 0 ? (
          <CampoDeSelecao
            etiqueta="Acção"
            valor={ler("accao")}
            opcoes={accoes.map((a) => ({ valor: a, rotulo: a }))}
            aoMudar={(v) => definir({ accao: v })}
          />
        ) : null}
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="filtro-actor">
            Utilizador
          </label>
          <input
            id="filtro-actor"
            className="entrada"
            type="search"
            placeholder="endereço exacto"
            defaultValue={ler("actor")}
            onBlur={(e) => definir({ actor: e.target.value.trim() })}
            onKeyDown={(e) => {
              if (e.key === "Enter") definir({ actor: e.currentTarget.value.trim() });
            }}
          />
        </div>
        {tiposDeRecurso && tiposDeRecurso.length > 0 ? (
          <CampoDeSelecao
            etiqueta="Tipo de recurso"
            valor={ler("tipo_recurso")}
            opcoes={tiposDeRecurso.map((t) => ({ valor: t, rotulo: t }))}
            aoMudar={(v) => definir({ tipo_recurso: v })}
          />
        ) : null}
        <FiltroDePeriodo
          desde={ler("desde")}
          ate={ler("ate")}
          aoMudar={definir}
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
          <Vazio titulo="Nenhum registo corresponde aos filtros" />
        </div>
      ) : data ? (
        <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
          <div className="tabela-envolvente">
            <table className="tabela">
              <thead>
                <tr>
                  <th>Quando</th>
                  <th>Quem</th>
                  <th>Acção</th>
                  <th>Recurso</th>
                  <th>Descrição</th>
                  <th>Resultado</th>
                </tr>
              </thead>
              <tbody>
                {data.itens.map((registo) => (
                  <tr
                    key={registo.id}
                    className="clicavel"
                    onClick={() => definirAberto(registo)}
                  >
                    <td className="secundario">{instante(registo.created_at)}</td>
                    <td className="secundario">
                      {registo.is_system_actor
                        ? "Sistema"
                        : (registo.actor_email ?? "anónimo")}
                    </td>
                    <td className="mono">{registo.action}</td>
                    <td className="secundario">
                      {registo.resource_reference ?? registo.resource_type}
                    </td>
                    <td className="truncar" style={{ maxWidth: "48ch" }}>
                      {registo.description}
                    </td>
                    <td>
                      <span
                        className={`distintivo ${
                          ASPECTO_DO_RESULTADO[registo.outcome] ?? "distintivo--neutro"
                        }`}
                      >
                        {registo.outcome}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
          </div>

          <p className="terciario">
            Este registo é imutável ao nível da base de dados: o PostgreSQL
            recusa UPDATE, DELETE e TRUNCATE sobre esta tabela através de
            gatilhos. Nem esta interface nem a API têm forma de alterar uma
            linha depois de escrita.
          </p>
        </div>
      ) : null}

      {aberto ? (
        <Detalhe registo={aberto} aoFechar={() => definirAberto(null)} />
      ) : null}
    </>
  );
}
