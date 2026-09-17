/**
 * Eventos brutos (§6) — a camada que fica **debaixo** do alerta.
 *
 * Esta página existe por uma razão que não é de conveniência: é aqui que a
 * distinção entre evento, alerta e incidente deixa de ser uma afirmação da
 * documentação e passa a ser observável. Quatro mil tentativas de força bruta
 * são quatro mil eventos e **um** alerta; sem esta lista, a agregação teria de
 * ser aceite por confiança.
 *
 * O detalhe de cada evento mostra o payload tal como a fonte o enviou. É a
 * resposta concreta à pergunta "como sei que este valor não foi inventado pela
 * plataforma?": qualquer campo normalizado pode ser confrontado, ali mesmo, com
 * o que foi efectivamente recebido (§4).
 *
 * A diferença entre o instante em que o evento *ocorreu* e o instante em que
 * foi *recebido* é mostrada de propósito. Não é ornamento: um desvio grande
 * denuncia relógios dessincronizados entre a fonte e a plataforma — a falha
 * mais silenciosa de toda a cadeia de recolha, porque não produz erro nenhum.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Evento, EventoDetalhado, Pagina } from "@/api/tipos";
import {
  Carregando,
  DistintivoDeSeveridade,
  Erro,
  instante,
  legivel,
  Vazio,
} from "@/componentes/comuns";
import {
  CampoDeSelecao,
  Paginacao,
  SEVERIDADES,
  useFiltros,
} from "@/componentes/listagem";

const FONTES = [
  { valor: "WAZUH", rotulo: "Wazuh" },
  { valor: "SURICATA", rotulo: "Suricata" },
  { valor: "QRADAR", rotulo: "IBM QRadar" },
  { valor: "NETSCOUT", rotulo: "NetScout" },
  { valor: "MANUAL", rotulo: "Registo manual" },
  { valor: "API_GENERICA", rotulo: "API genérica" },
];

const ORDENACOES = [
  { valor: "-occurred_at", rotulo: "Ocorrência (mais recente)" },
  { valor: "occurred_at", rotulo: "Ocorrência (mais antiga)" },
  { valor: "-received_at", rotulo: "Recepção (mais recente)" },
  { valor: "-severity", rotulo: "Severidade" },
];

/** Diferença entre ocorrência e recepção, em linguagem corrente. */
function atraso(ocorreu: string, recebido: string): string {
  const ms = new Date(recebido).getTime() - new Date(ocorreu).getTime();
  if (!Number.isFinite(ms)) return "—";
  const s = Math.round(ms / 1000);
  if (Math.abs(s) < 1) return "imediato";
  if (Math.abs(s) < 60) return `${s}s`;
  if (Math.abs(s) < 3600) return `${Math.round(s / 60)} min`;
  return `${Math.round(s / 3600)} h`;
}

/**
 * O atraso é destacado só quando é grande ou negativo.
 *
 * Negativo significa que a fonte diz ter o evento ocorrido *depois* do instante
 * em que foi recebido, o que é impossível e denuncia relógios desalinhados.
 */
function DistintivoDeAtraso({ evento }: { evento: Evento }) {
  const ms =
    new Date(evento.received_at).getTime() - new Date(evento.occurred_at).getTime();
  const texto = atraso(evento.occurred_at, evento.received_at);
  if (!Number.isFinite(ms)) return <span className="terciario">—</span>;

  if (ms < -1000) {
    return (
      <span
        className="distintivo distintivo--perigo"
        title="A fonte datou o evento depois do instante em que foi recebido. Os relógios não estão alinhados."
      >
        {texto}
      </span>
    );
  }
  if (ms > 15 * 60 * 1000) {
    return (
      <span
        className="distintivo distintivo--aviso"
        title="Demorou mais de 15 minutos a chegar. Pode indicar acumulação na fonte ou desvio de relógio."
      >
        {texto}
      </span>
    );
  }
  return <span className="secundario mono">{texto}</span>;
}

/** Uma linha por campo, mas só para os campos que o evento traz preenchidos. */
function Propriedade({
  rotulo,
  valor,
}: {
  rotulo: string;
  valor: string | number | null;
}) {
  if (valor === null || valor === undefined || valor === "") return null;
  return (
    <div className="propriedade">
      <span className="propriedade__rotulo">{rotulo}</span>
      <span className="propriedade__valor mono">{valor}</span>
    </div>
  );
}

function DetalheDoEvento({ id }: { id: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["evento", id],
    queryFn: () => pedir<EventoDetalhado>(`/events/${id}`),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data) return null;

  const temPayload = Object.keys(data.raw_payload ?? {}).length > 0;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
      <p className="secundario">{data.description}</p>

      <div className="propriedades">
        <Propriedade rotulo="Fonte" valor={data.source_name} />
        <Propriedade rotulo="Tipo de fonte" valor={legivel(data.source_kind)} />
        <Propriedade rotulo="Identificador na fonte" valor={data.source_event_id} />
        <Propriedade rotulo="Tipo de evento" valor={legivel(data.event_type)} />
        <Propriedade rotulo="Ocorreu" valor={instante(data.occurred_at)} />
        <Propriedade rotulo="Recebido" valor={instante(data.received_at)} />
        <Propriedade rotulo="Anfitrião" valor={data.host} />
        <Propriedade rotulo="Origem" valor={data.source_ip} />
        <Propriedade rotulo="Porta de origem" valor={data.source_port} />
        <Propriedade rotulo="Destino" valor={data.destination_ip} />
        <Propriedade rotulo="Porta de destino" valor={data.destination_port} />
        <Propriedade rotulo="Protocolo" valor={data.protocol} />
        <Propriedade rotulo="Utilizador" valor={data.username} />
        <Propriedade rotulo="Processo" valor={data.process} />
        <Propriedade rotulo="Hash do ficheiro" valor={data.file_hash} />
        <Propriedade rotulo="Regra" valor={data.rule_id} />
      </div>

      {data.rule_name ? <p className="terciario">Regra: {data.rule_name}</p> : null}

      {data.rule_groups.length > 0 ? (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          <span className="propriedade__rotulo">Grupos da regra</span>
          <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
            {data.rule_groups.map((g) => (
              <span key={g} className="distintivo distintivo--neutro mono">
                {g}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {data.reported_techniques.length > 0 ? (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
          <span className="propriedade__rotulo">Técnicas indicadas pela fonte</span>
          <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
            {data.reported_techniques.map((t) => (
              <span key={t} className="distintivo distintivo--neutro mono">
                {t}
              </span>
            ))}
          </div>
          <p className="terciario">
            Foram <em>declaradas pela fonte</em>, não inferidas pela plataforma.
          </p>
        </div>
      ) : null}

      <div className="separador" />

      <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
        <strong>Payload original</strong>
        <p className="terciario">
          Tal como a fonte o enviou, sem alteração. Serve de prova de origem:
          qualquer campo acima pode ser confrontado com o que está aqui.
        </p>
        {temPayload ? (
          <pre className="bloco-bruto mono">
            {JSON.stringify(data.raw_payload, null, 2)}
          </pre>
        ) : (
          <p className="secundario">
            Este evento não guardou payload original. Sem ele, os valores acima
            não podem ser confrontados com a fonte.
          </p>
        )}
      </div>

      {data.alert_id ? (
        <p className="secundario">
          Este evento foi agregado num alerta, com todos os outros sinais
          equivalentes. <Link to="/alertas">Ver a fila de alertas</Link>
        </p>
      ) : (
        <p className="terciario">
          Este evento não deu origem a nenhum alerta — foi recebido e
          normalizado, mas não atingiu nenhuma condição de agregação.
        </p>
      )}
    </div>
  );
}

export function Eventos() {
  const { ler, definir, limpar } = useFiltros();
  const [aberto, definirAberto] = useState<Evento | null>(null);

  const parametros = {
    fonte: ler("fonte"),
    severidade: ler("severidade"),
    ip: ler("ip"),
    host: ler("host"),
    page: ler("page", "1"),
    size: "25",
    sort: ler("sort", "-occurred_at"),
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["eventos", parametros],
    queryFn: () => pedir<Pagina<Evento>>(`/events${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const temFiltros =
    ler("fonte") !== "" ||
    ler("severidade") !== "" ||
    ler("ip") !== "" ||
    ler("host") !== "";

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Eventos</h1>
          <p className="pagina__descricao">
            Os sinais como as fontes os entregaram, antes de serem agregados em
            alertas. Muitos eventos equivalentes convergem num único alerta — é
            aqui que essa agregação se verifica, em vez de ser aceite por
            confiança. Cada evento guarda o payload original que o produziu.
          </p>
        </div>
      </div>

      <div className="filtros">
        <CampoDeSelecao
          etiqueta="Fonte"
          valor={ler("fonte")}
          opcoes={FONTES}
          aoMudar={(v) => definir({ fonte: v })}
        />
        <CampoDeSelecao
          etiqueta="Severidade"
          valor={ler("severidade")}
          opcoes={SEVERIDADES}
          aoMudar={(v) => definir({ severidade: v })}
        />
        <CampoDeSelecao
          etiqueta="Ordenar por"
          valor={ler("sort", "-occurred_at")}
          opcoes={ORDENACOES}
          aoMudar={(v) => definir({ sort: v || "-occurred_at" })}
          todos="—"
        />
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="filtro-ip">
            Endereço IP
          </label>
          <input
            id="filtro-ip"
            type="search"
            placeholder="origem ou destino"
            defaultValue={ler("ip")}
            onBlur={(e) => definir({ ip: e.target.value.trim() })}
            onKeyDown={(e) => {
              if (e.key === "Enter") definir({ ip: e.currentTarget.value.trim() });
            }}
          />
        </div>
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="filtro-host">
            Anfitrião
          </label>
          <input
            id="filtro-host"
            type="search"
            placeholder="nome do equipamento"
            defaultValue={ler("host")}
            onBlur={(e) => definir({ host: e.target.value.trim() })}
            onKeyDown={(e) => {
              if (e.key === "Enter") definir({ host: e.currentTarget.value.trim() });
            }}
          />
        </div>
        {temFiltros ? (
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            onClick={limpar}
          >
            Limpar filtros
          </button>
        ) : null}
      </div>

      {error ? <Erro erro={error} /> : null}
      {isPending ? <Carregando /> : null}
      {isFetching && !isPending ? <p className="terciario">A actualizar…</p> : null}

      {data && data.itens.length === 0 ? (
        <Vazio
          titulo="Nenhum evento"
          detalhe={
            temFiltros
              ? "Nenhum evento corresponde a estes filtros."
              : "Ainda não foi recebido nenhum sinal de nenhuma fonte."
          }
        />
      ) : null}

      {data && data.itens.length > 0 ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Ocorreu</th>
                <th>Atraso</th>
                <th>Fonte</th>
                <th>Tipo</th>
                <th>Severidade</th>
                <th>Anfitrião</th>
                <th>Origem → destino</th>
                <th>Utilizador</th>
                <th>Regra</th>
                <th>Agregado</th>
              </tr>
            </thead>
            <tbody>
              {data.itens.map((evento) => (
                <tr key={evento.id}>
                  <td className="secundario">
                    <button
                      type="button"
                      className="botao botao--discreto botao--pequeno"
                      onClick={() => definirAberto(evento)}
                      title="Ver o payload original"
                    >
                      {instante(evento.occurred_at)}
                    </button>
                  </td>
                  <td>
                    <DistintivoDeAtraso evento={evento} />
                  </td>
                  <td className="secundario">
                    <div className="mono">{evento.source_name}</div>
                    <div className="terciario">{legivel(evento.source_kind)}</div>
                  </td>
                  <td className="secundario">{legivel(evento.event_type)}</td>
                  <td>
                    <DistintivoDeSeveridade valor={evento.severity} />
                    {evento.source_severity ? (
                      <div
                        className="terciario mono"
                        title="Severidade original declarada pela fonte, antes da normalização."
                      >
                        fonte: {evento.source_severity}
                      </div>
                    ) : null}
                  </td>
                  <td className="secundario mono">{evento.host ?? "—"}</td>
                  <td className="secundario mono">
                    {evento.source_ip ?? "—"}
                    {evento.destination_ip ? ` → ${evento.destination_ip}` : ""}
                  </td>
                  <td className="secundario mono">{evento.username ?? "—"}</td>
                  <td className="secundario mono">{evento.rule_id ?? "—"}</td>
                  <td>
                    {evento.alert_id ? (
                      <span className="distintivo distintivo--sucesso">sim</span>
                    ) : (
                      <span
                        className="distintivo distintivo--neutro"
                        title="Recebido e normalizado, mas não atingiu nenhuma condição de agregação."
                      >
                        não
                      </span>
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
          aria-label={`Evento ${aberto.source_event_id}`}
          onClick={() => definirAberto(null)}
        >
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <div
              className="linha linha--espalhada"
              style={{ marginBottom: "var(--espaco-4)" }}
            >
              <div className="pilha" style={{ gap: 0 }}>
                <h2>Evento recebido de {aberto.source_name}</h2>
                <span className="terciario mono">{aberto.source_event_id}</span>
              </div>
              <button
                type="button"
                className="botao botao--discreto"
                onClick={() => definirAberto(null)}
              >
                Fechar
              </button>
            </div>
            <DetalheDoEvento id={aberto.id} />
          </div>
        </div>
      ) : null}
    </>
  );
}
