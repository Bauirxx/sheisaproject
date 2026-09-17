/**
 * Centro de operações (§27) — o ecrã do "o que faço agora".
 *
 * Distingue-se do painel de propósito. O painel responde a "como estamos":
 * tempos de resposta, tendências, distribuições. Esta página responde a outra
 * pergunta, que é a do turno a começar: **que trabalho está à espera de
 * alguém**. Por isso mostra itens, não médias — cada linha é uma coisa que se
 * pode abrir e tratar.
 *
 * As sete filas vêm numa única resposta (`GET /soc`), e isso é deliberado: sete
 * pedidos separados chegariam em instantes diferentes, e um ecrã que se compõe
 * aos pedaços leva o analista a agir sobre uma imagem parcial.
 *
 * O prazo é a coluna que manda. Um incidente fora de prazo não é sinalizado por
 * cor apenas: diz-se por palavras há quanto tempo passou, porque a cor sozinha
 * não sobrevive a uma impressão nem a quem não a distinga.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { pedir } from "@/api/cliente";
import type { VistaDoCentroDeOperacoes } from "@/api/tipos";
import {
  Carregando,
  DistintivoDeSeveridade,
  Erro,
  instante,
  legivel,
  Vazio,
} from "@/componentes/comuns";

/** Há quanto tempo o prazo passou, ou quanto falta. */
function prazoLegivel(prazo: string | null): { texto: string; expirado: boolean } | null {
  if (!prazo) return null;
  const ms = new Date(prazo).getTime() - Date.now();
  if (!Number.isFinite(ms)) return null;

  const minutos = Math.round(Math.abs(ms) / 60000);
  const quanto =
    minutos < 60
      ? `${minutos} min`
      : minutos < 1440
        ? `${Math.round(minutos / 60)} h`
        : `${Math.round(minutos / 1440)} d`;

  return ms < 0
    ? { texto: `fora de prazo há ${quanto}`, expirado: true }
    : { texto: `faltam ${quanto}`, expirado: false };
}

function Prazo({ prazo }: { prazo: string | null }) {
  const p = prazoLegivel(prazo);
  if (!p) return <span className="terciario">sem prazo</span>;
  return (
    <span
      className={p.expirado ? "distintivo distintivo--perigo" : "secundario"}
      title={instante(prazo)}
    >
      {p.texto}
    </span>
  );
}

/**
 * Cada fila num cartão próprio, com a sua contagem no título.
 *
 * A contagem aparece mesmo quando é zero: "0 aprovações pendentes" informa,
 * enquanto um cartão ausente deixa a dúvida entre "não há" e "não carregou".
 */
function Fila({
  titulo,
  explicacao,
  quantos,
  verTudo,
  children,
}: {
  titulo: string;
  explicacao: string;
  quantos: number;
  verTudo?: { para: string; rotulo: string };
  children: React.ReactNode;
}) {
  return (
    <section className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="linha linha--espalhada">
        <div className="pilha" style={{ gap: 0 }}>
          <strong>
            {titulo} <span className="mono terciario">({quantos})</span>
          </strong>
          <span className="terciario">{explicacao}</span>
        </div>
        {verTudo ? (
          <Link to={verTudo.para} className="terciario">
            {verTudo.rotulo}
          </Link>
        ) : null}
      </div>
      {quantos === 0 ? (
        <p className="terciario">Nada nesta fila.</p>
      ) : (
        <div className="pilha" style={{ gap: "var(--espaco-2)" }}>{children}</div>
      )}
    </section>
  );
}

/** Uma linha de fila: identificador, descrição e o que decide a prioridade. */
function Linha({
  esquerda,
  titulo,
  direita,
  para,
}: {
  esquerda: React.ReactNode;
  titulo: string;
  direita?: React.ReactNode;
  para?: string;
}) {
  return (
    <div
      className="linha linha--espalhada"
      style={{ gap: "var(--espaco-3)", alignItems: "baseline" }}
    >
      <div className="linha" style={{ gap: "var(--espaco-2)", minWidth: 0 }}>
        {esquerda}
        {para ? (
          <Link to={para} className="truncar" style={{ maxWidth: "34ch" }} title={titulo}>
            {titulo}
          </Link>
        ) : (
          <span className="truncar" style={{ maxWidth: "34ch" }} title={titulo}>
            {titulo}
          </span>
        )}
      </div>
      {direita ? <div className="linha" style={{ gap: "var(--espaco-2)" }}>{direita}</div> : null}
    </div>
  );
}

export function CentroDeOperacoes() {
  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["centro-de-operacoes"],
    queryFn: () => pedir<VistaDoCentroDeOperacoes>("/soc?limite=8"),
    // Um ecrã de turno tem de envelhecer devagar mas não ficar parado.
    refetchInterval: 60_000,
  });

  return (
    <div className="pilha">
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Centro de operações</h1>
          <p className="pagina__descricao">
            O trabalho que está à espera de alguém, reunido num só ecrã. Ao
            contrário do painel, que mostra como as coisas correram, aqui só
            aparecem itens que se podem abrir e tratar agora.
          </p>
        </div>
      </div>

      {error ? <Erro erro={error} /> : null}
      {isPending ? <Carregando /> : null}
      {isFetching && !isPending ? (
        <p className="terciario">A actualizar…</p>
      ) : null}

      {data ? (
        <div className="grelha grelha--2">
          <Fila
            titulo="Incidentes activos"
            explicacao="Abertos e não encerrados, os fora de prazo primeiro."
            quantos={data.incidentes_activos.length}
            verTudo={{ para: "/incidentes", rotulo: "Ver todos" }}
          >
            {data.incidentes_activos.map((i) => (
              <Linha
                key={i.id}
                esquerda={
                  <>
                    <span className="mono terciario">{i.referencia}</span>
                    <DistintivoDeSeveridade valor={i.severidade} />
                  </>
                }
                titulo={i.titulo}
                para={`/incidentes/${i.id}`}
                direita={
                  <>
                    <span className="terciario">
                      {i.responsavel ?? "sem responsável"}
                    </span>
                    <Prazo prazo={i.prazo} />
                  </>
                }
              />
            ))}
          </Fila>

          <Fila
            titulo="Alertas por triar"
            explicacao="Ordenados pela pontuação de triagem."
            quantos={data.alertas_recentes.length}
            verTudo={{ para: "/alertas", rotulo: "Ver a fila" }}
          >
            {data.alertas_recentes.map((a) => (
              <Linha
                key={a.id}
                esquerda={
                  <>
                    <span className="mono terciario">{a.referencia}</span>
                    <DistintivoDeSeveridade valor={a.severidade} />
                  </>
                }
                titulo={a.titulo}
                direita={
                  <>
                    <span className="mono" title="Pontuação de triagem">
                      {a.pontuacao}
                    </span>
                    {a.probabilidade_falso_positivo > 0 ? (
                      <span
                        className="terciario mono"
                        title="Probabilidade estimada de ser falso positivo"
                      >
                        FP {a.probabilidade_falso_positivo}%
                      </span>
                    ) : null}
                    <span className="terciario mono" title="Eventos agregados">
                      {a.eventos} ev.
                    </span>
                  </>
                }
              />
            ))}
          </Fila>

          <Fila
            titulo="Aprovações pendentes"
            explicacao="Acções que aguardam decisão humana para poderem executar."
            quantos={data.aprovacoes_pendentes.length}
            verTudo={{ para: "/aprovacoes", rotulo: "Decidir" }}
          >
            {data.aprovacoes_pendentes.map((a) => (
              <Linha
                key={a.id}
                esquerda={
                  <>
                    <span className="mono terciario">{a.referencia}</span>
                    <span
                      className={`distintivo ${
                        a.risco === "CRITICO"
                          ? "distintivo--perigo"
                          : a.risco === "ALTO"
                            ? "distintivo--aviso"
                            : "distintivo--neutro"
                      }`}
                      title="Nível de risco da acção"
                    >
                      {legivel(a.risco)}
                    </span>
                  </>
                }
                titulo={a.titulo}
                direita={<span className="terciario">{instante(a.solicitado_em)}</span>}
              />
            ))}
          </Fila>

          <Fila
            titulo="Playbooks em execução"
            explicacao="Os que estão suspensos num ponto de aprovação não avançam sozinhos."
            quantos={data.playbooks_em_execucao.length}
            verTudo={{ para: "/playbooks", rotulo: "Ver execuções" }}
          >
            {data.playbooks_em_execucao.map((p) => (
              <Linha
                key={p.id}
                esquerda={<span className="mono terciario">{p.referencia}</span>}
                titulo={p.playbook}
                direita={
                  <>
                    <span
                      className={`distintivo ${
                        p.estado === "AGUARDA_APROVACAO"
                          ? "distintivo--aviso"
                          : "distintivo--neutro"
                      }`}
                    >
                      {legivel(p.estado)}
                    </span>
                    <span className="terciario">{instante(p.iniciado_em)}</span>
                  </>
                }
              />
            ))}
          </Fila>

          <Fila
            titulo="Indicadores mais observados"
            explicacao="Contagem de avistamentos reais, não uma lista importada."
            quantos={data.indicadores_frequentes.length}
            verTudo={{ para: "/indicadores", rotulo: "Ver catálogo" }}
          >
            {data.indicadores_frequentes.map((i) => (
              <Linha
                key={i.id}
                esquerda={<span className="terciario">{legivel(i.tipo)}</span>}
                titulo={i.valor}
                direita={
                  <>
                    <span
                      className={`distintivo ${
                        i.reputacao === "MALICIOSA"
                          ? "distintivo--perigo"
                          : i.reputacao === "SUSPEITA"
                            ? "distintivo--aviso"
                            : "distintivo--neutro"
                      }`}
                    >
                      {legivel(i.reputacao)}
                    </span>
                    <span className="mono terciario" title="Avistamentos">
                      {i.avistamentos}
                    </span>
                  </>
                }
              />
            ))}
          </Fila>

          <Fila
            titulo="Activos afectados"
            explicacao="Equipamentos com incidentes activos, pela criticidade."
            quantos={data.activos_afectados.length}
            verTudo={{ para: "/activos", rotulo: "Ver inventário" }}
          >
            {data.activos_afectados.map((a) => (
              <Linha
                key={a.id}
                esquerda={<span className="mono terciario">{a.identificador}</span>}
                titulo={a.nome}
                direita={
                  <>
                    <span className="terciario">
                      criticidade {legivel(a.criticidade).toLowerCase()}
                    </span>
                    <span className="mono" title="Incidentes activos">
                      {a.incidentes_activos}
                    </span>
                  </>
                }
              />
            ))}
          </Fila>

          <Fila
            titulo="Tarefas em aberto"
            explicacao="Passos de investigação por concluir."
            quantos={data.tarefas_pendentes.length}
          >
            {data.tarefas_pendentes.map((t) => (
              <Linha
                key={t.id}
                esquerda={<span className="terciario mono">{t.prioridade}</span>}
                titulo={t.titulo}
                direita={
                  <>
                    <span className="terciario">
                      {t.responsavel ?? "sem responsável"}
                    </span>
                    <Prazo prazo={t.prazo} />
                  </>
                }
              />
            ))}
          </Fila>
        </div>
      ) : null}

      {data &&
      Object.values(data).every((v) => Array.isArray(v) && v.length === 0) ? (
        <Vazio
          titulo="Nenhum trabalho em fila"
          detalhe="Não há incidentes activos, alertas por triar nem aprovações pendentes."
        />
      ) : null}
    </div>
  );
}
