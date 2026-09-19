/**
 * Painel (§4.13, tela 2 · §4.5.2 · §58 do briefing).
 *
 * Todos os números vêm contados da base de dados no momento do pedido — a API
 * não mantém valores pré-calculados. A interface não guarda cache longa nem
 * arredonda: mostrar "aproximadamente 12" num painel de segurança é pior do
 * que não mostrar nada, porque ninguém sabe de que lado está o erro.
 *
 * Os indicadores que exigem acção — alertas por triar, incidentes sem
 * responsável, fora de prazo, aprovações pendentes — estão destacados e ligam
 * directamente à fila correspondente já filtrada. Um painel que obriga a
 * procurar depois de informar é meio painel.
 */

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type {
  CargaDeAnalista,
  Distribuicao,
  MetricasDeResposta,
  Painel as DadosDoPainel,
  PontoDaTendencia,
} from "@/api/tipos";
import { Carregando, Erro } from "@/componentes/comuns";
import {
  BarrasCategoricas,
  corDaSeveridade,
  duracaoLegivel,
  SerieTemporal,
} from "@/componentes/graficos";
import { CampoDeSelecao, useFiltros } from "@/componentes/listagem";

function Indicador({
  rotulo,
  valor,
  nota,
  aspecto,
  para,
}: {
  rotulo: string;
  valor: number | string;
  nota?: string;
  aspecto?: "alerta" | "critico";
  para?: string;
}) {
  const conteudo = (
    <>
      <span className="indicador__rotulo">{rotulo}</span>
      <span className="indicador__valor">{valor}</span>
      {nota ? <span className="indicador__nota">{nota}</span> : null}
    </>
  );

  const classe = `indicador${aspecto ? ` indicador--${aspecto}` : ""}`;

  if (para) {
    return (
      <Link to={para} className={classe} style={{ color: "inherit" }}>
        {conteudo}
      </Link>
    );
  }
  return <div className={classe}>{conteudo}</div>;
}

//: Janelas oferecidas. A API aceita 1 a 365; estas são as que se usam ao
//: responder a "como corremos" — a semana, o mês, o trimestre, o ano.
const JANELAS = [
  { valor: "7", rotulo: "7 dias" },
  { valor: "30", rotulo: "30 dias" },
  { valor: "90", rotulo: "90 dias" },
  { valor: "365", rotulo: "1 ano" },
];

export function Painel() {
  const { ler, definir } = useFiltros();
  // A janela vai na barra de endereço, e não em estado local, para que um painel
  // possa ser partilhado por ligação com a janela que quem o enviou estava a ver.
  const dias = ler("dias", "30");

  const { data, isPending, error } = useQuery({
    queryKey: ["painel", dias],
    queryFn: () => pedir<DadosDoPainel>(`/dashboard${consulta({ dias })}`),
    // Uma sala de operações quer números frescos; 30 segundos é o compromisso
    // entre estar actualizado e não martelar a base de dados.
    refetchInterval: 30_000,
  });

  // Consultas separadas de propósito: cada uma é uma agregação distinta e
  // falhar uma não deve deixar o painel inteiro em branco.
  const distribuicao = useQuery({
    queryKey: ["painel-distribuicao", dias],
    queryFn: () => pedir<Distribuicao>(`/dashboard/distribution${consulta({ dias })}`),
    refetchInterval: 60_000,
  });
  const tendencia = useQuery({
    queryKey: ["painel-tendencia", dias],
    queryFn: () => pedir<PontoDaTendencia[]>(`/dashboard/trend${consulta({ dias })}`),
    refetchInterval: 60_000,
  });
  const metricas = useQuery({
    queryKey: ["painel-metricas", dias],
    queryFn: () => pedir<MetricasDeResposta>(`/dashboard/response-metrics${consulta({ dias })}`),
    refetchInterval: 60_000,
  });
  const carga = useQuery({
    queryKey: ["painel-carga"],
    queryFn: () => pedir<CargaDeAnalista[]>("/dashboard/workload"),
    refetchInterval: 60_000,
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;

  const { incidentes, alertas, resposta, eventos, inteligencia } = data;

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Painel</h1>
          <p className="pagina__descricao">
            Situação dos últimos {data.periodo_dias} dias. Todos os valores são
            contados na base de dados no momento do pedido — não há números em
            cache. A janela é a que está escolhida à direita; o número mostrado
            vem do servidor, pelo que confirma qual foi de facto aplicada.
          </p>
        </div>
        <div className="pagina__accoes">
          <CampoDeSelecao
            etiqueta="Janela"
            valor={dias}
            opcoes={JANELAS}
            aoMudar={(v) => definir({ dias: v || "30" })}
            todos="30 dias"
          />
        </div>
      </div>

      <div className="pilha" style={{ gap: "var(--espaco-5)" }}>
        <section>
          <h2 style={{ marginBottom: "var(--espaco-3)" }}>A precisar de atenção</h2>
          <div className="grelha grelha--4">
            <Indicador
              rotulo="Alertas por triar"
              valor={alertas.por_triar}
              nota="Aguardam decisão humana"
              aspecto={alertas.por_triar > 0 ? "alerta" : undefined}
              para="/alertas?estado=NOVO"
            />
            <Indicador
              rotulo="Sem responsável"
              valor={incidentes.sem_responsavel}
              nota="Nenhum prazo é de ninguém"
              aspecto={incidentes.sem_responsavel > 0 ? "alerta" : undefined}
              para="/incidentes?sem_responsavel=true"
            />
            <Indicador
              rotulo="Fora de prazo"
              valor={incidentes.fora_de_prazo}
              nota="Prazo derivado da severidade"
              aspecto={incidentes.fora_de_prazo > 0 ? "critico" : undefined}
              para="/incidentes?apenas_activos=true"
            />
            <Indicador
              rotulo="Aprovações pendentes"
              valor={resposta.aprovacoes_pendentes}
              nota="Acções à espera de decisão"
              aspecto={resposta.aprovacoes_pendentes > 0 ? "alerta" : undefined}
              para="/aprovacoes"
            />
          </div>
        </section>

        <section>
          <h2 style={{ marginBottom: "var(--espaco-3)" }}>Incidentes</h2>
          <div className="grelha grelha--4">
            <Indicador rotulo="Total" valor={incidentes.total} para="/incidentes" />
            <Indicador
              rotulo="Activos"
              valor={incidentes.activos}
              nota="Por encerrar"
              para="/incidentes?apenas_activos=true"
            />
            <Indicador
              rotulo="Críticos"
              valor={incidentes.criticos}
              aspecto={incidentes.criticos > 0 ? "critico" : undefined}
              para="/incidentes?severidade=CRITICA"
            />
            <Indicador
              rotulo="Em investigação"
              valor={incidentes.em_investigacao}
              para="/incidentes?estado=INVESTIGACAO"
            />
            <Indicador
              rotulo="Resolvidos"
              valor={incidentes.resolvidos}
              para="/incidentes?estado=RESOLVIDO"
            />
            <Indicador
              rotulo="Encerrados"
              valor={incidentes.encerrados}
              para="/incidentes?estado=ENCERRADO"
            />
            <Indicador
              rotulo="Falsos positivos"
              valor={incidentes.falsos_positivos}
              nota="Alimentam o detector"
              para="/incidentes?estado=FALSO_POSITIVO"
            />
          </div>
        </section>

        <section>
          <h2 style={{ marginBottom: "var(--espaco-3)" }}>Detecção</h2>
          <div className="grelha grelha--4">
            <Indicador rotulo="Alertas" valor={alertas.total} para="/alertas" />
            <Indicador
              rotulo="No período"
              valor={alertas.no_periodo}
              nota={`Últimos ${data.periodo_dias} dias`}
            />
            <Indicador
              rotulo="Taxa de falsos positivos"
              valor={`${alertas.taxa_falsos_positivos_percentagem.toFixed(1)}%`}
              nota={`${alertas.descartados_ou_falsos_positivos} de ${alertas.total} decididos`}
            />
            <Indicador
              rotulo="Eventos ingeridos"
              valor={eventos.total}
              nota="Sinais brutos normalizados"
            />
            <Indicador
              rotulo="Indicadores adversos"
              valor={inteligencia.indicadores_adversos}
              nota="Suspeitos ou maliciosos"
              para="/indicadores"
            />
            <Indicador
              rotulo="Acções executadas"
              valor={resposta.accoes_executadas}
              para="/aprovacoes"
            />
            <Indicador
              rotulo="Tarefas pendentes"
              valor={resposta.tarefas_pendentes}
            />
          </div>
        </section>

        <section className="pilha">
          <h2>Tempos de resposta</h2>
          {metricas.error ? <Erro erro={metricas.error} /> : null}
          {metricas.isPending ? (
            <Carregando />
          ) : metricas.data ? (
            <>
              <div className="grelha grelha--4">
                <Indicador
                  rotulo="Reconhecimento (médio)"
                  valor={duracaoLegivel(metricas.data.tempo_medio_reconhecimento_segundos)}
                  nota={`${metricas.data.incidentes_reconhecidos} incidentes`}
                />
                <Indicador
                  rotulo="Reconhecimento (mediano)"
                  valor={duracaoLegivel(metricas.data.tempo_mediano_reconhecimento_segundos)}
                  nota="Menos sensível a casos extremos"
                />
                <Indicador
                  rotulo="Resolução (médio)"
                  valor={duracaoLegivel(metricas.data.tempo_medio_resolucao_segundos)}
                  nota={`${metricas.data.incidentes_resolvidos} incidentes`}
                />
                <Indicador
                  rotulo="Dentro do prazo"
                  valor={
                    metricas.data.cumprimento_prazo.percentagem === null
                      ? "—"
                      : `${metricas.data.cumprimento_prazo.percentagem}%`
                  }
                  nota={`${metricas.data.cumprimento_prazo.dentro_do_prazo} de ${metricas.data.cumprimento_prazo.avaliados}`}
                  aspecto={
                    metricas.data.cumprimento_prazo.percentagem !== null &&
                    metricas.data.cumprimento_prazo.percentagem < 80
                      ? "alerta"
                      : undefined
                  }
                />
              </div>
              {/* A API explica o que fica de fora das médias; repeti-lo aqui
                  evita que alguém leia um "—" como se fosse zero. */}
              <p className="terciario">{metricas.data.nota}</p>
            </>
          ) : null}
        </section>

        <section className="pilha">
          <h2>Tendência e distribuição</h2>
          {tendencia.error ? <Erro erro={tendencia.error} /> : null}
          {tendencia.data ? <SerieTemporal dados={tendencia.data} /> : null}

          {distribuicao.error ? <Erro erro={distribuicao.error} /> : null}
          {distribuicao.data ? (
            <div className="grelha grelha--2">
              <BarrasCategoricas
                titulo="Incidentes por severidade"
                nota={`Últimos ${distribuicao.data.periodo_dias} dias`}
                dados={distribuicao.data.incidentes_por_severidade}
                colorir={corDaSeveridade}
              />
              <BarrasCategoricas
                titulo="Incidentes por categoria"
                nota={`Últimos ${distribuicao.data.periodo_dias} dias`}
                dados={distribuicao.data.incidentes_por_categoria}
              />
              <BarrasCategoricas
                titulo="Incidentes por estado"
                dados={distribuicao.data.incidentes_por_estado}
              />
              <BarrasCategoricas
                titulo="Alertas por fonte"
                nota="De onde vem a detecção"
                dados={distribuicao.data.alertas_por_fonte}
              />
            </div>
          ) : null}
        </section>

        <section className="pilha">
          <h2>Carga por analista</h2>
          {carga.error ? <Erro erro={carga.error} /> : null}
          {carga.isPending ? (
            <Carregando />
          ) : carga.data && carga.data.length > 0 ? (
            <div className="tabela-envolvente">
              <table className="tabela">
                <thead>
                  <tr>
                    <th>Analista</th>
                    <th>Incidentes activos</th>
                    <th>Graves</th>
                    <th>Tarefas pendentes</th>
                  </tr>
                </thead>
                <tbody>
                  {carga.data.map((a) => (
                    <tr key={a.utilizador_id}>
                      <td>
                        {a.nome}
                        <span className="terciario mono"> · {a.email}</span>
                      </td>
                      <td className="mono">{a.incidentes_activos}</td>
                      <td className="mono">{a.incidentes_graves}</td>
                      <td className="mono">{a.tarefas_pendentes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="terciario">Sem incidentes atribuídos.</p>
          )}
        </section>
      </div>
    </>
  );
}
