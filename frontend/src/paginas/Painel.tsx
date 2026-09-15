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

import { pedir } from "@/api/cliente";
import type { Painel as DadosDoPainel } from "@/api/tipos";
import { Carregando, Erro } from "@/componentes/comuns";

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

export function Painel() {
  const { data, isPending, error } = useQuery({
    queryKey: ["painel"],
    queryFn: () => pedir<DadosDoPainel>("/dashboard"),
    // Uma sala de operações quer números frescos; 30 segundos é o compromisso
    // entre estar actualizado e não martelar a base de dados.
    refetchInterval: 30_000,
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
            cache.
          </p>
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
      </div>
    </>
  );
}
