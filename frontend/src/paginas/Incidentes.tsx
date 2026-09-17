/**
 * Lista de incidentes (§4.13, tela 3 · RF15, RF16).
 *
 * Densidade de SOC: linhas compactas, colunas que cabem num ecrã, e a
 * informação que decide a ordem de trabalho — severidade, estado, prazo,
 * responsável — visível sem abrir nada. A pesquisa incide sobre referência,
 * título e descrição, como a API a implementa.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { IncidenteResumo, Pagina } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import {
  Carregando,
  DistintivoDeEstado,
  DistintivoDeSeveridade,
  Erro,
  instante,
  legivel,
  MarcaDeDemonstracao,
  Vazio,
} from "@/componentes/comuns";
import {
  CATEGORIAS,
  CampoDeSelecao,
  ESTADOS_DO_INCIDENTE,
  Paginacao,
  SEVERIDADES,
  useFiltros,
} from "@/componentes/listagem";
import { useAgora } from "@/componentes/relogio";

/**
 * Assinala um prazo já ultrapassado num incidente por resolver.
 *
 * O instante vem de `useAgora()` e não de `Date.now()`: lido durante o render,
 * um prazo que expirasse com a fila aberta nunca ficaria vermelho, porque um
 * refetch com os mesmos dados não provoca render. Ver `componentes/relogio.ts`.
 */
function Prazo({ valor, resolvido }: { valor: string | null; resolvido: boolean }) {
  const agora = useAgora();
  if (!valor) return <span className="terciario">—</span>;
  const expirou = !resolvido && new Date(valor).getTime() < agora;
  return (
    <span style={expirou ? { color: "var(--critico)", fontWeight: 600 } : undefined}>
      {instante(valor)}
      {expirou ? " ⚠" : ""}
    </span>
  );
}

export function Incidentes() {
  const { ler, definir, limpar } = useFiltros();
  const navegar = useNavigate();
  const { pode } = useSessao();

  const parametros = {
    q: ler("q"),
    estado: ler("estado"),
    severidade: ler("severidade"),
    categoria: ler("categoria"),
    apenas_activos: ler("apenas_activos"),
    sem_responsavel: ler("sem_responsavel"),
    page: ler("page", "1"),
    size: "25",
    sort: ler("sort", "-detected_at"),
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["incidentes", parametros],
    queryFn: () =>
      pedir<Pagina<IncidenteResumo>>(`/incidents${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const temFiltros = ["q", "estado", "severidade", "categoria", "apenas_activos", "sem_responsavel"]
    .some((chave) => ler(chave) !== "");

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Incidentes</h1>
          <p className="pagina__descricao">
            Fila de trabalho. A ordenação por omissão é pela detecção mais
            recente; o prazo a vermelho assinala incidentes por resolver que já
            o ultrapassaram.
          </p>
        </div>
        {pode("incidents:create") ? (
          <div className="pagina__accoes">
            <Link to="/incidentes/novo" className="botao botao--primario">
              Registar incidente
            </Link>
          </div>
        ) : null}
      </div>

      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa">
            Pesquisa
          </label>
          <input
            id="pesquisa"
            className="entrada"
            type="search"
            placeholder="Referência, título ou descrição…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <CampoDeSelecao
          etiqueta="Estado"
          valor={ler("estado")}
          opcoes={ESTADOS_DO_INCIDENTE}
          aoMudar={(v) => definir({ estado: v })}
        />
        <CampoDeSelecao
          etiqueta="Severidade"
          valor={ler("severidade")}
          opcoes={SEVERIDADES}
          aoMudar={(v) => definir({ severidade: v })}
        />
        <CampoDeSelecao
          etiqueta="Categoria"
          valor={ler("categoria")}
          opcoes={CATEGORIAS}
          aoMudar={(v) => definir({ categoria: v })}
        />
        <CampoDeSelecao
          etiqueta="Âmbito"
          valor={ler("apenas_activos")}
          opcoes={[{ valor: "true", rotulo: "Apenas activos" }]}
          aoMudar={(v) => definir({ apenas_activos: v })}
          todos="Todos"
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
          <Vazio
            titulo={temFiltros ? "Nenhum incidente corresponde aos filtros" : "Sem incidentes"}
            detalhe={
              temFiltros
                ? "Ajuste ou limpe os filtros para ver mais resultados."
                : "Os incidentes aparecem aqui quando um alerta é promovido ou quando alguém regista uma ocorrência."
            }
          />
        </div>
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Referência</th>
                <th>Título</th>
                <th>Severidade</th>
                <th>Estado</th>
                <th>Categoria</th>
                <th>Responsável</th>
                <th>Detectado</th>
                <th>Prazo</th>
              </tr>
            </thead>
            <tbody>
              {data.itens.map((incidente) => (
                <tr
                  key={incidente.id}
                  className="clicavel"
                  onClick={() => navegar(`/incidentes/${incidente.id}`)}
                >
                  <td className="mono">{incidente.reference}</td>
                  <td>
                    <div className="linha" style={{ gap: "var(--espaco-2)" }}>
                      <span className="truncar" style={{ maxWidth: "42ch" }}>
                        {incidente.title}
                      </span>
                      {incidente.is_demo_data ? <MarcaDeDemonstracao /> : null}
                    </div>
                  </td>
                  <td>
                    <DistintivoDeSeveridade valor={incidente.severity} />
                  </td>
                  <td>
                    <DistintivoDeEstado valor={incidente.status} />
                  </td>
                  <td className="secundario">{legivel(incidente.category)}</td>
                  <td className="secundario">
                    {incidente.assignee?.nome ?? (
                      <span className="terciario">Sem responsável</span>
                    )}
                  </td>
                  <td className="secundario">{instante(incidente.detected_at)}</td>
                  <td className="secundario">
                    <Prazo
                      valor={incidente.due_at}
                      resolvido={["RESOLVIDO", "ENCERRADO", "FALSO_POSITIVO"].includes(
                        incidente.status,
                      )}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao
            pagina={data}
            aoMudar={(numero) => definir({ page: numero })}
          />
        </div>
      ) : null}
    </>
  );
}
