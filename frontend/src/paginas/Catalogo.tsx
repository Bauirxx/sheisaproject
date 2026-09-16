/**
 * Catálogo: indicadores, activos e MITRE ATT&CK.
 *
 * Três listagens que partilham a mesma forma e por isso vivem no mesmo
 * ficheiro. Separá-las em três daria três cópias do mesmo esqueleto de tabela
 * com filtros — e a terceira cópia seria a que ficaria por corrigir.
 *
 * Nos indicadores, `avistamentos` é a coluna que importa: um indicador visto
 * uma vez é uma curiosidade; visto vinte vezes em incidentes diferentes é uma
 * pista. É a diferença entre o IOC como entidade global e a observação como
 * avistamento concreto.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { consulta, pedir } from "@/api/cliente";
import { CoberturaMitre } from "@/componentes/CoberturaMitre";
import { EditarActivo, EditarIndicador } from "@/componentes/EditarCatalogo";
import type { Activo, Indicador, Pagina } from "@/api/tipos";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";
import { CampoDeSelecao, Paginacao, useFiltros } from "@/componentes/listagem";

// ------------------------------------------------------------- indicadores
const ASPECTO_DA_REPUTACAO: Record<string, string> = {
  MALICIOSA: "distintivo--perigo",
  SUSPEITA: "distintivo--aviso",
  BENIGNA: "distintivo--sucesso",
  DESCONHECIDA: "distintivo--neutro",
};

export function Indicadores() {
  const { ler, definir, limpar } = useFiltros();
  const [aEditar, definirAEditar] = useState<Indicador | null>(null);

  const parametros = {
    q: ler("q"),
    tipo: ler("tipo"),
    reputacao: ler("reputacao"),
    page: ler("page", "1"),
    size: "30",
    sort: ler("sort", "-last_seen"),
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["indicadores", parametros],
    queryFn: () => pedir<Pagina<Indicador>>(`/iocs${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const temFiltros = ["q", "tipo", "reputacao"].some((c) => ler(c) !== "");

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Indicadores</h1>
          <p className="pagina__descricao">
            Cada indicador é único por tipo e valor, e acumula avistamentos ao
            longo dos incidentes. É por isso que <code>primeiro visto</code> e
            <code> último visto</code> são factos e não estimativas.
          </p>
        </div>
      </div>

      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa-ioc">
            Pesquisa
          </label>
          <input
            id="pesquisa-ioc"
            className="entrada"
            type="search"
            placeholder="Endereço, domínio, hash…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <CampoDeSelecao
          etiqueta="Tipo"
          valor={ler("tipo")}
          opcoes={[
            { valor: "IP", rotulo: "Endereço IP" },
            { valor: "DOMINIO", rotulo: "Domínio" },
            { valor: "URL", rotulo: "URL" },
            { valor: "HASH_SHA256", rotulo: "SHA-256" },
            { valor: "HASH_MD5", rotulo: "MD5" },
            { valor: "UTILIZADOR", rotulo: "Utilizador" },
            { valor: "HOSTNAME", rotulo: "Anfitrião" },
            { valor: "EMAIL", rotulo: "Correio electrónico" },
            { valor: "USER_AGENT", rotulo: "User-Agent" },
          ]}
          aoMudar={(v) => definir({ tipo: v })}
        />
        <CampoDeSelecao
          etiqueta="Reputação"
          valor={ler("reputacao")}
          opcoes={[
            { valor: "MALICIOSA", rotulo: "Maliciosa" },
            { valor: "SUSPEITA", rotulo: "Suspeita" },
            { valor: "BENIGNA", rotulo: "Benigna" },
            { valor: "DESCONHECIDA", rotulo: "Desconhecida" },
          ]}
          aoMudar={(v) => definir({ reputacao: v })}
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
            titulo={temFiltros ? "Nenhum indicador corresponde" : "Sem indicadores"}
            detalhe="Os indicadores são extraídos automaticamente dos eventos ingeridos."
          />
        </div>
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Valor</th>
                <th>Tipo</th>
                <th>Reputação</th>
                <th>Risco</th>
                <th>Avistamentos</th>
                <th>Primeiro visto</th>
                <th>Último visto</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.itens.map((indicador) => (
                <tr key={indicador.id}>
                  <td className="mono">
                    {indicador.value}
                    {indicador.is_allowlisted ? (
                      <span
                        className="distintivo distintivo--neutro"
                        style={{ marginLeft: "var(--espaco-2)" }}
                        title={indicador.allowlist_reason ?? "Na lista de permitidos"}
                      >
                        permitido
                      </span>
                    ) : null}
                  </td>
                  <td className="secundario">{legivel(indicador.ioc_type)}</td>
                  <td>
                    <span
                      className={`distintivo ${
                        ASPECTO_DA_REPUTACAO[indicador.reputation] ?? "distintivo--neutro"
                      }`}
                    >
                      {legivel(indicador.reputation)}
                    </span>
                  </td>
                  <td className="mono">{indicador.risk_score}</td>
                  <td className="mono">{indicador.sighting_count}</td>
                  <td className="secundario">{instante(indicador.first_seen)}</td>
                  <td className="secundario">{instante(indicador.last_seen)}</td>
                  <td>
                    <button
                      type="button"
                      className="botao botao--pequeno"
                      onClick={() => definirAEditar(indicador)}
                    >
                      Editar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
        </div>
      ) : null}

      {aEditar ? (
        <div
          className="sobreposicao"
          role="dialog"
          aria-modal="true"
          aria-label={`Editar ${aEditar.value}`}
          onClick={() => definirAEditar(null)}
        >
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
              <div className="pilha" style={{ gap: 0 }}>
                <h2>Editar indicador</h2>
                <span className="terciario mono">{aEditar.value}</span>
              </div>
              <button
                type="button"
                className="botao botao--discreto"
                onClick={() => definirAEditar(null)}
              >
                Fechar
              </button>
            </div>
            <EditarIndicador
              key={aEditar.id}
              indicador={aEditar}
              aoFechar={() => definirAEditar(null)}
            />
          </div>
        </div>
      ) : null}
    </>
  );
}

// ------------------------------------------------------------------ activos
const ASPECTO_DA_CRITICIDADE: Record<string, string> = {
  CRITICA: "distintivo--perigo",
  ALTA: "distintivo--aviso",
  MEDIA: "distintivo--neutro",
  BAIXA: "distintivo--neutro",
};

export function Activos() {
  const [activoAEditar, definirActivoAEditar] = useState<Activo | null>(null);
  const { ler, definir } = useFiltros();

  const parametros = {
    q: ler("q"),
    criticidade: ler("criticidade"),
    page: ler("page", "1"),
    size: "30",
  };

  const { data, isPending, error } = useQuery({
    queryKey: ["activos", parametros],
    queryFn: () => pedir<Pagina<Activo & { is_active: boolean; owner: string | null; location: string | null; operating_system: string | null }>>(
      `/assets${consulta(parametros)}`,
    ),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Activos</h1>
          <p className="pagina__descricao">
            Inventário dos sistemas monitorizados. A criticidade do activo entra
            na pontuação de triagem: o mesmo alerta contra um servidor crítico e
            contra uma estação de trabalho não vale o mesmo.
          </p>
        </div>
      </div>

      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa-activo">
            Pesquisa
          </label>
          <input
            id="pesquisa-activo"
            className="entrada"
            type="search"
            placeholder="Identificador, nome, anfitrião ou endereço…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <CampoDeSelecao
          etiqueta="Criticidade"
          valor={ler("criticidade")}
          opcoes={[
            { valor: "CRITICA", rotulo: "Crítica" },
            { valor: "ALTA", rotulo: "Alta" },
            { valor: "MEDIA", rotulo: "Média" },
            { valor: "BAIXA", rotulo: "Baixa" },
          ]}
          aoMudar={(v) => definir({ criticidade: v })}
        />
      </div>

      {error ? <Erro erro={error} /> : null}

      {isPending ? (
        <Carregando />
      ) : data && data.total === 0 ? (
        <div className="tabela-envolvente">
          <Vazio titulo="Sem activos no inventário" />
        </div>
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Identificador</th>
                <th>Nome</th>
                <th>Tipo</th>
                <th>Criticidade</th>
                <th>Anfitrião</th>
                <th>Endereço</th>
                <th>Responsável</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.itens.map((activo) => (
                <tr key={activo.id}>
                  <td className="mono">{activo.identifier}</td>
                  <td>{activo.name}</td>
                  <td className="secundario">{legivel(activo.asset_type)}</td>
                  <td>
                    <span
                      className={`distintivo ${
                        ASPECTO_DA_CRITICIDADE[activo.criticality] ?? "distintivo--neutro"
                      }`}
                    >
                      {legivel(activo.criticality)}
                    </span>
                  </td>
                  <td className="secundario mono">{activo.hostname ?? "—"}</td>
                  <td className="secundario mono">{activo.ip_address ?? "—"}</td>
                  <td className="secundario">{activo.owner ?? "—"}</td>
                  <td>
                    <button
                      type="button"
                      className="botao botao--pequeno"
                      onClick={() => definirActivoAEditar(activo)}
                    >
                      Editar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
        </div>
      ) : null}

      {activoAEditar ? (
        <div
          className="sobreposicao"
          role="dialog"
          aria-modal="true"
          aria-label={`Editar ${activoAEditar.identifier}`}
          onClick={() => definirActivoAEditar(null)}
        >
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
              <div className="pilha" style={{ gap: 0 }}>
                <h2>Editar activo</h2>
                <span className="terciario mono">{activoAEditar.identifier}</span>
              </div>
              <button
                type="button"
                className="botao botao--discreto"
                onClick={() => definirActivoAEditar(null)}
              >
                Fechar
              </button>
            </div>
            <EditarActivo
              key={activoAEditar.id}
              activo={activoAEditar}
              aoFechar={() => definirActivoAEditar(null)}
            />
          </div>
        </div>
      ) : null}
    </>
  );
}

// -------------------------------------------------------------------- MITRE
interface Tecnica {
  id: string;
  technique_id: string;
  name: string;
  description: string;
  url: string | null;
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  tactic_shortnames: string[];
  platforms: string[];
  attack_version: string | null;
}

export function Mitre() {
  const { ler, definir } = useFiltros();
  // A cobertura observada é o que interessa ao dia-a-dia; o catálogo completo
  // (709 técnicas) serve para consulta. Por isso a cobertura vem primeiro.
  const vista = ler("vista", "cobertura");

  const parametros = {
    q: ler("q"),
    incluir_subtecnicas: ler("subtecnicas", "false"),
    page: ler("page", "1"),
    size: "30",
  };

  const { data, isPending, error, isFetching } = useQuery({
    queryKey: ["mitre", parametros],
    queryFn: () => pedir<Pagina<Tecnica>>(`/mitre/techniques${consulta(parametros)}`),
    placeholderData: keepPreviousData,
  });

  const comSubtecnicas = ler("subtecnicas", "false") === "true";

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>MITRE ATT&CK</h1>
          <p className="pagina__descricao">
            Catálogo carregado do bundle oficial
            {data?.itens[0]?.attack_version
              ? ` (versão ${data.itens[0].attack_version})`
              : ""}
            . É a linguagem comum para descrever comportamento adversário — e é
            contra este catálogo que qualquer técnica proposta pelo motor é
            validada antes de ser sugerida.
          </p>
        </div>
      </div>

      <div className="separadores" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={vista === "cobertura"}
          className={`separador${vista === "cobertura" ? " separador--activo" : ""}`}
          onClick={() => definir({ vista: "cobertura" })}
        >
          Cobertura observada
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={vista === "catalogo"}
          className={`separador${vista === "catalogo" ? " separador--activo" : ""}`}
          onClick={() => definir({ vista: "catalogo" })}
        >
          Catálogo completo
        </button>
      </div>

      {vista === "cobertura" ? <CoberturaMitre /> : null}

      <div hidden={vista !== "catalogo"}>
      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa-mitre">
            Pesquisa
          </label>
          <input
            id="pesquisa-mitre"
            className="entrada"
            type="search"
            placeholder="T1110, força bruta, credenciais…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        <div className="campo">
          <label className="campo__etiqueta">Âmbito</label>
          <button
            type="button"
            className="botao"
            onClick={() => definir({ subtecnicas: comSubtecnicas ? "false" : "true" })}
          >
            {comSubtecnicas ? "Com subtécnicas" : "Só técnicas"}
          </button>
        </div>
        {isFetching ? <span className="carregando" aria-hidden="true" /> : null}
      </div>

      {error ? <Erro erro={error} /> : null}

      {isPending ? (
        <Carregando />
      ) : data && data.total === 0 ? (
        <div className="tabela-envolvente">
          <Vazio
            titulo="Catálogo vazio"
            detalhe="Carregue-o com: python -m scripts.manage mitre-load"
          />
        </div>
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Identificador</th>
                <th>Nome</th>
                <th>Tácticas</th>
                <th>Plataformas</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.itens.map((tecnica) => (
                <tr key={tecnica.id}>
                  <td className="mono">
                    {tecnica.technique_id}
                    {tecnica.is_subtechnique ? (
                      <span className="terciario"> (sub)</span>
                    ) : null}
                  </td>
                  <td>{tecnica.name}</td>
                  <td className="secundario">
                    {tecnica.tactic_shortnames.join(", ") || "—"}
                  </td>
                  <td className="secundario truncar" style={{ maxWidth: "24ch" }}>
                    {tecnica.platforms.join(", ") || "—"}
                  </td>
                  <td>
                    {tecnica.url ? (
                      <a href={tecnica.url} target="_blank" rel="noreferrer">
                        attack.mitre.org
                      </a>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
        </div>
      ) : null}
      </div>
    </>
  );
}
