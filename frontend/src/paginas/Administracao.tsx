/**
 * Administração: utilizadores, perfis e playbooks (§4.5.5 · RF02, RF03).
 *
 * A lista de permissões de cada perfil é mostrada por inteiro, e não resumida a
 * uma contagem. Quem administra precisa de poder responder à pergunta "o que é
 * que este perfil pode fazer?" sem consultar documentação — e um número ("23
 * permissões") não responde a isso.
 *
 * As permissões vêm da base de dados, não de uma constante do cliente: são as
 * mesmas que o servidor consulta a cada pedido para autorizar.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { consulta, pedir } from "@/api/cliente";
import type {
  Pagina,
  PerfilDetalhado,
  UtilizadorResumo,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import {
  AlterarMinhaPalavraPasse,
  EditarUtilizador,
} from "@/componentes/EditarUtilizador";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";
import { CampoDeSelecao, Paginacao, useFiltros } from "@/componentes/listagem";

interface Playbook {
  id: string;
  name: string;
  description: string;
  is_enabled: boolean;
  version: number;
  auto_execute: boolean;
  trigger_category: string | null;
  trigger_min_severity: string;
  execution_count: number;
  success_count: number;
  last_executed_at: string | null;
  steps: { id: string; ordering: number; name: string; step_type: string }[];
}

type Aba = "utilizadores" | "perfis" | "playbooks";

function NovoUtilizador({ aoCriar }: { aoCriar: () => void }) {
  const [aberto, definirAberto] = useState(false);
  const [email, definirEmail] = useState("");
  const [nome, definirNome] = useState("");
  const [palavraPasse, definirPalavraPasse] = useState("");
  const [perfil, definirPerfil] = useState("ANALISTA_SOC");

  const { data: perfis } = useQuery({
    queryKey: ["perfis"],
    queryFn: () => pedir<PerfilDetalhado[]>("/roles"),
  });

  const criar = useMutation({
    mutationFn: () =>
      pedir("/users", {
        metodo: "POST",
        corpo: {
          email: email.trim(),
          full_name: nome.trim(),
          password: palavraPasse,
          role_name: perfil,
          must_change_password: true,
        },
      }),
    onSuccess: () => {
      definirAberto(false);
      definirEmail("");
      definirNome("");
      definirPalavraPasse("");
      aoCriar();
    },
  });

  if (!aberto) {
    return (
      <button
        type="button"
        className="botao botao--primario"
        onClick={() => definirAberto(true)}
      >
        Criar utilizador
      </button>
    );
  }

  const submeter = (evento: FormEvent) => {
    evento.preventDefault();
    criar.mutate();
  };

  return (
    <form className="cartao pilha" onSubmit={submeter} style={{ maxWidth: "560px" }}>
      <h3>Novo utilizador</h3>
      <div className="grelha grelha--2">
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="novo-email">
            Endereço
          </label>
          <input
            id="novo-email"
            className="entrada"
            type="email"
            required
            value={email}
            onChange={(e) => definirEmail(e.target.value)}
          />
        </div>
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="novo-nome">
            Nome
          </label>
          <input
            id="novo-nome"
            className="entrada"
            required
            minLength={2}
            value={nome}
            onChange={(e) => definirNome(e.target.value)}
          />
        </div>
      </div>
      <div className="grelha grelha--2">
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="nova-senha">
            Palavra-passe inicial
          </label>
          <input
            id="nova-senha"
            className="entrada"
            type="password"
            required
            value={palavraPasse}
            onChange={(e) => definirPalavraPasse(e.target.value)}
          />
          <span className="campo__ajuda">
            Mínimo 12 caracteres, com minúscula, maiúscula e algarismo. Terá de
            ser alterada no primeiro acesso.
          </span>
        </div>
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="novo-perfil">
            Perfil
          </label>
          <select
            id="novo-perfil"
            className="selector"
            value={perfil}
            onChange={(e) => definirPerfil(e.target.value)}
          >
            {perfis?.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
      </div>
      {criar.error ? <Erro erro={criar.error} /> : null}
      <div className="linha">
        <button type="submit" className="botao botao--primario" disabled={criar.isPending}>
          {criar.isPending ? "A criar…" : "Criar"}
        </button>
        <button
          type="button"
          className="botao botao--discreto"
          onClick={() => definirAberto(false)}
        >
          Cancelar
        </button>
      </div>
    </form>
  );
}

function Utilizadores() {
  const [aEditar, definirAEditar] = useState<UtilizadorResumo | null>(null);
  const { ler, definir } = useFiltros();
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();

  const parametros = {
    q: ler("q"),
    perfil: ler("perfil"),
    page: ler("page", "1"),
    size: "25",
  };

  const { data, isPending, error } = useQuery({
    queryKey: ["utilizadores", parametros],
    queryFn: () => pedir<Pagina<UtilizadorResumo>>(`/users${consulta(parametros)}`),
  });

  const { data: perfis } = useQuery({
    queryKey: ["perfis"],
    queryFn: () => pedir<PerfilDetalhado[]>("/roles"),
  });

  return (
    <div className="pilha">
      {pode("users:manage") ? (
        <NovoUtilizador
          aoCriar={() => clienteDeDados.invalidateQueries({ queryKey: ["utilizadores"] })}
        />
      ) : null}

      <div className="filtros">
        <div className="campo campo--pesquisa">
          <label className="campo__etiqueta" htmlFor="pesquisa-utilizador">
            Pesquisa
          </label>
          <input
            id="pesquisa-utilizador"
            className="entrada"
            type="search"
            placeholder="Nome ou endereço…"
            value={ler("q")}
            onChange={(e) => definir({ q: e.target.value })}
          />
        </div>
        {perfis ? (
          <CampoDeSelecao
            etiqueta="Perfil"
            valor={ler("perfil")}
            opcoes={perfis.map((p) => ({ valor: p.name, rotulo: p.name }))}
            aoMudar={(v) => definir({ perfil: v })}
          />
        ) : null}
      </div>

      {error ? <Erro erro={error} /> : null}
      {isPending ? (
        <Carregando />
      ) : data ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Nome</th>
                <th>Endereço</th>
                <th>Perfil</th>
                <th>Estado</th>
                <th>Último acesso</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.itens.map((utilizador) => (
                <tr key={utilizador.id}>
                  <td>{utilizador.full_name}</td>
                  <td className="secundario mono">{utilizador.email}</td>
                  <td className="secundario">{utilizador.role?.name ?? "—"}</td>
                  <td>
                    <span
                      className={`distintivo ${
                        utilizador.is_active ? "distintivo--sucesso" : "distintivo--neutro"
                      }`}
                    >
                      {utilizador.is_active ? "activo" : "desactivado"}
                    </span>
                    {utilizador.must_change_password ? (
                      <span
                        className="distintivo distintivo--aviso"
                        style={{ marginLeft: "var(--espaco-2)" }}
                      >
                        senha por alterar
                      </span>
                    ) : null}
                  </td>
                  <td className="secundario">{instante(utilizador.last_login_at)}</td>
                  <td>
                    {pode("users:manage") ? (
                      <button
                        type="button"
                        className="botao botao--pequeno"
                        onClick={() => definirAEditar(utilizador)}
                      >
                        Editar
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Paginacao pagina={data} aoMudar={(n) => definir({ page: n })} />
        </div>
      ) : null}

      <div className="separador" style={{ margin: "var(--espaco-5) 0" }} />
      <AlterarMinhaPalavraPasse />

      {aEditar ? (
        <div
          className="sobreposicao"
          role="dialog"
          aria-modal="true"
          aria-label={`Editar ${aEditar.full_name}`}
          onClick={() => definirAEditar(null)}
        >
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <div className="linha linha--espalhada" style={{ marginBottom: "var(--espaco-4)" }}>
              <div className="pilha" style={{ gap: 0 }}>
                <h2>Editar utilizador</h2>
                <span className="terciario mono">{aEditar.email}</span>
              </div>
              <button
                type="button"
                className="botao botao--discreto"
                onClick={() => definirAEditar(null)}
              >
                Fechar
              </button>
            </div>
            <EditarUtilizador
              key={aEditar.id}
              utilizador={aEditar}
              aoFechar={() => definirAEditar(null)}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function Perfis() {
  const { data, isPending, error } = useQuery({
    queryKey: ["perfis"],
    queryFn: () => pedir<PerfilDetalhado[]>("/roles"),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;

  return (
    <div className="pilha">
      <p className="secundario">
        As permissões abaixo são as que o servidor consulta a cada pedido para
        autorizar. Esconder uma opção na interface não impede ninguém de chamar a
        API directamente — é esta lista que decide.
      </p>
      {data?.map((perfil) => (
        <div key={perfil.id} className="cartao pilha">
          <div className="linha linha--espalhada">
            <div className="pilha" style={{ gap: 2 }}>
              <strong>{perfil.name}</strong>
              <span className="secundario">{perfil.description}</span>
            </div>
            <span className="distintivo distintivo--neutro">
              {perfil.permissions.length} permissões
            </span>
          </div>
          <div className="linha" style={{ flexWrap: "wrap", gap: "var(--espaco-2)" }}>
            {perfil.permissions
              .slice()
              .sort((a, b) => a.code.localeCompare(b.code))
              .map((permissao) => (
                <span
                  key={permissao.code}
                  className="distintivo distintivo--neutro mono"
                  title={permissao.description}
                >
                  {permissao.code}
                </span>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ListaDePlaybooks() {
  const { data, isPending, error } = useQuery({
    queryKey: ["playbooks"],
    queryFn: () => pedir<Playbook[]>("/playbooks"),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;
  if (!data || data.length === 0) {
    return <Vazio titulo="Sem playbooks definidos" />;
  }

  return (
    <div className="pilha">
      {data.map((playbook) => (
        <div key={playbook.id} className="cartao pilha">
          <div className="linha linha--espalhada">
            <div className="pilha" style={{ gap: 2 }}>
              <div className="linha" style={{ gap: "var(--espaco-2)" }}>
                <strong>{playbook.name}</strong>
                <span className="terciario">v{playbook.version}</span>
                <span
                  className={`distintivo ${
                    playbook.is_enabled ? "distintivo--sucesso" : "distintivo--neutro"
                  }`}
                >
                  {playbook.is_enabled ? "activo" : "desactivado"}
                </span>
                {playbook.auto_execute ? (
                  <span className="distintivo distintivo--aviso">automático</span>
                ) : null}
              </div>
              <span className="secundario">{playbook.description}</span>
            </div>
            <span className="terciario">
              {playbook.execution_count} execuções
              {playbook.last_executed_at
                ? ` · última ${instante(playbook.last_executed_at)}`
                : ""}
            </span>
          </div>

          <div className="terciario">
            Gatilho: severidade mínima {legivel(playbook.trigger_min_severity)}
            {playbook.trigger_category
              ? ` · categoria ${legivel(playbook.trigger_category)}`
              : " · qualquer categoria"}
          </div>

          <div className="pilha" style={{ gap: "var(--espaco-1)" }}>
            {playbook.steps
              .slice()
              .sort((a, b) => a.ordering - b.ordering)
              .map((passo) => (
                <div key={passo.id} className="linha" style={{ gap: "var(--espaco-3)" }}>
                  <span className="mono terciario" style={{ width: "20px" }}>
                    {passo.ordering}
                  </span>
                  <span>{passo.name}</span>
                  <span className="terciario">{legivel(passo.step_type)}</span>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Página própria dos playbooks.
 *
 * Separada da administração de propósito: `playbooks:read` e `users:read` são
 * permissões distintas, e um analista que tem a primeira e não a segunda veria
 * a listagem de utilizadores a falhar por trás dos separadores.
 */
export function PaginaDePlaybooks() {
  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Playbooks</h1>
          <p className="pagina__descricao">
            Procedimentos de resposta. A execução suspende nos passos que
            exigem aprovação e retoma quando a decisão for registada — a
            automação não contorna o controlo humano.
          </p>
        </div>
      </div>
      <ListaDePlaybooks />
    </>
  );
}

export function Administracao() {
  const { pode } = useSessao();

  // Só se mostram os separadores que o perfil pode consultar: um separador que
  // abre numa consulta recusada ensina o utilizador a desconfiar da interface.
  const abasVisiveis = (
    [
      ["utilizadores", "Utilizadores"],
      ["perfis", "Perfis e permissões"],
      ["playbooks", "Playbooks"],
    ] as [Aba, string][]
  ).filter(([chave]) => {
    if (chave === "utilizadores") return pode("users:read");
    if (chave === "perfis") return pode("roles:manage") || pode("users:read");
    return pode("playbooks:read");
  });

  const [aba, definirAba] = useState<Aba>(abasVisiveis[0]?.[0] ?? "playbooks");

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Administração</h1>
          <p className="pagina__descricao">
            Contas, perfis de acesso e procedimentos de resposta.
          </p>
        </div>
      </div>

      <div className="separadores" role="tablist">
        {abasVisiveis.map(([chave, rotulo]) => (
          <button
            key={chave}
            type="button"
            role="tab"
            aria-selected={aba === chave}
            className={`separador${aba === chave ? " separador--activo" : ""}`}
            onClick={() => definirAba(chave)}
          >
            {rotulo}
          </button>
        ))}
      </div>

      {aba === "utilizadores" ? <Utilizadores /> : null}
      {aba === "perfis" ? <Perfis /> : null}
      {aba === "playbooks" ? <ListaDePlaybooks /> : null}
    </>
  );
}
