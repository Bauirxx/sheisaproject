/**
 * Equipas — os grupos de triagem e resposta.
 *
 * Um incidente é entregue a um responsável *e* a uma equipa. Ao atribuir ou
 * escalar para uma equipa, os membros activos são avisados na plataforma e por
 * email, pelo que esta é a lista que decide quem é chamado. Cada pessoa
 * pertence a uma equipa de cada vez: juntá-la a outra tira-a da anterior.
 *
 * Equipas não se apagam, desactivam-se — incidentes antigos continuam a apontar
 * para elas, e uma equipa desactivada deixa de poder receber incidentes.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { consulta, pedir } from "@/api/cliente";
import type { EquipaDetalhe, EquipaResumo, Pagina, UtilizadorResumo } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, Vazio } from "@/componentes/comuns";

function NovaEquipa({ aoCriar }: { aoCriar: () => void }) {
  const [aberto, definirAberto] = useState(false);
  const [nome, definirNome] = useState("");
  const [descricao, definirDescricao] = useState("");

  const criar = useMutation({
    mutationFn: () =>
      pedir<EquipaDetalhe>("/teams", {
        metodo: "POST",
        corpo: { name: nome.trim(), description: descricao.trim() },
      }),
    onSuccess: () => {
      definirAberto(false);
      definirNome("");
      definirDescricao("");
      aoCriar();
    },
  });

  if (!aberto) {
    return (
      <button type="button" className="botao botao--primario" onClick={() => definirAberto(true)}>
        Criar equipa
      </button>
    );
  }

  const submeter = (evento: FormEvent) => {
    evento.preventDefault();
    criar.mutate();
  };

  return (
    <form className="cartao pilha" onSubmit={submeter} style={{ maxWidth: "560px" }}>
      <h3>Nova equipa</h3>
      <div className="campo">
        <label className="campo__etiqueta" htmlFor="equipa-nome">Nome</label>
        <input
          id="equipa-nome"
          className="entrada"
          value={nome}
          onChange={(e) => definirNome(e.target.value)}
          placeholder="Ex.: Triagem N1"
          required
          minLength={2}
          maxLength={80}
        />
      </div>
      <div className="campo">
        <label className="campo__etiqueta" htmlFor="equipa-descricao">Descrição</label>
        <textarea
          id="equipa-descricao"
          className="area-texto"
          value={descricao}
          onChange={(e) => definirDescricao(e.target.value)}
          placeholder="O que esta equipa trata, e em que turno."
          maxLength={2000}
        />
      </div>
      {criar.error ? <Erro erro={criar.error} /> : null}
      <div className="linha">
        <button type="submit" className="botao botao--primario" disabled={criar.isPending}>
          {criar.isPending ? "A criar…" : "Criar"}
        </button>
        <button type="button" className="botao botao--discreto" onClick={() => definirAberto(false)}>
          Cancelar
        </button>
      </div>
    </form>
  );
}

function GerirEquipa({ equipaId, aoFechar }: { equipaId: string; aoFechar: () => void }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const podeGerir = pode("users:manage");
  const [aJuntar, definirAJuntar] = useState("");

  const equipa = useQuery({
    queryKey: ["equipa", equipaId],
    queryFn: () => pedir<EquipaDetalhe>(`/teams/${equipaId}`),
  });

  const utilizadores = useQuery({
    queryKey: ["utilizadores-activos"],
    queryFn: () =>
      pedir<Pagina<UtilizadorResumo>>(
        `/users${consulta({ apenas_activos: true, size: 200, sort: "full_name" })}`,
      ),
    enabled: podeGerir,
  });

  const actualizar = async (detalhe: EquipaDetalhe) => {
    clienteDeDados.setQueryData(["equipa", equipaId], detalhe);
    await clienteDeDados.invalidateQueries({ queryKey: ["equipas"] });
    await clienteDeDados.invalidateQueries({ queryKey: ["utilizadores"] });
    await clienteDeDados.invalidateQueries({ queryKey: ["utilizadores-activos"] });
  };

  const juntar = useMutation({
    mutationFn: (userId: string) =>
      pedir<EquipaDetalhe>(`/teams/${equipaId}/members`, {
        metodo: "POST",
        corpo: { user_id: userId },
      }),
    onSuccess: async (detalhe) => {
      definirAJuntar("");
      await actualizar(detalhe);
    },
  });

  const retirar = useMutation({
    mutationFn: (userId: string) =>
      pedir<EquipaDetalhe>(`/teams/${equipaId}/members/${userId}`, { metodo: "DELETE" }),
    onSuccess: actualizar,
  });

  const alternarActiva = useMutation({
    mutationFn: (activa: boolean) =>
      pedir<EquipaDetalhe>(`/teams/${equipaId}`, {
        metodo: "PATCH",
        corpo: { is_active: activa },
      }),
    onSuccess: actualizar,
  });

  if (equipa.isPending) return <Carregando />;
  if (equipa.error) return <Erro erro={equipa.error} />;
  const dados = equipa.data;
  const membros = new Set(dados.membros.map((m) => m.id));
  const candidatos = (utilizadores.data?.itens ?? []).filter((u) => !membros.has(u.id));

  return (
    <div className="pilha">
      <div className="linha linha--espalhada">
        <div className="pilha" style={{ gap: 0 }}>
          <h3>{dados.name}</h3>
          <span className="secundario">{dados.description || "Sem descrição."}</span>
        </div>
        <button type="button" className="botao botao--discreto" onClick={aoFechar}>
          Fechar
        </button>
      </div>

      <div className="linha">
        <span className={`distintivo ${dados.is_active ? "distintivo--sucesso" : "distintivo--neutro"}`}>
          {dados.is_active ? "Activa" : "Desactivada"}
        </span>
        {podeGerir ? (
          <button
            type="button"
            className="botao botao--pequeno"
            disabled={alternarActiva.isPending}
            onClick={() => alternarActiva.mutate(!dados.is_active)}
          >
            {dados.is_active ? "Desactivar equipa" : "Reactivar equipa"}
          </button>
        ) : null}
      </div>
      {alternarActiva.error ? <Erro erro={alternarActiva.error} /> : null}
      {!dados.is_active ? (
        <p className="terciario">
          Uma equipa desactivada não recebe incidentes nem novos membros.
        </p>
      ) : null}

      <h4>Membros ({dados.membros.length})</h4>
      <p className="terciario">
        Os membros activos recebem, na plataforma e por email, os incidentes
        atribuídos ou escalados para esta equipa.
      </p>
      {dados.membros.length === 0 ? (
        <Vazio titulo="Sem membros" detalhe="Junte analistas à equipa para que possam ser chamados." />
      ) : (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Nome</th>
                <th>Email</th>
                <th>Perfil</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {dados.membros.map((membro) => (
                <tr key={membro.id}>
                  <td>
                    {membro.full_name}{" "}
                    {!membro.is_active ? (
                      <span className="distintivo distintivo--aviso">conta desactivada</span>
                    ) : null}
                  </td>
                  <td className="secundario mono">{membro.email}</td>
                  <td className="secundario">{membro.role.name}</td>
                  <td>
                    {podeGerir ? (
                      <button
                        type="button"
                        className="botao botao--pequeno botao--discreto"
                        disabled={retirar.isPending}
                        onClick={() => retirar.mutate(membro.id)}
                      >
                        Retirar
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {retirar.error ? <Erro erro={retirar.error} /> : null}

      {podeGerir && dados.is_active ? (
        <div className="campo">
          <label className="campo__etiqueta" htmlFor="juntar-membro">Juntar membro</label>
          <div className="linha">
            <select
              id="juntar-membro"
              className="selector"
              value={aJuntar}
              onChange={(e) => definirAJuntar(e.target.value)}
              disabled={utilizadores.isPending || juntar.isPending}
            >
              <option value="">— escolher utilizador —</option>
              {candidatos.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name} ({u.role?.name ?? "?"}){u.team ? ` — sai de ${u.team.name}` : ""}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="botao botao--primario botao--pequeno"
              disabled={!aJuntar || juntar.isPending}
              onClick={() => juntar.mutate(aJuntar)}
            >
              {juntar.isPending ? "A juntar…" : "Juntar"}
            </button>
          </div>
          <span className="campo__ajuda">
            Quem já pertence a outra equipa sai dela — cada pessoa está numa equipa de cada vez.
          </span>
          {juntar.error ? <Erro erro={juntar.error} /> : null}
          {utilizadores.error ? <Erro erro={utilizadores.error} /> : null}
        </div>
      ) : null}
    </div>
  );
}

export function Equipas() {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [aGerir, definirAGerir] = useState<string | null>(null);

  const equipas = useQuery({
    queryKey: ["equipas"],
    queryFn: () => pedir<EquipaResumo[]>("/teams"),
  });

  return (
    <div className="pilha">
      <p className="secundario">
        Grupos de triagem e resposta. Atribuir ou escalar um incidente para uma
        equipa avisa todos os seus membros activos, na plataforma e por email.
      </p>
      {pode("users:manage") ? (
        <NovaEquipa aoCriar={() => clienteDeDados.invalidateQueries({ queryKey: ["equipas"] })} />
      ) : null}

      {equipas.isPending ? <Carregando /> : null}
      {equipas.error ? <Erro erro={equipas.error} /> : null}
      {equipas.data && equipas.data.length === 0 ? (
        <Vazio titulo="Ainda não há equipas" detalhe="Crie a primeira para começar a distribuir incidentes." />
      ) : null}
      {equipas.data && equipas.data.length > 0 ? (
        <div className="tabela-envolvente">
          <table className="tabela">
            <thead>
              <tr>
                <th>Equipa</th>
                <th>Descrição</th>
                <th>Membros activos</th>
                <th>Estado</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {equipas.data.map((equipa) => (
                <tr key={equipa.id}>
                  <td>{equipa.name}</td>
                  <td className="secundario">{equipa.description || "—"}</td>
                  <td>{equipa.total_membros}</td>
                  <td>
                    <span
                      className={`distintivo ${equipa.is_active ? "distintivo--sucesso" : "distintivo--neutro"}`}
                    >
                      {equipa.is_active ? "Activa" : "Desactivada"}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="botao botao--pequeno"
                      onClick={() => definirAGerir(equipa.id)}
                    >
                      Gerir
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {aGerir ? (
        <div className="sobreposicao" onClick={() => definirAGerir(null)}>
          <div className="painel-lateral" onClick={(e) => e.stopPropagation()}>
            <GerirEquipa equipaId={aGerir} aoFechar={() => definirAGerir(null)} />
          </div>
        </div>
      ) : null}
    </div>
  );
}
