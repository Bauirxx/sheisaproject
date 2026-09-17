/**
 * Edição de um utilizador e reposição da palavra-passe.
 *
 * Duas operações separadas, de propósito, porque têm consequências diferentes:
 *
 * **Editar** altera nome, perfil, equipa e estado. Desactivar uma conta termina
 * as sessões dela de imediato — sem isso, o token de acesso continuaria válido
 * até expirar, e uma conta desactivada seguiria a funcionar durante meia hora.
 *
 * **Repor a palavra-passe** termina *todas* as sessões e obriga a alterar no
 * primeiro acesso. A palavra-passe é escrita por quem repõe, e por isso passa
 * por um ecrã; marcá-la como "por alterar" é o que impede que fique a servir
 * de segredo permanente.
 *
 * A API impede um administrador de se desactivar a si próprio. A interface
 * antecipa-o desactivando o controlo, mas a regra que conta é a do servidor.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { pedir } from "@/api/cliente";
import type { Equipa, PerfilDetalhado, UtilizadorResumo } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Erro } from "@/componentes/comuns";

export function EditarUtilizador({
  utilizador,
  aoFechar,
}: {
  utilizador: UtilizadorResumo;
  aoFechar: () => void;
}) {
  const clienteDeDados = useQueryClient();
  const { pode, utilizador: eu } = useSessao();

  const [nome, definirNome] = useState(utilizador.full_name);
  const [perfil, definirPerfil] = useState(utilizador.role?.name ?? "");
  const [activo, definirActivo] = useState(utilizador.is_active);
  const [equipa, definirEquipa] = useState(utilizador.team?.id ?? "");

  const [novaSenha, definirNovaSenha] = useState("");
  const [obrigarAlterar, definirObrigarAlterar] = useState(true);
  const [resultadoDaReposicao, definirResultadoDaReposicao] = useState<string | null>(
    null,
  );

  const perfis = useQuery({
    queryKey: ["perfis"],
    queryFn: () => pedir<PerfilDetalhado[]>("/roles"),
    staleTime: 10 * 60 * 1000,
  });

  // As equipas mudam raramente, mas têm de vir do servidor: uma lista fixa no
  // código ficaria desactualizada sem que nada o assinalasse.
  const equipas = useQuery({
    queryKey: ["equipas"],
    queryFn: () => pedir<Equipa[]>("/roles/teams"),
    staleTime: 10 * 60 * 1000,
  });

  const invalidar = () =>
    clienteDeDados.invalidateQueries({ queryKey: ["utilizadores"] });

  function alteracoes(): Record<string, unknown> {
    const m: Record<string, unknown> = {};
    if (nome !== utilizador.full_name) m.full_name = nome;
    if (perfil !== (utilizador.role?.name ?? "")) m.role_name = perfil;
    if (activo !== utilizador.is_active) m.is_active = activo;
    // `null` é o valor que retira o utilizador de qualquer equipa; "" no
    // selector significa exactamente isso e não "sem alteração".
    if (equipa !== (utilizador.team?.id ?? "")) m.team_id = equipa || null;
    return m;
  }

  const guardar = useMutation({
    mutationFn: () =>
      pedir<UtilizadorResumo>(`/users/${utilizador.id}`, {
        metodo: "PATCH",
        corpo: alteracoes(),
      }),
    onSuccess: async () => {
      await invalidar();
      aoFechar();
    },
  });

  const repor = useMutation({
    mutationFn: () =>
      pedir<{ mensagem: string }>(`/users/${utilizador.id}/reset-password`, {
        metodo: "POST",
        corpo: {
          new_password: novaSenha,
          must_change_password: obrigarAlterar,
        },
      }),
    onSuccess: async (r) => {
      definirResultadoDaReposicao(r.mensagem);
      definirNovaSenha("");
      await invalidar();
    },
  });

  if (!pode("users:manage")) return null;

  const porGravar = Object.keys(alteracoes()).length;
  const souEu = eu?.id === utilizador.id;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
      <form
        className="pilha"
        style={{ gap: "var(--espaco-3)" }}
        onSubmit={(e) => {
          e.preventDefault();
          guardar.mutate();
        }}
      >
        <label className="campo">
          <span className="campo__etiqueta">Nome</span>
          <input
            type="text"
            required
            minLength={2}
            maxLength={120}
            value={nome}
            onChange={(e) => definirNome(e.target.value)}
          />
        </label>

        <label className="campo">
          <span className="campo__etiqueta">Perfil</span>
          <select
            className="selector"
            value={perfil}
            onChange={(e) => definirPerfil(e.target.value)}
          >
            {perfis.data?.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
          <span className="campo__ajuda">
            {perfis.data?.find((p) => p.name === perfil)?.description ?? ""}
          </span>
        </label>

        <label className="campo">
          <span className="campo__etiqueta">Equipa</span>
          <select
            className="selector"
            value={equipa}
            onChange={(e) => definirEquipa(e.target.value)}
          >
            <option value="">— sem equipa —</option>
            {(equipas.data ?? [])
              .filter((eq) => eq.is_active || eq.id === utilizador.team?.id)
              .map((eq) => (
                <option key={eq.id} value={eq.id}>
                  {eq.name}
                </option>
              ))}
          </select>
          <span className="campo__ajuda">
            {equipas.data?.find((eq) => eq.id === equipa)?.description ??
              "A equipa determina a quem um incidente pode ser atribuído."}
          </span>
        </label>
        {equipas.error ? <Erro erro={equipas.error} /> : null}

        <label className="linha" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={activo}
            disabled={souEu}
            onChange={(e) => definirActivo(e.target.checked)}
          />
          <span>Conta activa</span>
        </label>
        <p className="terciario">
          {souEu
            ? "Não pode desactivar a sua própria conta."
            : "Desactivar termina de imediato todas as sessões desta conta."}
        </p>

        {guardar.error ? <Erro erro={guardar.error} /> : null}
        <div className="linha" style={{ gap: "var(--espaco-2)" }}>
          <button
            className="botao botao--primario botao--pequeno"
            disabled={guardar.isPending || porGravar === 0}
          >
            {guardar.isPending
              ? "A guardar…"
              : porGravar === 0
                ? "Sem alterações"
                : `Guardar ${porGravar}`}
          </button>
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            onClick={aoFechar}
          >
            Fechar
          </button>
        </div>
      </form>

      <div className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
        <strong>Repor palavra-passe</strong>
        <p className="terciario">
          Termina todas as sessões desta conta. Mínimo 12 caracteres, com
          maiúscula, minúscula e algarismo.
        </p>
        <label className="campo">
          <span className="campo__etiqueta">Nova palavra-passe</span>
          <input
            type="password"
            value={novaSenha}
            minLength={12}
            maxLength={256}
            autoComplete="new-password"
            onChange={(e) => definirNovaSenha(e.target.value)}
          />
        </label>
        <label className="linha" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={obrigarAlterar}
            onChange={(e) => definirObrigarAlterar(e.target.checked)}
          />
          <span>Obrigar a alterar no primeiro acesso</span>
        </label>
        <p className="terciario">
          Recomendado: uma palavra-passe que passou por um ecrã deixou de ser um
          segredo.
        </p>
        {repor.error ? <Erro erro={repor.error} /> : null}
        {resultadoDaReposicao ? (
          <div className="mensagem mensagem--sucesso">{resultadoDaReposicao}</div>
        ) : null}
        <div className="linha">
          <button
            type="button"
            className="botao botao--perigo botao--pequeno"
            disabled={repor.isPending || novaSenha.length < 12}
            onClick={() => repor.mutate()}
          >
            {repor.isPending ? "A repor…" : "Repor palavra-passe"}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Alteração da própria palavra-passe.
 *
 * Distinta da reposição: exige a palavra-passe actual, porque quem a altera é
 * o próprio. As restantes sessões são terminadas — se a alteração foi motivada
 * por suspeita de compromisso, deixar sessões antigas abertas anularia o efeito.
 */
export function AlterarMinhaPalavraPasse() {
  const [aberto, definirAberto] = useState(false);
  const [actual, definirActual] = useState("");
  const [nova, definirNova] = useState("");
  const [confirmacao, definirConfirmacao] = useState("");
  const [resultado, definirResultado] = useState<string | null>(null);

  const alterar = useMutation({
    mutationFn: () =>
      pedir<{ mensagem: string }>("/auth/change-password", {
        metodo: "POST",
        corpo: { current_password: actual, new_password: nova },
      }),
    onSuccess: (r) => {
      definirResultado(r.mensagem);
      definirActual("");
      definirNova("");
      definirConfirmacao("");
    },
  });

  if (!aberto) {
    return (
      <button className="botao botao--pequeno" onClick={() => definirAberto(true)}>
        Alterar a minha palavra-passe
      </button>
    );
  }

  const coincidem = nova.length > 0 && nova === confirmacao;

  return (
    <form
      className="cartao pilha"
      style={{ gap: "var(--espaco-3)", maxWidth: "36rem" }}
      onSubmit={(e) => {
        e.preventDefault();
        alterar.mutate();
      }}
    >
      <strong>Alterar a minha palavra-passe</strong>

      <label className="campo">
        <span className="campo__etiqueta">Palavra-passe actual</span>
        <input
          type="password"
          required
          autoComplete="current-password"
          value={actual}
          onChange={(e) => definirActual(e.target.value)}
        />
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Nova palavra-passe</span>
        <input
          type="password"
          required
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
          value={nova}
          onChange={(e) => definirNova(e.target.value)}
        />
        <span className="campo__ajuda">
          Mínimo 12 caracteres, com maiúscula, minúscula e algarismo.
        </span>
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Confirmar</span>
        <input
          type="password"
          required
          autoComplete="new-password"
          value={confirmacao}
          onChange={(e) => definirConfirmacao(e.target.value)}
        />
        {confirmacao.length > 0 && !coincidem ? (
          <span className="campo__ajuda" style={{ color: "var(--perigo)" }}>
            As palavras-passe não coincidem.
          </span>
        ) : null}
      </label>

      <p className="terciario">
        As restantes sessões são terminadas.
      </p>

      {alterar.error ? <Erro erro={alterar.error} /> : null}
      {resultado ? (
        <div className="mensagem mensagem--sucesso">{resultado}</div>
      ) : null}

      <div className="linha" style={{ gap: "var(--espaco-2)" }}>
        <button
          className="botao botao--primario botao--pequeno"
          disabled={alterar.isPending || !coincidem || actual.length === 0}
        >
          {alterar.isPending ? "A alterar…" : "Alterar"}
        </button>
        <button
          type="button"
          className="botao botao--discreto botao--pequeno"
          onClick={() => definirAberto(false)}
        >
          Fechar
        </button>
      </div>
    </form>
  );
}
