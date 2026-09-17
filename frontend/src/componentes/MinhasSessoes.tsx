/**
 * Sessões do próprio utilizador e criação de chaves de ingestão.
 *
 * **Sessões.** Existem para o utilizador poder reconhecer — ou não reconhecer —
 * de onde a sua conta foi usada. Um acesso a partir de um endereço estranho é
 * o primeiro sinal de uma credencial comprometida, e é o dono da conta quem
 * está em melhor posição para o notar. Por isso mostram-se o endereço, o
 * agente e o instante da última utilização, e a sessão actual é assinalada.
 *
 * **Chaves de ingestão.** A chave em claro é devolvida **uma única vez**: a
 * base de dados guarda apenas o hash. A interface avisa-o antes de a mostrar e
 * não a volta a pedir ao servidor, porque não poderia obtê-la.
 */

import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { pedir } from "@/api/cliente";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante } from "@/componentes/comuns";

interface Sessao {
  id: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  ip_address: string | null;
  user_agent: string | null;
  revoked_at: string | null;
}

export function MinhasSessoes() {
  const { data, isPending, error } = useQuery({
    queryKey: ["minhas-sessoes"],
    queryFn: () => pedir<Sessao[]>("/auth/sessions"),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;

  const activas = (data ?? []).filter((s) => !s.revoked_at);
  const terminadas = (data ?? []).filter((s) => s.revoked_at);

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <p className="terciario">
        {activas.length} sessão(ões) activa(s) e {terminadas.length} terminada(s).
        Se não reconhecer um endereço, altere a palavra-passe: isso termina
        todas as outras sessões.
      </p>

      <div className="tabela-envolvente">
        <table className="tabela">
          <thead>
            <tr>
              <th>Iniciada</th>
              <th>Última utilização</th>
              <th>Endereço</th>
              <th>Agente</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            {(data ?? []).slice(0, 25).map((s) => (
              <tr key={s.id}>
                <td className="secundario">{instante(s.created_at)}</td>
                <td className="secundario">
                  {s.last_used_at ? instante(s.last_used_at) : "—"}
                </td>
                <td className="mono secundario">{s.ip_address ?? "—"}</td>
                <td
                  className="terciario truncar"
                  style={{ maxWidth: "28ch" }}
                  title={s.user_agent ?? ""}
                >
                  {s.user_agent ?? "—"}
                </td>
                <td>
                  <span
                    className={`distintivo ${
                      s.revoked_at ? "distintivo--neutro" : "distintivo--sucesso"
                    }`}
                  >
                    {s.revoked_at ? "terminada" : "activa"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const FONTES = [
  { valor: "WAZUH", rotulo: "Wazuh" },
  { valor: "SURICATA", rotulo: "Suricata" },
  { valor: "QRADAR", rotulo: "IBM QRadar" },
  { valor: "NETSCOUT", rotulo: "NetScout" },
  { valor: "API_GENERICA", rotulo: "API genérica" },
];

export function NovaChaveDeIngestao() {
  const { pode } = useSessao();
  const [aberto, definirAberto] = useState(false);
  const [nome, definirNome] = useState("");
  const [fonte, definirFonte] = useState("WAZUH");
  const [descricao, definirDescricao] = useState("");
  const [chave, definirChave] = useState<{ chave: string; prefixo: string } | null>(
    null,
  );

  const criar = useMutation({
    mutationFn: () =>
      pedir<{ chave: string; prefixo: string; aviso: string }>(
        "/integrations/api-keys",
        {
          metodo: "POST",
          corpo: { name: nome, kind: fonte, description: descricao },
        },
      ),
    onSuccess: (r) => {
      definirChave({ chave: r.chave, prefixo: r.prefixo });
      definirNome("");
      definirDescricao("");
    },
  });

  if (!pode("integrations:manage")) return null;

  if (chave) {
    return (
      <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
        <strong>Chave criada</strong>
        <div className="mensagem mensagem--aviso">
          Copie-a agora. A base de dados guarda apenas o hash, pelo que esta
          chave <strong>não pode voltar a ser mostrada</strong>.
        </div>
        <code
          className="mono"
          style={{
            display: "block",
            padding: "var(--espaco-3)",
            background: "var(--contorno-suave)",
            borderRadius: "var(--raio-pequeno)",
            wordBreak: "break-all",
          }}
        >
          {chave.chave}
        </code>
        <p className="terciario">
          Prefixo <span className="mono">{chave.prefixo}</span> — é por ele que a
          chave aparece identificada na lista, sem nunca ser revelada.
        </p>
        <div className="linha" style={{ gap: "var(--espaco-2)" }}>
          <button
            type="button"
            className="botao botao--pequeno"
            onClick={() => {
              void navigator.clipboard?.writeText(chave.chave);
            }}
          >
            Copiar
          </button>
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            onClick={() => {
              definirChave(null);
              definirAberto(false);
            }}
          >
            Já guardei
          </button>
        </div>
      </div>
    );
  }

  if (!aberto) {
    return (
      <div className="linha">
        <button className="botao botao--pequeno" onClick={() => definirAberto(true)}>
          Nova chave de ingestão
        </button>
      </div>
    );
  }

  return (
    <form
      className="cartao pilha"
      style={{ gap: "var(--espaco-3)" }}
      onSubmit={(e) => {
        e.preventDefault();
        criar.mutate();
      }}
    >
      <strong>Nova chave de ingestão</strong>
      <p className="terciario">
        Cada fonte deve ter a sua chave, para que a origem de qualquer evento
        seja atribuível e revogável isoladamente.
      </p>

      <label className="campo">
        <span className="campo__etiqueta">Nome</span>
        <input
          type="text"
          required
          maxLength={80}
          value={nome}
          placeholder="ex.: Wazuh — laboratório"
          onChange={(e) => definirNome(e.target.value)}
        />
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Fonte</span>
        <select
          className="selector"
          value={fonte}
          onChange={(e) => definirFonte(e.target.value)}
        >
          {FONTES.map((f) => (
            <option key={f.valor} value={f.valor}>
              {f.rotulo}
            </option>
          ))}
        </select>
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Descrição</span>
        <input
          type="text"
          maxLength={500}
          value={descricao}
          onChange={(e) => definirDescricao(e.target.value)}
        />
      </label>

      {criar.error ? <Erro erro={criar.error} /> : null}
      <div className="linha" style={{ gap: "var(--espaco-2)" }}>
        <button
          className="botao botao--primario botao--pequeno"
          disabled={criar.isPending || nome.trim().length === 0}
        >
          {criar.isPending ? "A criar…" : "Criar chave"}
        </button>
        <button
          type="button"
          className="botao botao--discreto botao--pequeno"
          onClick={() => definirAberto(false)}
        >
          Cancelar
        </button>
      </div>
    </form>
  );
}
