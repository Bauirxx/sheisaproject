/**
 * Integrações (§26) e notificações.
 *
 * Esta página existe sobretudo para tornar visível uma regra que atravessa a
 * plataforma: **uma integração só aparece como activa depois de o ter
 * provado.** O estado vem do servidor e reflecte verificação real — um teste de
 * ligação bem-sucedido ou tráfego efectivamente recebido. Declarar credenciais
 * coloca-a em CONFIGURADA, não em ACTIVA.
 *
 * Por isso a página mostra, para cada integração, três coisas que normalmente
 * ficariam escondidas: as variáveis de ambiente em falta, o resultado da última
 * verificação e a contagem de eventos recebidos. É o que permite distinguir
 * "não configurada" de "configurada mas nunca testada" de "a funcionar".
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { pedir } from "@/api/cliente";
import type { Integracao, Notificacao } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";
import { NovaChaveDeIngestao } from "@/componentes/MinhasSessoes";

const ASPECTO_DO_ESTADO: Record<string, string> = {
  ACTIVA: "distintivo--sucesso",
  CONFIGURADA: "distintivo--aviso",
  NAO_CONFIGURADA: "distintivo--neutro",
  ERRO: "distintivo--perigo",
  DESACTIVADA: "distintivo--neutro",
};

/** O que cada estado significa, em vez de deixar o utilizador adivinhar. */
const EXPLICACAO_DO_ESTADO: Record<string, string> = {
  ACTIVA: "Verificada: respondeu a um teste de ligação ou recebeu eventos reais.",
  CONFIGURADA: "Tem credenciais, mas a ligação ainda não foi confirmada.",
  NAO_CONFIGURADA: "Faltam credenciais. Não recebe nem executa nada.",
  ERRO: "A última tentativa de contacto falhou.",
  DESACTIVADA: "Desligada manualmente.",
};

function CartaoDeIntegracao({ integracao }: { integracao: Integracao }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [resultado, definirResultado] = useState<string | null>(null);

  const testar = useMutation({
    mutationFn: () =>
      pedir<{ sucesso: boolean; estado: string; detalhe: string }>(
        `/integrations/${integracao.id}/test`,
        { metodo: "POST" },
      ),
    onSuccess: async (r) => {
      definirResultado(`${r.sucesso ? "✓" : "✗"} ${r.detalhe}`);
      await clienteDeDados.invalidateQueries({ queryKey: ["integracoes"] });
    },
  });

  const emFalta = integracao.variaveis_em_falta ?? [];

  return (
    <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="linha linha--espalhada">
        <div>
          <strong>{integracao.name}</strong>{" "}
          <span className="terciario mono">{integracao.kind}</span>
        </div>
        <span
          className={`distintivo ${ASPECTO_DO_ESTADO[integracao.status] ?? "distintivo--neutro"}`}
          title={EXPLICACAO_DO_ESTADO[integracao.status] ?? ""}
        >
          {legivel(integracao.status)}
        </span>
      </div>

      <p className="secundario">{integracao.description}</p>
      <p className="terciario">{EXPLICACAO_DO_ESTADO[integracao.status]}</p>

      <div className="propriedades">
        <div className="propriedade">
          <span className="propriedade__rotulo">Direcção</span>
          <span className="propriedade__valor">{legivel(integracao.direction)}</span>
        </div>
        <div className="propriedade">
          <span className="propriedade__rotulo">Eventos recebidos</span>
          <span className="propriedade__valor mono">{integracao.events_received}</span>
        </div>
        <div className="propriedade">
          <span className="propriedade__rotulo">Último evento</span>
          <span className="propriedade__valor">
            {integracao.last_event_at ? instante(integracao.last_event_at) : "—"}
          </span>
        </div>
        <div className="propriedade">
          <span className="propriedade__rotulo">Acções executadas</span>
          <span className="propriedade__valor mono">
            {integracao.actions_executed} ({integracao.actions_failed} falhadas)
          </span>
        </div>
        <div className="propriedade">
          <span className="propriedade__rotulo">Última verificação</span>
          <span className="propriedade__valor">
            {integracao.last_check_at ? instante(integracao.last_check_at) : "nunca"}
          </span>
        </div>
        <div className="propriedade">
          <span className="propriedade__rotulo">Chaves activas</span>
          <span className="propriedade__valor mono">{integracao.chaves_activas}</span>
        </div>
      </div>

      {emFalta.length > 0 ? (
        <div className="mensagem mensagem--aviso">
          Variáveis de ambiente em falta:{" "}
          <span className="mono">{emFalta.join(", ")}</span>. Sem elas a
          integração não pode ser verificada nem executar acções.
        </div>
      ) : null}

      {integracao.last_check_detail ? (
        <p className="terciario">
          Última verificação: {integracao.last_check_detail}
        </p>
      ) : null}

      {integracao.supported_actions?.length ? (
        <p className="terciario">
          Executa: {integracao.supported_actions.map(legivel).join(", ")}.
        </p>
      ) : null}

      {resultado ? <p className="secundario">{resultado}</p> : null}
      {testar.error ? <Erro erro={testar.error} /> : null}

      {pode("integrations:manage") ? (
        <div className="linha">
          <button
            type="button"
            className="botao botao--pequeno"
            disabled={testar.isPending}
            onClick={() => testar.mutate()}
          >
            {testar.isPending ? "A contactar…" : "Testar ligação"}
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function Integracoes() {
  const { data, isPending, error } = useQuery({
    queryKey: ["integracoes"],
    queryFn: () => pedir<Integracao[]>("/integrations"),
  });

  return (
    <div className="pilha">
      <header className="pagina__cabecalho">
        <div>
          <h1 className="pagina__titulo">Integrações</h1>
          <p className="pagina__descricao">
            Fontes de detecção e sistemas de resposta. O estado reflecte
            verificação real: uma integração só aparece como activa depois de
            responder a um teste de ligação ou de ter recebido eventos.
          </p>
        </div>
      </header>

      <NovaChaveDeIngestao />

      {error ? <Erro erro={error} /> : null}
      {isPending ? (
        <Carregando />
      ) : !data || data.length === 0 ? (
        <Vazio titulo="Nenhuma integração registada" />
      ) : (
        <div className="grelha grelha--2">
          {data.map((i) => (
            <CartaoDeIntegracao key={i.id} integracao={i} />
          ))}
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------- notificações
export function Notificacoes() {
  const clienteDeDados = useQueryClient();
  const [apenasPorLer, definirApenasPorLer] = useState(false);

  const { data, isPending, error } = useQuery({
    queryKey: ["notificacoes", apenasPorLer],
    queryFn: () =>
      pedir<Notificacao[]>(
        `/notifications${apenasPorLer ? "?apenas_nao_lidas=true" : ""}`,
      ),
  });

  const marcar = useMutation({
    mutationFn: (id: string) =>
      pedir(`/notifications/${id}/read`, { metodo: "POST" }),
    onSuccess: () =>
      clienteDeDados.invalidateQueries({ queryKey: ["notificacoes"] }),
  });

  return (
    <div className="pilha">
      <header className="pagina__cabecalho">
        <div>
          <h1 className="pagina__titulo">Notificações</h1>
          <p className="pagina__descricao">
            Avisos dirigidos a si: aprovações pendentes, incidentes atribuídos e
            resultados de acções.
          </p>
        </div>
        <div className="pagina__accoes">
          <button
            type="button"
            className={`botao botao--pequeno${apenasPorLer ? " botao--primario" : ""}`}
            onClick={() => definirApenasPorLer((v) => !v)}
          >
            {apenasPorLer ? "A mostrar só por ler" : "Mostrar só por ler"}
          </button>
        </div>
      </header>

      {error ? <Erro erro={error} /> : null}
      {isPending ? (
        <Carregando />
      ) : !data || data.length === 0 ? (
        <Vazio
          titulo="Sem notificações"
          detalhe={
            apenasPorLer
              ? "Não há notificações por ler."
              : "Ainda não recebeu notificações."
          }
        />
      ) : (
        <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
          {data.map((n) => (
            <div
              key={n.id}
              className="cartao"
              style={{ opacity: n.read_at ? 0.6 : 1 }}
            >
              <div className="linha linha--espalhada">
                <strong>{n.title}</strong>
                <span className="terciario">{instante(n.created_at)}</span>
              </div>
              <p className="secundario" style={{ marginTop: "var(--espaco-2)" }}>
                {n.body}
              </p>
              <div
                className="linha linha--espalhada"
                style={{ marginTop: "var(--espaco-3)" }}
              >
                <span className="terciario mono">
                  {legivel(n.kind)}
                  {n.resource_reference ? ` · ${n.resource_reference}` : ""}
                </span>
                {n.read_at ? (
                  <span className="terciario">Lida</span>
                ) : (
                  <button
                    type="button"
                    className="botao botao--pequeno"
                    disabled={marcar.isPending}
                    onClick={() => marcar.mutate(n.id)}
                  >
                    Marcar como lida
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
