/**
 * Tarefas e playbooks de um incidente (§19, §14).
 *
 * **Tarefas.** A investigação é uma sequência operacional, não um comentário
 * longo. Cada tarefa tem responsável, estado e — importa insistir — um campo de
 * *resultado*: uma tarefa concluída sem resultado registado não contribui para
 * a reconstituição do incidente no relatório final.
 *
 * As dependências são impostas pelo servidor: concluir uma tarefa que depende
 * de outra por concluir devolve 409. A interface não replica essa verificação,
 * mostra a razão que a API devolve — a regra vive num sítio só.
 *
 * **Playbooks.** Cada sugestão vem acompanhada do motivo pelo qual é aplicável
 * àquele incidente. Um procedimento proposto sem explicação é um procedimento
 * que o analista executa por hábito, e o §14 existe para o contrário.
 *
 * Uma execução que chega a um passo de aprovação **suspende-se** e fica em
 * AGUARDA_APROVACAO. Isso é visível aqui, com a indicação de que a continuação
 * depende de uma decisão na fila de aprovações.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type {
  ExecucaoDePlaybook,
  Pagina,
  SugestaoDePlaybook,
  Tarefa,
  UtilizadorResumo,
} from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, instante, legivel, Vazio } from "@/componentes/comuns";

const ESTADOS_DA_TAREFA = [
  { valor: "PENDENTE", rotulo: "Pendente" },
  { valor: "EM_CURSO", rotulo: "Em curso" },
  { valor: "BLOQUEADA", rotulo: "Bloqueada" },
  { valor: "CONCLUIDA", rotulo: "Concluída" },
  { valor: "CANCELADA", rotulo: "Cancelada" },
];

const PRIORIDADES = [
  { valor: "P1", rotulo: "P1 — urgente" },
  { valor: "P2", rotulo: "P2 — elevada" },
  { valor: "P3", rotulo: "P3 — normal" },
  { valor: "P4", rotulo: "P4 — planeada" },
];

// --------------------------------------------------------------------- tarefas
function NovaTarefa({ incidenteId }: { incidenteId: string }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [aberto, definirAberto] = useState(false);
  const [titulo, definirTitulo] = useState("");
  const [descricao, definirDescricao] = useState("");
  const [prioridade, definirPrioridade] = useState("P3");
  const [responsavel, definirResponsavel] = useState("");

  const utilizadores = useQuery({
    queryKey: ["utilizadores-atribuiveis"],
    queryFn: () =>
      pedir<Pagina<UtilizadorResumo>>(
        `/users${consulta({ apenas_activos: true, size: 200, sort: "full_name" })}`,
      ),
    enabled: aberto && pode("users:read"),
    staleTime: 5 * 60 * 1000,
  });

  const criar = useMutation({
    mutationFn: () =>
      pedir<Tarefa>(`/tasks${consulta({ incident_id: incidenteId })}`, {
        metodo: "POST",
        corpo: {
          title: titulo.trim(),
          description: descricao,
          priority: prioridade,
          ...(responsavel ? { assignee_id: responsavel } : {}),
        },
      }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["tarefas", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidenteId] });
      definirTitulo("");
      definirDescricao("");
      definirAberto(false);
    },
  });

  if (!pode("tasks:manage")) return null;

  if (!aberto) {
    return (
      <div className="linha">
        <button className="botao botao--pequeno" onClick={() => definirAberto(true)}>
          Nova tarefa
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
      <label className="campo">
        <span className="campo__etiqueta">Título</span>
        <input
          type="text"
          required
          minLength={3}
          maxLength={250}
          value={titulo}
          placeholder="O que é preciso fazer."
          onChange={(e) => definirTitulo(e.target.value)}
        />
      </label>

      <label className="campo">
        <span className="campo__etiqueta">Descrição</span>
        <textarea
          className="area-texto"
          value={descricao}
          maxLength={10000}
          onChange={(e) => definirDescricao(e.target.value)}
        />
      </label>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo">
          <span className="campo__etiqueta">Prioridade</span>
          <select
            className="selector"
            value={prioridade}
            onChange={(e) => definirPrioridade(e.target.value)}
          >
            {PRIORIDADES.map((p) => (
              <option key={p.valor} value={p.valor}>
                {p.rotulo}
              </option>
            ))}
          </select>
        </label>
        {pode("users:read") ? (
          <label className="campo">
            <span className="campo__etiqueta">Responsável</span>
            <select
              className="selector"
              value={responsavel}
              onChange={(e) => definirResponsavel(e.target.value)}
            >
              <option value="">— sem responsável —</option>
              {utilizadores.data?.itens.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name}
                </option>
              ))}
            </select>
          </label>
        ) : null}
      </div>

      {criar.error ? <Erro erro={criar.error} /> : null}
      <div className="linha">
        <button className="botao botao--primario botao--pequeno" disabled={criar.isPending}>
          {criar.isPending ? "A criar…" : "Criar tarefa"}
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

function LinhaDaTarefa({ tarefa, incidenteId }: { tarefa: Tarefa; incidenteId: string }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [aberto, definirAberto] = useState(false);
  const [resultado, definirResultado] = useState(tarefa.outcome ?? "");

  const actualizar = useMutation({
    mutationFn: (corpo: Record<string, unknown>) =>
      pedir<Tarefa>(`/tasks/${tarefa.id}`, { metodo: "PATCH", corpo }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["tarefas", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidenteId] });
      definirAberto(false);
    },
  });

  const podeGerir = pode("tasks:manage");
  const concluida = tarefa.status === "CONCLUIDA";

  return (
    <div className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
      <div className="linha linha--espalhada">
        <strong style={{ textDecoration: concluida ? "line-through" : undefined }}>
          {tarefa.title}
        </strong>
        <span className="distintivo distintivo--neutro">{legivel(tarefa.status)}</span>
      </div>

      {tarefa.description ? <p className="secundario">{tarefa.description}</p> : null}

      <div className="linha terciario" style={{ gap: "var(--espaco-4)", flexWrap: "wrap" }}>
        <span>{tarefa.priority}</span>
        <span>{tarefa.assignee?.nome ?? "sem responsável"}</span>
        {tarefa.completed_at ? <span>concluída {instante(tarefa.completed_at)}</span> : null}
      </div>

      {tarefa.outcome ? (
        <p className="secundario">
          <strong>Resultado:</strong> {tarefa.outcome}
        </p>
      ) : null}

      {actualizar.error ? <Erro erro={actualizar.error} /> : null}

      {podeGerir ? (
        aberto ? (
          <form
            className="pilha"
            style={{ gap: "var(--espaco-2)" }}
            onSubmit={(e) => {
              e.preventDefault();
              actualizar.mutate({ status: "CONCLUIDA", outcome: resultado });
            }}
          >
            <label className="campo">
              <span className="campo__etiqueta">Resultado</span>
              <textarea
                className="area-texto"
                value={resultado}
                maxLength={10000}
                placeholder="O que se apurou. Entra no relatório do incidente."
                onChange={(e) => definirResultado(e.target.value)}
              />
            </label>
            <div className="linha">
              <button
                className="botao botao--primario botao--pequeno"
                disabled={actualizar.isPending}
              >
                {actualizar.isPending ? "A concluir…" : "Concluir"}
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
        ) : (
          <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
            <select
              className="selector"
              value={tarefa.status}
              disabled={actualizar.isPending}
              onChange={(e) => {
                // Concluir pede resultado: em vez de o gravar vazio, abre o
                // formulário. Uma tarefa concluída sem resultado não diz nada
                // ao relatório.
                if (e.target.value === "CONCLUIDA") definirAberto(true);
                else actualizar.mutate({ status: e.target.value });
              }}
            >
              {ESTADOS_DA_TAREFA.map((s) => (
                <option key={s.valor} value={s.valor}>
                  {s.rotulo}
                </option>
              ))}
            </select>
          </div>
        )
      ) : null}
    </div>
  );
}

export function Tarefas({ incidenteId }: { incidenteId: string }) {
  const { data, isPending, error } = useQuery({
    queryKey: ["tarefas", incidenteId],
    queryFn: () =>
      pedir<Pagina<Tarefa>>(
        `/tasks${consulta({ incident_id: incidenteId, size: 100, sort: "ordering" })}`,
      ),
  });

  if (isPending) return <Carregando />;
  if (error) return <Erro erro={error} />;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <NovaTarefa incidenteId={incidenteId} />
      {!data || data.itens.length === 0 ? (
        <Vazio
          titulo="Sem tarefas"
          detalhe="As tarefas transformam a investigação numa sequência operacional, com responsável e resultado registados."
        />
      ) : (
        data.itens.map((t) => (
          <LinhaDaTarefa key={t.id} tarefa={t} incidenteId={incidenteId} />
        ))
      )}
    </div>
  );
}

// ------------------------------------------------------------------ playbooks
export function Playbooks({ incidenteId }: { incidenteId: string }) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();

  const sugestoes = useQuery({
    queryKey: ["playbooks-sugeridos", incidenteId],
    queryFn: () =>
      pedir<SugestaoDePlaybook[]>(
        `/playbooks/suggestions${consulta({ incident_id: incidenteId })}`,
      ),
  });

  const execucoes = useQuery({
    queryKey: ["execucoes", incidenteId],
    queryFn: () =>
      pedir<Pagina<ExecucaoDePlaybook>>(
        `/playbooks/executions/list${consulta({ incident_id: incidenteId, size: 50 })}`,
      ),
  });

  const executar = useMutation({
    mutationFn: (playbookId: string) =>
      pedir<ExecucaoDePlaybook>(`/playbooks/${playbookId}/run`, {
        metodo: "POST",
        corpo: { incident_id: incidenteId },
      }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["execucoes", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["accoes", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidenteId] });
    },
  });

  return (
    <div className="pilha" style={{ gap: "var(--espaco-5)" }}>
      <section className="pilha" style={{ gap: "var(--espaco-3)" }}>
        <h3>Playbooks aplicáveis</h3>
        {sugestoes.error ? <Erro erro={sugestoes.error} /> : null}
        {sugestoes.isPending ? (
          <Carregando />
        ) : !sugestoes.data || sugestoes.data.length === 0 ? (
          <p className="terciario">
            Nenhum playbook corresponde à categoria e severidade deste incidente.
          </p>
        ) : (
          sugestoes.data.map(({ playbook, motivo }) => (
            <div key={playbook.id} className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
              <div className="linha linha--espalhada">
                <strong>{playbook.name}</strong>
                <span className="terciario">
                  {playbook.steps.length} passos · v{playbook.version}
                </span>
              </div>
              <p className="secundario">{playbook.description}</p>
              {/* O motivo vem da API: um procedimento proposto sem explicação
                  é um procedimento executado por hábito. */}
              <p className="terciario">{motivo}</p>
              {playbook.success_criteria ? (
                <p className="terciario">
                  <strong>Sucesso:</strong> {playbook.success_criteria}
                </p>
              ) : null}
              {pode("playbooks:execute") ? (
                <div className="linha">
                  <button
                    className="botao botao--primario botao--pequeno"
                    disabled={executar.isPending}
                    onClick={() => executar.mutate(playbook.id)}
                  >
                    {executar.isPending ? "A executar…" : "Executar"}
                  </button>
                </div>
              ) : null}
            </div>
          ))
        )}
        {executar.error ? <Erro erro={executar.error} /> : null}
      </section>

      <section className="pilha" style={{ gap: "var(--espaco-3)" }}>
        <h3>Execuções</h3>
        {execucoes.error ? <Erro erro={execucoes.error} /> : null}
        {execucoes.isPending ? (
          <Carregando />
        ) : !execucoes.data || execucoes.data.itens.length === 0 ? (
          <p className="terciario">Nenhum playbook foi executado sobre este incidente.</p>
        ) : (
          execucoes.data.itens.map((e) => (
            <div key={e.id} className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
              <div className="linha linha--espalhada">
                <span className="mono">{e.reference}</span>
                <span
                  className={`distintivo ${
                    e.status === "CONCLUIDA"
                      ? "distintivo--sucesso"
                      : e.status === "FALHADA"
                        ? "distintivo--perigo"
                        : "distintivo--aviso"
                  }`}
                >
                  {legivel(e.status)}
                </span>
              </div>

              {e.status === "AGUARDA_APROVACAO" ? (
                <div className="mensagem mensagem--aviso">
                  Suspensa à espera de decisão humana. Continua assim que a acção
                  for aprovada em <Link to="/aprovacoes">Aprovações</Link>.
                </div>
              ) : null}

              <ol className="pilha" style={{ gap: 4, paddingLeft: "var(--espaco-5)" }}>
                {e.step_executions.map((p) => (
                  <li key={p.id}>
                    <span className="secundario">{p.step_name}</span>{" "}
                    <span className="terciario">
                      — {p.error ?? p.output?.resumo ?? legivel(p.status)}
                    </span>
                  </li>
                ))}
              </ol>

              {e.error ? <p className="terciario">Erro: {e.error}</p> : null}
            </div>
          ))
        )}
      </section>
    </div>
  );
}
