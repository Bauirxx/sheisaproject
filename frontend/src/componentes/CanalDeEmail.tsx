/**
 * Estado do canal de correio electrónico, e a recolha da caixa (§37).
 *
 * Mostra **configuração** e não disponibilidade. A rota que alimenta isto não
 * contacta o servidor de propósito: apresentar um canal como activo sem o provar
 * é exactamente o que o §4 proíbe, e uma leitura que contactasse o servidor a
 * cada abertura da página passaria a afirmar disponibilidade sem querer.
 *
 * Quem prova é o botão de testar, que envia uma mensagem a sério e mostra o
 * `Message-ID` que o servidor lhe atribuiu — um "ligado" não provaria nada, e o
 * identificador permite encontrar a mensagem no servidor depois.
 *
 * A recolha diz **o que ignorou e porquê**. Uma caixa de segurança recebe muito
 * que não é comunicação de ninguém: respostas automáticas, devoluções de entrega,
 * e o próprio aviso de recepção da plataforma — porque a caixa costuma ser o
 * mesmo endereço que ela usa como remetente. Sem mostrar o motivo, um resultado
 * de "7 lidas, 1 criada" pareceria uma falha em vez do comportamento correcto.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { consulta, pedir } from "@/api/cliente";
import type { EstadoDoCanalDeEmail, ResultadoDaRecolha } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando, Erro, legivel } from "@/componentes/comuns";

export function CanalDeEmail() {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();
  const [destino, definirDestino] = useState("");
  const [aberto, definirAberto] = useState(false);

  const estado = useQuery({
    queryKey: ["canal-de-email"],
    queryFn: () => pedir<EstadoDoCanalDeEmail>("/reports-inbox/canal-de-email"),
  });

  const testar = useMutation({
    mutationFn: () =>
      pedir<{ enviada: boolean; para: string; message_id: string }>(
        `/reports-inbox/canal-de-email/testar${consulta({ destino })}`,
        { metodo: "POST" },
      ),
  });

  const recolher = useMutation({
    mutationFn: () =>
      pedir<ResultadoDaRecolha>("/reports-inbox/recolher-email", { metodo: "POST" }),
    onSuccess: () => clienteDeDados.invalidateQueries({ queryKey: ["comunicacoes"] }),
  });

  const canal = estado.data;
  const podeTriar = pode("reports_inbox:triage");

  if (!aberto) {
    return (
      <div className="linha" style={{ gap: "var(--espaco-2)", flexWrap: "wrap" }}>
        <button
          type="button"
          className="botao botao--discreto botao--pequeno"
          onClick={() => definirAberto(true)}
        >
          Canal de correio electrónico
        </button>
        {podeTriar && canal?.recolha_configurada ? (
          <button
            type="button"
            className="botao botao--pequeno"
            disabled={recolher.isPending}
            onClick={() => recolher.mutate()}
          >
            {recolher.isPending ? "A recolher…" : "Recolher da caixa"}
          </button>
        ) : null}
        {recolher.data ? (
          <span className="terciario">
            {recolher.data.criadas} criada(s) e {recolher.data.ignoradas}{" "}
            ignorada(s) de {recolher.data.lidas} lida(s).
          </span>
        ) : null}
        {recolher.error ? <Erro erro={recolher.error} /> : null}
      </div>
    );
  }

  return (
    <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="linha linha--espalhada">
        <strong>Canal de correio electrónico</strong>
        <button
          type="button"
          className="botao botao--discreto botao--pequeno"
          onClick={() => definirAberto(false)}
        >
          Fechar
        </button>
      </div>

      {estado.error ? <Erro erro={estado.error} /> : null}
      {estado.isPending ? <Carregando /> : null}

      {canal ? (
        <>
          <p className="terciario">
            O que se mostra aqui é <strong>configuração</strong>, não
            disponibilidade — esta leitura não contacta o servidor. Use o teste
            para o provar.
          </p>

          <div className="propriedades">
            <div className="propriedade">
              <span className="propriedade__rotulo">Envio</span>
              <span
                className={`distintivo ${
                  canal.envio_configurado
                    ? "distintivo--sucesso"
                    : "distintivo--neutro"
                }`}
              >
                {canal.envio_configurado ? "configurado" : "não configurado"}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Recolha</span>
              <span
                className={`distintivo ${
                  canal.recolha_configurada
                    ? "distintivo--sucesso"
                    : "distintivo--neutro"
                }`}
              >
                {canal.recolha_configurada ? "configurada" : "não configurada"}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Remetente</span>
              <span className="propriedade__valor mono">
                {canal.remetente ?? "—"}
              </span>
            </div>
            <div className="propriedade">
              <span className="propriedade__rotulo">Caixa lida</span>
              <span className="propriedade__valor mono">{canal.caixa ?? "—"}</span>
            </div>
          </div>

          {canal.variaveis_em_falta.length > 0 ? (
            <div className="mensagem mensagem--aviso">
              Variáveis de ambiente em falta:{" "}
              <span className="mono">{canal.variaveis_em_falta.join(", ")}</span>.
              Sem elas o canal não envia nem recolhe — e nada é apresentado como
              enviado.
            </div>
          ) : null}

          {podeTriar && canal.envio_configurado ? (
            <form
              className="linha"
              style={{
                gap: "var(--espaco-2)",
                flexWrap: "wrap",
                alignItems: "flex-end",
              }}
              onSubmit={(evento) => {
                evento.preventDefault();
                testar.mutate();
              }}
            >
              <label className="campo" style={{ flex: "1 1 16rem" }}>
                <span className="campo__etiqueta">Testar o envio para</span>
                <input
                  type="email"
                  required
                  placeholder="endereco@exemplo.local"
                  value={destino}
                  onChange={(evento) => definirDestino(evento.target.value)}
                />
              </label>
              <button
                className="botao botao--pequeno"
                disabled={testar.isPending || !destino.includes("@")}
              >
                {testar.isPending ? "A enviar…" : "Enviar mensagem de teste"}
              </button>
            </form>
          ) : null}

          {testar.error ? <Erro erro={testar.error} /> : null}
          {testar.data ? (
            <div className="mensagem mensagem--sucesso">
              Enviada para <span className="mono">{testar.data.para}</span>. O
              servidor atribuiu-lhe{" "}
              <span className="mono">{testar.data.message_id}</span> — é por este
              identificador que a mensagem se encontra no servidor.
            </div>
          ) : null}

          {podeTriar && canal.recolha_configurada ? (
            <div className="linha">
              <button
                type="button"
                className="botao botao--primario botao--pequeno"
                disabled={recolher.isPending}
                onClick={() => recolher.mutate()}
              >
                {recolher.isPending ? "A recolher…" : "Recolher da caixa agora"}
              </button>
            </div>
          ) : null}

          {recolher.error ? <Erro erro={recolher.error} /> : null}
          {recolher.data ? (
            <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
              <p className="secundario">
                {recolher.data.lidas} mensagem(ns) lida(s):{" "}
                {recolher.data.criadas} tornou-se comunicação e{" "}
                {recolher.data.ignoradas} foi ignorada. O motivo de cada uma
                aparece abaixo — uma caixa de segurança recebe muito que não é
                comunicação de ninguém.
              </p>
              {recolher.data.resultados.map((linha, indice) => (
                <div
                  key={`${linha.assunto}-${indice}`}
                  className="linha linha--espalhada"
                  style={{ gap: "var(--espaco-2)" }}
                >
                  <span
                    className={`distintivo ${
                      linha.estado === "criada"
                        ? "distintivo--sucesso"
                        : "distintivo--neutro"
                    }`}
                  >
                    {legivel(linha.estado)}
                  </span>
                  <span
                    className="secundario truncar"
                    style={{ maxWidth: "30ch" }}
                    title={linha.assunto}
                  >
                    {linha.assunto}
                  </span>
                  <span
                    className="terciario truncar"
                    style={{ maxWidth: "28ch" }}
                    title={linha.detalhe ?? ""}
                  >
                    {linha.referencia ?? linha.detalhe ?? ""}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
