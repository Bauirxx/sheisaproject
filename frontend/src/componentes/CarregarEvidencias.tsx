/**
 * Zona de carregamento de evidências (§15).
 *
 * Aceita arrastar-e-largar e escolha manual, vários ficheiros de uma vez, e
 * mostra miniatura das imagens antes de enviar. Não é enfeite: quem recolhe
 * uma captura de ecrã de um posto comprometido precisa de confirmar que
 * arrastou a captura certa antes de a anexar a um processo que vai ser lido
 * por terceiros.
 *
 * Decisões que merecem justificação:
 *
 * **Os limites vêm do servidor** (`GET /evidence/limits`), não estão escritos
 * aqui. Uma lista de extensões duplicada no cliente diverge mais cedo ou mais
 * tarde da que é realmente imposta, e o utilizador veria um ficheiro ser
 * recusado depois de a interface lhe dizer que era aceite.
 *
 * **A validação local não substitui a do servidor.** Serve para dar resposta
 * imediata e evitar um carregamento de 60 MB destinado a falhar; a decisão
 * continua a ser do servidor, e é a resposta dele que é mostrada.
 *
 * **Cada ficheiro é enviado num pedido próprio, em sequência.** A API recebe
 * uma evidência de cada vez, e cada uma tem o seu SHA-256 calculado na
 * recepção. Enviar em paralelo pouparia segundos e tornaria a ordem do registo
 * de auditoria não determinística.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { enviarFormulario, pedir } from "@/api/cliente";
import type { Evidencia } from "@/api/tipos";
import { Erro, tamanhoDeFicheiro } from "@/componentes/comuns";

interface Limites {
  tamanho_maximo_bytes: number;
  tamanho_maximo_legivel: string;
  extensoes_permitidas: string[];
  tipos: string[];
}

const ROTULO_DO_TIPO: Record<string, string> = {
  LOG: "Registo (log)",
  CAPTURA_ECRA: "Captura de ecrã",
  CAPTURA_REDE: "Captura de rede",
  FICHEIRO: "Ficheiro",
  RELATORIO: "Relatório",
  ARTEFACTO: "Artefacto",
  EVENTO: "Evento",
  OUTRO: "Outro",
};

/** Tipo sugerido a partir da extensão. O analista pode sempre corrigir. */
function tipoSugerido(nome: string): string {
  const ext = nome.toLowerCase().slice(nome.lastIndexOf("."));
  if ([".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(ext)) return "CAPTURA_ECRA";
  if ([".pcap", ".pcapng"].includes(ext)) return "CAPTURA_REDE";
  if ([".log", ".txt", ".evtx"].includes(ext)) return "LOG";
  if ([".pdf"].includes(ext)) return "RELATORIO";
  if ([".exe", ".dll", ".bin", ".dmp", ".ps1", ".sh"].includes(ext)) return "ARTEFACTO";
  return "FICHEIRO";
}

interface EmFila {
  id: string;
  ficheiro: File;
  tipo: string;
  descricao: string;
  /** URL local da miniatura; só para imagens. Revogado ao remover. */
  miniatura: string | null;
  problema: string | null;
}

export function CarregarEvidencias({ incidenteId }: { incidenteId: string }) {
  const clienteDeDados = useQueryClient();
  const entradaRef = useRef<HTMLInputElement>(null);
  const [fila, definirFila] = useState<EmFila[]>([]);
  const [sobre, definirSobre] = useState(false);
  const [enviados, definirEnviados] = useState<Evidencia[]>([]);

  const limites = useQuery({
    queryKey: ["limites-evidencia"],
    queryFn: () => pedir<Limites>("/evidence/limits"),
    staleTime: 30 * 60 * 1000,
  });

  // As miniaturas são objectos locais; sem revogar, ficam retidas em memória
  // até a página ser recarregada.
  useEffect(() => {
    return () => {
      fila.forEach((f) => f.miniatura && URL.revokeObjectURL(f.miniatura));
    };
    // Só na desmontagem: a remoção individual revoga no próprio handler.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function validar(ficheiro: File): string | null {
    if (!limites.data) return null;
    if (ficheiro.size === 0) return "Ficheiro vazio.";
    if (ficheiro.size > limites.data.tamanho_maximo_bytes) {
      return `Excede ${limites.data.tamanho_maximo_legivel}.`;
    }
    const ponto = ficheiro.name.lastIndexOf(".");
    const ext = ponto >= 0 ? ficheiro.name.slice(ponto).toLowerCase() : "";
    if (ext && !limites.data.extensoes_permitidas.includes(ext)) {
      return `Extensão ${ext} não aceite.`;
    }
    return null;
  }

  function acrescentar(ficheiros: FileList | File[]) {
    const novos: EmFila[] = Array.from(ficheiros).map((f) => ({
      id: `${f.name}-${f.size}-${f.lastModified}-${Math.random().toString(36).slice(2, 8)}`,
      ficheiro: f,
      tipo: tipoSugerido(f.name),
      descricao: "",
      miniatura: f.type.startsWith("image/") ? URL.createObjectURL(f) : null,
      problema: validar(f),
    }));
    definirFila((actual) => [...actual, ...novos]);
  }

  function remover(id: string) {
    definirFila((actual) => {
      const alvo = actual.find((f) => f.id === id);
      if (alvo?.miniatura) URL.revokeObjectURL(alvo.miniatura);
      return actual.filter((f) => f.id !== id);
    });
  }

  function alterar(id: string, campos: Partial<EmFila>) {
    definirFila((actual) =>
      actual.map((f) => (f.id === id ? { ...f, ...campos } : f)),
    );
  }

  const enviar = useMutation({
    mutationFn: async () => {
      const aceitaveis = fila.filter((f) => !f.problema);
      const resultados: Evidencia[] = [];
      // Sequencial de propósito: mantém a ordem do registo de auditoria.
      for (const item of aceitaveis) {
        const formulario = new FormData();
        // Nomes conforme a API declara (app/api/v1/investigation.py).
        formulario.append("incident_id", incidenteId);
        formulario.append("ficheiro", item.ficheiro);
        formulario.append("descricao", item.descricao);
        formulario.append("tipo", item.tipo);
        resultados.push(await enviarFormulario<Evidencia>("/evidence", formulario));
      }
      return resultados;
    },
    onSuccess: async (resultados) => {
      definirEnviados(resultados);
      fila.forEach((f) => f.miniatura && URL.revokeObjectURL(f.miniatura));
      definirFila([]);
      await clienteDeDados.invalidateQueries({ queryKey: ["evidencias", incidenteId] });
      await clienteDeDados.invalidateQueries({ queryKey: ["linha", incidenteId] });
    },
  });

  const prontos = fila.filter((f) => !f.problema).length;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      {/* --- zona de largada --- */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          definirSobre(true);
        }}
        onDragLeave={() => definirSobre(false)}
        onDrop={(e) => {
          e.preventDefault();
          definirSobre(false);
          if (e.dataTransfer.files.length) acrescentar(e.dataTransfer.files);
        }}
        onClick={() => entradaRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") entradaRef.current?.click();
        }}
        role="button"
        tabIndex={0}
        style={{
          border: `2px dashed ${sobre ? "var(--primaria)" : "var(--contorno)"}`,
          background: sobre ? "var(--primaria-suave)" : "var(--superficie)",
          borderRadius: "var(--raio)",
          padding: "var(--espaco-6)",
          textAlign: "center",
          cursor: "pointer",
          transition: "var(--transicao)",
        }}
      >
        <div style={{ fontSize: "1.8rem", lineHeight: 1 }} aria-hidden="true">
          ⇪
        </div>
        <p style={{ marginTop: "var(--espaco-2)" }}>
          <strong>Arraste ficheiros para aqui</strong> ou clique para escolher
        </p>
        <p className="terciario" style={{ marginTop: "var(--espaco-1)" }}>
          Fotografias, capturas de ecrã, registos, capturas de rede, relatórios.
          {limites.data ? ` Até ${limites.data.tamanho_maximo_legivel} por ficheiro.` : ""}
        </p>
        {limites.data ? (
          <p className="terciario mono" style={{ marginTop: "var(--espaco-2)" }}>
            {limites.data.extensoes_permitidas.join(" ")}
          </p>
        ) : null}
        <input
          ref={entradaRef}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            if (e.target.files?.length) acrescentar(e.target.files);
            // Permite voltar a escolher o mesmo ficheiro depois de o remover.
            e.target.value = "";
          }}
        />
      </div>

      {limites.error ? <Erro erro={limites.error} /> : null}

      {/* --- fila --- */}
      {fila.length > 0 ? (
        <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
          {fila.map((item) => (
            <div
              key={item.id}
              className="cartao"
              style={{
                display: "grid",
                gridTemplateColumns: "64px 1fr auto",
                gap: "var(--espaco-3)",
                alignItems: "start",
                borderColor: item.problema ? "var(--perigo)" : undefined,
              }}
            >
              <div
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: "var(--raio-pequeno)",
                  background: "var(--contorno-suave)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  overflow: "hidden",
                }}
              >
                {item.miniatura ? (
                  <img
                    src={item.miniatura}
                    alt={`Pré-visualização de ${item.ficheiro.name}`}
                    style={{ width: "100%", height: "100%", objectFit: "cover" }}
                  />
                ) : (
                  <span aria-hidden="true" style={{ fontSize: "1.4rem" }}>
                    ▤
                  </span>
                )}
              </div>

              <div className="pilha" style={{ gap: "var(--espaco-2)", minWidth: 0 }}>
                <div className="pilha" style={{ gap: 0 }}>
                  <strong className="truncar">{item.ficheiro.name}</strong>
                  <span className="terciario mono">
                    {tamanhoDeFicheiro(item.ficheiro.size)}
                  </span>
                </div>

                {item.problema ? (
                  <p style={{ color: "var(--perigo)" }}>{item.problema}</p>
                ) : (
                  <>
                    <select
                      className="selector"
                      value={item.tipo}
                      onChange={(e) => alterar(item.id, { tipo: e.target.value })}
                    >
                      {(limites.data?.tipos ?? Object.keys(ROTULO_DO_TIPO)).map((t) => (
                        <option key={t} value={t}>
                          {ROTULO_DO_TIPO[t] ?? t}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      placeholder="O que é e de onde veio (opcional)."
                      maxLength={2000}
                      value={item.descricao}
                      onChange={(e) => alterar(item.id, { descricao: e.target.value })}
                    />
                  </>
                )}
              </div>

              <button
                type="button"
                className="botao botao--discreto botao--pequeno"
                onClick={() => remover(item.id)}
                aria-label={`Remover ${item.ficheiro.name}`}
              >
                Remover
              </button>
            </div>
          ))}

          {enviar.error ? <Erro erro={enviar.error} /> : null}

          <div className="linha" style={{ gap: "var(--espaco-2)" }}>
            <button
              type="button"
              className="botao botao--primario"
              disabled={enviar.isPending || prontos === 0}
              onClick={() => enviar.mutate()}
            >
              {enviar.isPending
                ? "A carregar…"
                : `Carregar ${prontos} ficheiro${prontos === 1 ? "" : "s"}`}
            </button>
            <button
              type="button"
              className="botao botao--discreto"
              disabled={enviar.isPending}
              onClick={() => {
                fila.forEach((f) => f.miniatura && URL.revokeObjectURL(f.miniatura));
                definirFila([]);
              }}
            >
              Limpar
            </button>
          </div>
          <p className="terciario">
            O SHA-256 é calculado sobre os bytes recebidos e passa a ser a
            referência para verificações de integridade posteriores.
          </p>
        </div>
      ) : null}

      {/* --- confirmação do último envio, com o hash --- */}
      {enviados.length > 0 ? (
        <div className="mensagem mensagem--sucesso">
          <strong>
            {enviados.length} evidência{enviados.length === 1 ? "" : "s"} anexada
            {enviados.length === 1 ? "" : "s"}.
          </strong>
          <ul style={{ marginTop: "var(--espaco-2)" }}>
            {enviados.map((e) => (
              <li key={e.id}>
                {e.name}{" "}
                <span className="terciario mono" title={e.sha256}>
                  sha256 {e.sha256.slice(0, 16)}…
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
