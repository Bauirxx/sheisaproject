/**
 * Componentes partilhados por todas as páginas.
 *
 * Os distintivos de severidade e estado nunca comunicam só por cor (§79): cada
 * um traz o texto do valor, e os mais graves trazem também um ponto. Um
 * analista com daltonismo tem de conseguir distinguir ALTA de CRÍTICA numa fila
 * de trinta linhas, e a projecção de uma defesa costuma achatar cores.
 */

import type { ReactNode } from "react";

import { ErroDaApi } from "@/api/cliente";
import type { EstadoAlerta, EstadoIncidente, Severidade } from "@/api/tipos";

// ------------------------------------------------------------- severidade
export function DistintivoDeSeveridade({ valor }: { valor: Severidade }) {
  return (
    <span className={`distintivo sev--${valor}`}>
      <span className="distintivo__ponto" aria-hidden="true" />
      {valor}
    </span>
  );
}

// ---------------------------------------------------------------- estados
/**
 * Cor por *significado*, não por ordem alfabética: em curso é azul, terminado
 * é verde, descartado é neutro, escalado é vermelho. O objectivo é que a fila
 * se leia de relance.
 */
const ASPECTO_DO_INCIDENTE: Record<EstadoIncidente, string> = {
  NOVO: "distintivo--aviso",
  ABERTO: "distintivo--activo",
  TRIAGEM: "distintivo--activo",
  INVESTIGACAO: "distintivo--activo",
  CONTENCAO: "distintivo--aviso",
  ERRADICACAO: "distintivo--aviso",
  RECUPERACAO: "distintivo--aviso",
  RESOLVIDO: "distintivo--sucesso",
  ENCERRADO: "distintivo--neutro",
  SUSPENSO: "distintivo--neutro",
  DUPLICADO: "distintivo--neutro",
  FALSO_POSITIVO: "distintivo--neutro",
  ESCALADO: "distintivo--perigo",
};

const ROTULO_DO_INCIDENTE: Record<EstadoIncidente, string> = {
  NOVO: "Novo",
  ABERTO: "Aberto",
  TRIAGEM: "Triagem",
  INVESTIGACAO: "Investigação",
  CONTENCAO: "Contenção",
  ERRADICACAO: "Erradicação",
  RECUPERACAO: "Recuperação",
  RESOLVIDO: "Resolvido",
  ENCERRADO: "Encerrado",
  SUSPENSO: "Suspenso",
  DUPLICADO: "Duplicado",
  FALSO_POSITIVO: "Falso positivo",
  ESCALADO: "Escalado",
};

export function DistintivoDeEstado({ valor }: { valor: EstadoIncidente }) {
  return (
    <span className={`distintivo ${ASPECTO_DO_INCIDENTE[valor] ?? "distintivo--neutro"}`}>
      {ROTULO_DO_INCIDENTE[valor] ?? valor}
    </span>
  );
}

const ASPECTO_DO_ALERTA: Record<EstadoAlerta, string> = {
  NOVO: "distintivo--aviso",
  EM_TRIAGEM: "distintivo--activo",
  CORRELACIONADO: "distintivo--activo",
  PROMOVIDO: "distintivo--sucesso",
  DESCARTADO: "distintivo--neutro",
  FALSO_POSITIVO: "distintivo--neutro",
  DUPLICADO: "distintivo--neutro",
};

const ROTULO_DO_ALERTA: Record<EstadoAlerta, string> = {
  NOVO: "Novo",
  EM_TRIAGEM: "Em triagem",
  CORRELACIONADO: "Correlacionado",
  PROMOVIDO: "Promovido",
  DESCARTADO: "Descartado",
  FALSO_POSITIVO: "Falso positivo",
  DUPLICADO: "Duplicado",
};

export function DistintivoDeEstadoDoAlerta({ valor }: { valor: EstadoAlerta }) {
  return (
    <span className={`distintivo ${ASPECTO_DO_ALERTA[valor] ?? "distintivo--neutro"}`}>
      {ROTULO_DO_ALERTA[valor] ?? valor}
    </span>
  );
}

/** Marca visível de dados de demonstração. Nunca silenciosa (§4). */
export function MarcaDeDemonstracao() {
  return (
    <span
      className="distintivo distintivo--demonstracao"
      title="Registo criado pelo cenário de demonstração; não é actividade real."
    >
      demonstração
    </span>
  );
}

// ------------------------------------------------------------------ estados
export function Carregando({ texto = "A carregar…" }: { texto?: string }) {
  return (
    <div className="vazio">
      <span className="carregando" aria-hidden="true" />
      <span className="secundario">{texto}</span>
    </div>
  );
}

export function Vazio({
  titulo,
  detalhe,
  accao,
}: {
  titulo: string;
  detalhe?: string;
  accao?: ReactNode;
}) {
  return (
    <div className="vazio">
      <p className="vazio__titulo">{titulo}</p>
      {detalhe ? <p className="vazio__detalhe">{detalhe}</p> : null}
      {accao}
    </div>
  );
}

/**
 * Apresentação de um erro da API.
 *
 * Mostra o código além da mensagem. Não é ruído técnico: é o que permite a
 * quem apoia o utilizador saber do que se trata sem reproduzir o problema, e é
 * o que distingue "não tem permissão" de "o servidor falhou".
 */
export function Erro({ erro }: { erro: unknown }) {
  if (erro instanceof ErroDaApi) {
    const permissao = erro.permissaoNecessaria;
    return (
      <div className="mensagem mensagem--erro" role="alert">
        <div className="pilha" style={{ gap: "var(--espaco-1)" }}>
          <strong>{erro.message}</strong>
          {permissao ? (
            <span className="terciario">
              Esta operação exige a permissão <code>{permissao}</code>.
            </span>
          ) : null}
          <span className="mensagem__codigo">{erro.codigo}</span>
        </div>
      </div>
    );
  }
  return (
    <div className="mensagem mensagem--erro" role="alert">
      <span>
        {erro instanceof Error
          ? erro.message
          : "Ocorreu um erro inesperado ao contactar o servidor."}
      </span>
    </div>
  );
}

// --------------------------------------------------------------- formatação
export function instante(valor: string | null | undefined): string {
  if (!valor) return "—";
  const data = new Date(valor);
  if (Number.isNaN(data.getTime())) return "—";
  return data.toLocaleString("pt-PT", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function instanteCurto(valor: string | null | undefined): string {
  if (!valor) return "—";
  const data = new Date(valor);
  if (Number.isNaN(data.getTime())) return "—";
  return data.toLocaleString("pt-PT", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Duração legível a partir de segundos. `null` fica "—", nunca "0". */
export function duracao(segundos: number | null | undefined): string {
  if (segundos === null || segundos === undefined) return "—";
  if (segundos < 60) return `${segundos} s`;
  const minutos = Math.floor(segundos / 60);
  if (minutos < 60) return `${minutos} min`;
  const horas = Math.floor(minutos / 60);
  const restoMinutos = minutos % 60;
  if (horas < 24) return restoMinutos ? `${horas}h ${restoMinutos}min` : `${horas}h`;
  const dias = Math.floor(horas / 24);
  const restoHoras = horas % 24;
  return restoHoras ? `${dias}d ${restoHoras}h` : `${dias}d`;
}

export function tamanhoDeFicheiro(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Substitui os sublinhados dos enumerados por espaços, para leitura. */
export function legivel(valor: string | null | undefined): string {
  if (!valor) return "—";
  const texto = valor.replace(/_/g, " ").toLowerCase();
  return texto.charAt(0).toUpperCase() + texto.slice(1);
}
