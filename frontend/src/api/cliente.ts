/**
 * Cliente HTTP da API.
 *
 * Três decisões que convém não desfazer:
 *
 * **O token de acesso vive em memória, não em `localStorage`.** Um token em
 * `localStorage` é legível por qualquer script que consiga correr na página —
 * é exactamente o que um XSS procura. Em memória, perde-se ao recarregar; é
 * por isso que existe o token de renovação, guardado separadamente e usado
 * para recuperar a sessão. Numa plataforma de segurança, perder a sessão ao
 * recarregar é um preço aceitável; entregar o token a um XSS não é.
 *
 * **A renovação é feita uma vez, não uma por pedido.** Se cinco pedidos
 * falharem com 401 ao mesmo tempo, os cinco esperam pela mesma renovação. Sem
 * isto, cinco renovações concorrentes disparariam a detecção de reutilização de
 * token do servidor — que revoga a sessão inteira, por suspeitar de roubo.
 *
 * **Os erros da API chegam como `ErroDaApi`, com código.** A API responde
 * sempre no mesmo formato (`{erro: {codigo, mensagem, detalhes}}`); traduzir
 * isso para uma cadeia de texto perderia o código, que é o que permite à
 * interface distinguir "transição inválida" de "sem permissão" e reagir em
 * conformidade.
 */

import type { ErroApi, RespostaEntrada, Utilizador } from "./tipos";

const PREFIXO = "/api";
const CHAVE_RENOVACAO = "sheisa.renovacao";

export class ErroDaApi extends Error {
  readonly estado: number;
  readonly codigo: string;
  readonly detalhes: Record<string, unknown> | null;

  constructor(estado: number, erro: ErroApi) {
    super(erro.mensagem);
    this.name = "ErroDaApi";
    this.estado = estado;
    this.codigo = erro.codigo;
    this.detalhes = erro.detalhes ?? null;
  }

  /** O utilizador está autenticado mas não tem a permissão exigida. */
  get semPermissao(): boolean {
    return this.estado === 403;
  }

  /** A sessão caducou ou não existe. */
  get semSessao(): boolean {
    return this.estado === 401;
  }

  /** Permissão em falta, quando a API a identifica. */
  get permissaoNecessaria(): string | null {
    const valor = this.detalhes?.["permissao_necessaria"];
    return typeof valor === "string" ? valor : null;
  }
}

let tokenDeAcesso: string | null = null;
let renovacaoEmCurso: Promise<boolean> | null = null;
let aoPerderSessao: (() => void) | null = null;

export function definirToken(token: string | null): void {
  tokenDeAcesso = token;
}

export function obterToken(): string | null {
  return tokenDeAcesso;
}

export function guardarRenovacao(token: string | null): void {
  try {
    if (token) {
      window.localStorage.setItem(CHAVE_RENOVACAO, token);
    } else {
      window.localStorage.removeItem(CHAVE_RENOVACAO);
    }
  } catch {
    // Janela privada ou armazenamento bloqueado: a sessão passa a durar
    // apenas enquanto o separador estiver aberto, o que é degradação
    // aceitável e não uma falha.
  }
}

export function lerRenovacao(): string | null {
  try {
    return window.localStorage.getItem(CHAVE_RENOVACAO);
  } catch {
    return null;
  }
}

export function definirTratamentoDePerdaDeSessao(f: (() => void) | null): void {
  aoPerderSessao = f;
}

interface Opcoes {
  metodo?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  corpo?: unknown;
  /** Quando falso, um 401 não tenta renovar (usado pela própria renovação). */
  renovavel?: boolean;
  sinal?: AbortSignal;
}

async function executar(caminho: string, opcoes: Opcoes = {}): Promise<Response> {
  const cabecalhos: Record<string, string> = {};
  if (opcoes.corpo !== undefined) {
    cabecalhos["Content-Type"] = "application/json";
  }
  if (tokenDeAcesso) {
    cabecalhos["Authorization"] = `Bearer ${tokenDeAcesso}`;
  }

  return fetch(`${PREFIXO}${caminho}`, {
    method: opcoes.metodo ?? "GET",
    headers: cabecalhos,
    body: opcoes.corpo !== undefined ? JSON.stringify(opcoes.corpo) : undefined,
    signal: opcoes.sinal,
  });
}

async function extrairErro(resposta: Response): Promise<ErroDaApi> {
  let corpo: { erro?: ErroApi } | null = null;
  try {
    corpo = (await resposta.json()) as { erro?: ErroApi };
  } catch {
    corpo = null;
  }
  const erro: ErroApi = corpo?.erro ?? {
    codigo: `HTTP_${resposta.status}`,
    mensagem:
      resposta.status >= 500
        ? "O servidor não conseguiu responder. Tente novamente."
        : "Pedido recusado.",
  };
  return new ErroDaApi(resposta.status, erro);
}

/** Renova a sessão. Concorrentes partilham a mesma tentativa. */
async function renovarSessao(): Promise<boolean> {
  if (renovacaoEmCurso) return renovacaoEmCurso;

  renovacaoEmCurso = (async () => {
    const token = lerRenovacao();
    if (!token) return false;
    try {
      const resposta = await executar("/auth/refresh", {
        metodo: "POST",
        corpo: { refresh_token: token },
        renovavel: false,
      });
      if (!resposta.ok) {
        guardarRenovacao(null);
        return false;
      }
      const dados = (await resposta.json()) as RespostaEntrada;
      definirToken(dados.access_token);
      guardarRenovacao(dados.refresh_token);
      return true;
    } catch {
      return false;
    } finally {
      renovacaoEmCurso = null;
    }
  })();

  return renovacaoEmCurso;
}

export async function pedir<T>(caminho: string, opcoes: Opcoes = {}): Promise<T> {
  let resposta = await executar(caminho, opcoes);

  if (resposta.status === 401 && opcoes.renovavel !== false) {
    if (await renovarSessao()) {
      resposta = await executar(caminho, opcoes);
    } else {
      definirToken(null);
      aoPerderSessao?.();
    }
  }

  if (!resposta.ok) {
    throw await extrairErro(resposta);
  }

  if (resposta.status === 204) {
    return undefined as T;
  }
  return (await resposta.json()) as T;
}

// ------------------------------------------------------------------ sessão
export async function entrar(
  email: string,
  palavraPasse: string,
): Promise<RespostaEntrada> {
  const resposta = await executar("/auth/login", {
    metodo: "POST",
    corpo: { email, password: palavraPasse },
    renovavel: false,
  });
  if (!resposta.ok) throw await extrairErro(resposta);

  const dados = (await resposta.json()) as RespostaEntrada;
  definirToken(dados.access_token);
  guardarRenovacao(dados.refresh_token);
  return dados;
}

export async function sair(): Promise<void> {
  const token = lerRenovacao();
  try {
    if (token) {
      await executar("/auth/logout", {
        metodo: "POST",
        corpo: { refresh_token: token },
      });
    }
  } catch {
    // Terminar sessão do lado do servidor é o desejável, mas se falhar o
    // utilizador tem de conseguir sair local na mesma.
  } finally {
    definirToken(null);
    guardarRenovacao(null);
  }
}

export async function recuperarSessao(): Promise<Utilizador | null> {
  if (!lerRenovacao()) return null;
  if (!(await renovarSessao())) return null;
  try {
    return await pedir<Utilizador>("/auth/me");
  } catch {
    return null;
  }
}

/** Constrói uma query string, omitindo valores vazios. */
export function consulta(
  parametros: Record<string, string | number | boolean | undefined | null | string[]>,
): string {
  const partes = new URLSearchParams();
  for (const [chave, valor] of Object.entries(parametros)) {
    if (valor === undefined || valor === null || valor === "") continue;
    if (Array.isArray(valor)) {
      for (const item of valor) if (item) partes.append(chave, item);
    } else {
      partes.append(chave, String(valor));
    }
  }
  const texto = partes.toString();
  return texto ? `?${texto}` : "";
}
