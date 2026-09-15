/**
 * Sessão do utilizador e verificação de permissões no cliente.
 *
 * `pode()` existe para **esconder o que o utilizador não pode fazer**, por
 * cortesia — nunca como controlo de acesso. A autorização real acontece no
 * servidor, que reconfirma o perfil contra a base de dados a cada pedido. Um
 * botão escondido continua a ser uma chamada que qualquer pessoa pode fazer
 * com `curl`; é o 403 do servidor que a recusa.
 *
 * A consequência prática: a interface nunca deve *assumir* que uma operação vai
 * correr bem só porque `pode()` devolveu `true`. Trata sempre o 403 quando ele
 * vier.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  definirTratamentoDePerdaDeSessao,
  entrar as entrarNaApi,
  recuperarSessao,
  sair as sairDaApi,
} from "@/api/cliente";
import type { Utilizador } from "@/api/tipos";

interface EstadoDaSessao {
  utilizador: Utilizador | null;
  aRecuperar: boolean;
  entrar: (email: string, palavraPasse: string) => Promise<void>;
  sair: () => Promise<void>;
  pode: (...permissoes: string[]) => boolean;
  podeAlguma: (...permissoes: string[]) => boolean;
}

const Contexto = createContext<EstadoDaSessao | null>(null);

export function ProvedorDeSessao({ children }: { children: ReactNode }) {
  const [utilizador, definirUtilizador] = useState<Utilizador | null>(null);
  const [aRecuperar, definirRecuperacao] = useState(true);

  // Tenta repor a sessão a partir do token de renovação guardado. É o que
  // evita que recarregar a página obrigue a autenticar de novo, apesar de o
  // token de acesso viver apenas em memória.
  useEffect(() => {
    let activo = true;
    void (async () => {
      const recuperado = await recuperarSessao();
      if (activo) {
        definirUtilizador(recuperado);
        definirRecuperacao(false);
      }
    })();
    return () => {
      activo = false;
    };
  }, []);

  // Quando o cliente HTTP conclui que a sessão se perdeu — renovação recusada —
  // o estado local tem de acompanhar, ou a interface continuaria a mostrar
  // menus de alguém que já não está autenticado.
  useEffect(() => {
    definirTratamentoDePerdaDeSessao(() => definirUtilizador(null));
    return () => definirTratamentoDePerdaDeSessao(null);
  }, []);

  const entrar = useCallback(async (email: string, palavraPasse: string) => {
    const resposta = await entrarNaApi(email, palavraPasse);
    definirUtilizador(resposta.user);
  }, []);

  const sair = useCallback(async () => {
    await sairDaApi();
    definirUtilizador(null);
  }, []);

  const permissoes = useMemo(
    () => new Set(utilizador?.permissions ?? []),
    [utilizador],
  );

  const pode = useCallback(
    (...pedidas: string[]) => pedidas.every((p) => permissoes.has(p)),
    [permissoes],
  );

  const podeAlguma = useCallback(
    (...pedidas: string[]) => pedidas.some((p) => permissoes.has(p)),
    [permissoes],
  );

  const valor = useMemo<EstadoDaSessao>(
    () => ({ utilizador, aRecuperar, entrar, sair, pode, podeAlguma }),
    [utilizador, aRecuperar, entrar, sair, pode, podeAlguma],
  );

  return <Contexto.Provider value={valor}>{children}</Contexto.Provider>;
}

export function useSessao(): EstadoDaSessao {
  const contexto = useContext(Contexto);
  if (!contexto) {
    throw new Error("useSessao tem de ser usado dentro de <ProvedorDeSessao>.");
  }
  return contexto;
}
