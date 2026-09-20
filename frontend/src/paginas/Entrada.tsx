/**
 * Início de sessão (§4.13, tela 1).
 *
 * A mensagem de erro é sempre a que o servidor devolve, sem a interpretar nem
 * a enriquecer. O servidor responde exactamente o mesmo para "conta
 * inexistente" e "palavra-passe errada", de propósito: distinguir os dois
 * casos permitiria enumerar contas válidas. Se a interface acrescentasse
 * "verifique o endereço" a um dos casos, desfazia no cliente o cuidado que o
 * servidor teve.
 */

import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { ErroDaApi } from "@/api/cliente";
import { useSessao } from "@/autenticacao/contexto";
import { Carregando } from "@/componentes/comuns";

export function Entrada() {
  const { entrar, utilizador, aRecuperar } = useSessao();
  const navegar = useNavigate();

  const [email, definirEmail] = useState("");
  const [palavraPasse, definirPalavraPasse] = useState("");
  const [erro, definirErro] = useState<string | null>(null);
  const [aSubmeter, definirSubmissao] = useState(false);

  if (aRecuperar) {
    return (
      <div className="entrada-pagina">
        <Carregando texto="A verificar a sessão…" />
      </div>
    );
  }
  if (utilizador) {
    return <Navigate to="/painel" replace />;
  }

  const submeter = async (evento: FormEvent) => {
    evento.preventDefault();
    definirErro(null);
    definirSubmissao(true);
    try {
      await entrar(email.trim(), palavraPasse);
      navegar("/painel", { replace: true });
    } catch (e) {
      definirErro(
        e instanceof ErroDaApi
          ? e.message
          : "Não foi possível contactar o servidor.",
      );
    } finally {
      definirSubmissao(false);
    }
  };

  return (
    <div className="entrada-pagina">
      <form className="entrada-cartao" onSubmit={(e) => void submeter(e)}>
        <div className="entrada-cartao__marca">
          <img src="/logo.svg" alt="Logótipo" width="44" height="44" />
          <div className="pilha" style={{ gap: 0 }}>
            <strong style={{ fontSize: "var(--texto-md)" }}>
              Gestão de Incidentes
            </strong>
            <span className="terciario">
              Resposta a incidentes cibernéticos
            </span>
          </div>
        </div>

        <div className="pilha">
          <div className="campo">
            <label className="campo__etiqueta" htmlFor="email">
              Endereço de correio electrónico
            </label>
            <input
              id="email"
              className="entrada"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => definirEmail(e.target.value)}
              placeholder="analista@organizacao.local"
            />
          </div>

          <div className="campo">
            <label className="campo__etiqueta" htmlFor="palavra-passe">
              Palavra-passe
            </label>
            <input
              id="palavra-passe"
              className="entrada"
              type="password"
              autoComplete="current-password"
              required
              value={palavraPasse}
              onChange={(e) => definirPalavraPasse(e.target.value)}
            />
          </div>

          {erro ? (
            <div className="mensagem mensagem--erro" role="alert">
              {erro}
            </div>
          ) : null}

          <button
            type="submit"
            className="botao botao--primario"
            disabled={aSubmeter || !email || !palavraPasse}
          >
            {aSubmeter ? <span className="carregando" aria-hidden="true" /> : null}
            {aSubmeter ? "A entrar…" : "Entrar"}
          </button>

          <p className="campo__ajuda">
            O acesso é registado na auditoria, incluindo as tentativas falhadas.
          </p>
        </div>
      </form>
    </div>
  );
}
