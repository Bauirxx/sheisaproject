/**
 * Disposição do centro de operações (§80 do briefing).
 *
 * Barra lateral fixa, topo com pesquisa e identidade, área de trabalho. O
 * princípio é que o analista chegue a qualquer fila — alertas, incidentes,
 * recomendações, aprovações — num clique, sem navegar por menus encadeados.
 * Numa sala de operações, cada clique a mais é tempo de resposta.
 *
 * As entradas da barra lateral são filtradas pelas permissões do utilizador.
 * É cortesia, não segurança: o servidor recusa na mesma quem lá chegar pelo
 * URL. Mostrar um menu que dá 403 ao ser clicado ensina o utilizador a
 * desconfiar da interface.
 */

import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useSessao } from "@/autenticacao/contexto";

/** Largura abaixo da qual a barra é uma gaveta por cima, não uma coluna fixa. */
const LARGURA_ESTREITA = 900;

/**
 * Estado inicial da barra lateral: lê a preferência guardada; na ausência dela,
 * aberta em ecrã largo e fechada em ecrã estreito. Fechá-la por omissão num
 * telemóvel evita que a gaveta tape o conteúdo logo à entrada.
 */
function lateralInicial(): boolean {
  try {
    const guardado = window.localStorage.getItem("sheisa.lateral");
    if (guardado !== null) return guardado === "1";
  } catch {
    // Sem localStorage: cai para a regra por largura.
  }
  return window.innerWidth > LARGURA_ESTREITA;
}

interface Entrada {
  para: string;
  rotulo: string;
  icone: string;
  /** Permissões exigidas para a entrada ser mostrada. */
  permissoes?: string[];
}

interface Grupo {
  titulo: string;
  entradas: Entrada[];
}

const NAVEGACAO: Grupo[] = [
  {
    titulo: "Operação",
    entradas: [
      { para: "/painel", rotulo: "Painel", icone: "◧", permissoes: ["dashboard:read"] },
      // O painel diz como estamos; o centro diz o que está à espera de alguém.
      {
        para: "/centro",
        rotulo: "Centro de operações",
        icone: "◉",
        permissoes: ["dashboard:read"],
      },
      { para: "/alertas", rotulo: "Alertas", icone: "◆", permissoes: ["alerts:read"] },
      // Logo abaixo dos alertas de propósito: é a camada de que eles são feitos.
      { para: "/eventos", rotulo: "Eventos", icone: "·", permissoes: ["events:read"] },
      // Matéria-prima vinda de fora, ao lado da que vem das ferramentas.
      {
        para: "/comunicacoes",
        rotulo: "Comunicações",
        icone: "✉",
        permissoes: ["reports_inbox:read"],
      },
      {
        para: "/incidentes",
        rotulo: "Incidentes",
        icone: "▣",
        permissoes: ["incidents:read"],
      },
      {
        para: "/recomendacoes",
        rotulo: "Recomendações",
        icone: "✦",
        permissoes: ["recommendations:read"],
      },
    ],
  },
  {
    titulo: "Resposta",
    entradas: [
      { para: "/aprovacoes", rotulo: "Aprovações", icone: "⎔", permissoes: ["actions:read"] },
      { para: "/playbooks", rotulo: "Playbooks", icone: "≡", permissoes: ["playbooks:read"] },
    ],
  },
  {
    titulo: "Inteligência",
    entradas: [
      { para: "/indicadores", rotulo: "Indicadores", icone: "◇", permissoes: ["iocs:read"] },
      { para: "/activos", rotulo: "Activos", icone: "▤", permissoes: ["assets:read"] },
      { para: "/mitre", rotulo: "MITRE ATT&CK", icone: "⊞", permissoes: ["mitre:read"] },
    ],
  },
  {
    titulo: "Governo",
    entradas: [
      { para: "/relatorios", rotulo: "Relatórios", icone: "▦", permissoes: ["reports:read"] },
      { para: "/auditoria", rotulo: "Auditoria", icone: "⊟", permissoes: ["audit:read"] },
      {
        para: "/integracoes",
        rotulo: "Integrações",
        icone: "⇄",
        permissoes: ["integrations:read"],
      },
      // Sem `permissoes`: as notificações são as do próprio utilizador e a API
      // filtra-as por sessão, pelo que não há nada a esconder na navegação.
      { para: "/notificacoes", rotulo: "Notificações", icone: "◉" },
      {
        para: "/administracao",
        rotulo: "Administração",
        icone: "⚙",
        permissoes: ["users:read"],
      },
    ],
  },
];

function AlternarTema() {
  const alternar = () => {
    const raiz = document.documentElement;
    const claro = raiz.getAttribute("data-tema") === "claro";
    raiz.setAttribute("data-tema", claro ? "escuro" : "claro");
    try {
      window.localStorage.setItem("sheisa.tema", claro ? "escuro" : "claro");
    } catch {
      // Preferência não persistida: irrelevante para o funcionamento.
    }
  };
  return (
    <button
      type="button"
      className="botao botao--discreto"
      onClick={alternar}
      title="Alternar entre modo escuro e claro"
    >
      ◐<span className="so-leitores">Alternar tema</span>
    </button>
  );
}

export function Disposicao() {
  const { utilizador, sair, pode } = useSessao();
  const navegar = useNavigate();
  const [lateralAberta, definirLateralAberta] = useState(lateralInicial);

  const alternarLateral = () =>
    definirLateralAberta((aberta) => {
      const nova = !aberta;
      try {
        window.localStorage.setItem("sheisa.lateral", nova ? "1" : "0");
      } catch {
        // Preferência não persistida: irrelevante para o funcionamento.
      }
      return nova;
    });

  // Ao seguir uma ligação num ecrã estreito, a gaveta fecha-se: caso contrário
  // ficaria a tapar a página que se acabou de abrir.
  const fecharSeEstreito = () => {
    if (window.innerWidth <= LARGURA_ESTREITA) definirLateralAberta(false);
  };

  const terminarSessao = async () => {
    await sair();
    navegar("/entrar", { replace: true });
  };

  const grupos = NAVEGACAO.map((grupo) => ({
    ...grupo,
    entradas: grupo.entradas.filter(
      (entrada) => !entrada.permissoes || pode(...entrada.permissoes),
    ),
  })).filter((grupo) => grupo.entradas.length > 0);

  return (
    <div
      className={`disposicao${lateralAberta ? "" : " disposicao--lateral-fechada"}`}
    >
      <aside className="barra-lateral">
        <div className="barra-lateral__marca">
          <span className="terciario">Resposta a incidentes</span>
        </div>

        <nav className="barra-lateral__navegacao" aria-label="Navegação principal">
          {grupos.map((grupo) => (
            <div key={grupo.titulo} className="barra-lateral__grupo">
              <p className="barra-lateral__grupo-titulo">{grupo.titulo}</p>
              {grupo.entradas.map((entrada) => (
                <NavLink
                  key={entrada.para}
                  to={entrada.para}
                  onClick={fecharSeEstreito}
                  className={({ isActive }) =>
                    `barra-lateral__ligacao${isActive ? " barra-lateral__ligacao--activa" : ""}`
                  }
                >
                  <span className="barra-lateral__icone" aria-hidden="true">
                    {entrada.icone}
                  </span>
                  {entrada.rotulo}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      {/* Fundo escuro que fecha a gaveta num ecrã estreito. O CSS esconde-o em
          ecrã largo, onde a barra é uma coluna e não uma sobreposição. */}
      {lateralAberta ? (
        <button
          type="button"
          className="barra-lateral__fundo"
          aria-hidden="true"
          tabIndex={-1}
          onClick={alternarLateral}
        />
      ) : null}

      <div className="area">
        <header className="topo">
          <button
            type="button"
            className="botao-menu"
            onClick={alternarLateral}
            aria-label={lateralAberta ? "Fechar menu" : "Abrir menu"}
            aria-expanded={lateralAberta}
            title={lateralAberta ? "Fechar menu" : "Abrir menu"}
          >
            <img src="/logo.svg" alt="" width="30" height="30" />
          </button>
          <div className="crescer" />
          <AlternarTema />
          <div className="topo__identidade">
            <div className="pilha" style={{ gap: 0, alignItems: "flex-end" }}>
              <span className="truncar">{utilizador?.full_name}</span>
              <span className="terciario">{utilizador?.role?.name ?? "—"}</span>
            </div>
            <button
              type="button"
              className="botao botao--discreto"
              onClick={() => void terminarSessao()}
            >
              Sair
            </button>
          </div>
        </header>

        <main className="area__conteudo">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
