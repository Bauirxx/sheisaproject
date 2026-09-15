/**
 * Grafo investigativo de um incidente (§19 do briefing · §21 antigo).
 *
 * SVG directo, sem biblioteca de grafos. A razão não é economizar uma
 * dependência: é que uma disposição por simulação física move os nós enquanto
 * estabiliza, e um analista que aponta para um nó e o vê fugir perde o fio à
 * investigação. Aqui a disposição é **determinística** — o incidente ao centro,
 * os alertas e os indicadores em anéis — pelo que abrir o mesmo incidente duas
 * vezes dá exactamente o mesmo desenho, e é possível dizer a um colega "o nó em
 * cima à direita".
 *
 * Os nós não comunicam só por cor: cada um tem o seu rótulo, e a forma muda
 * consoante o tipo.
 */

import { useMemo, useState } from "react";

import type { Grafo, NoDoGrafo } from "@/api/tipos";

const COR_POR_TIPO: Record<string, string> = {
  incidente: "var(--primaria)",
  alerta: "var(--sev-media)",
  indicador: "var(--info)",
  activo: "var(--sucesso)",
  tecnica: "var(--sev-alta)",
  utilizador: "var(--texto-secundario)",
};

interface NoPosicionado extends NoDoGrafo {
  x: number;
  y: number;
  raio: number;
}

const LARGURA = 900;
const ALTURA = 460;

/**
 * Disposição em anéis concêntricos: o incidente ao centro, os alertas no anel
 * interior, tudo o resto no exterior. Determinística por construção.
 */
function dispor(grafo: Grafo): NoPosicionado[] {
  const centroX = LARGURA / 2;
  const centroY = ALTURA / 2;

  const centrais = grafo.nos.filter((n) => n.tipo === "incidente");
  const interiores = grafo.nos.filter((n) => n.tipo === "alerta");
  const exteriores = grafo.nos.filter(
    (n) => n.tipo !== "incidente" && n.tipo !== "alerta",
  );

  const posicionados: NoPosicionado[] = [];

  centrais.forEach((no, indice) => {
    const deslocamento = centrais.length === 1 ? 0 : (indice - (centrais.length - 1) / 2) * 90;
    posicionados.push({ ...no, x: centroX + deslocamento, y: centroY, raio: 13 });
  });

  const anel = (nos: NoDoGrafo[], raioAnel: number, raioNo: number, rotacao: number) => {
    nos.forEach((no, indice) => {
      const angulo = rotacao + (2 * Math.PI * indice) / Math.max(nos.length, 1);
      posicionados.push({
        ...no,
        x: centroX + Math.cos(angulo) * raioAnel * 1.7,
        y: centroY + Math.sin(angulo) * raioAnel,
        raio: raioNo,
      });
    });
  };

  anel(interiores, 88, 9, -Math.PI / 2);
  anel(exteriores, 172, 7, -Math.PI / 2 + Math.PI / Math.max(exteriores.length, 1));

  return posicionados;
}

export function GrafoInvestigativo({ grafo }: { grafo: Grafo }) {
  const [focado, definirFocado] = useState<string | null>(null);
  const nos = useMemo(() => dispor(grafo), [grafo]);
  const porId = useMemo(() => new Map(nos.map((n) => [n.id, n])), [nos]);

  if (grafo.nos.length === 0) {
    return (
      <p className="secundario">
        Este incidente ainda não tem observações nem alertas associados, pelo que
        não há relações a desenhar. O grafo é construído a partir de avistamentos
        reais — não desenha uma estrutura só para haver figura.
      </p>
    );
  }

  const detalhe = focado ? porId.get(focado) : null;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-3)" }}>
      <svg
        className="grafo"
        viewBox={`0 0 ${LARGURA} ${ALTURA}`}
        role="img"
        aria-label={`Grafo com ${grafo.nos.length} nós e ${grafo.arestas.length} relações`}
      >
        {grafo.arestas.map((aresta, indice) => {
          const origem = porId.get(aresta.origem);
          const destino = porId.get(aresta.destino);
          if (!origem || !destino) return null;
          const realcada =
            focado === aresta.origem || focado === aresta.destino;
          return (
            <line
              key={`${aresta.origem}-${aresta.destino}-${indice}`}
              x1={origem.x}
              y1={origem.y}
              x2={destino.x}
              y2={destino.y}
              stroke={realcada ? "var(--primaria)" : "var(--contorno)"}
              strokeWidth={realcada ? 1.8 : 1}
            />
          );
        })}

        {nos.map((no) => {
          const cor = COR_POR_TIPO[no.tipo] ?? "var(--texto-secundario)";
          const activo = focado === no.id;
          return (
            <g
              key={no.id}
              className="grafo__no"
              onMouseEnter={() => definirFocado(no.id)}
              onMouseLeave={() => definirFocado(null)}
            >
              {no.tipo === "incidente" ? (
                <rect
                  x={no.x - no.raio}
                  y={no.y - no.raio}
                  width={no.raio * 2}
                  height={no.raio * 2}
                  rx={3}
                  fill={cor}
                  stroke={activo ? "var(--texto)" : "none"}
                  strokeWidth={2}
                />
              ) : (
                <circle
                  cx={no.x}
                  cy={no.y}
                  r={activo ? no.raio + 2 : no.raio}
                  fill={cor}
                  stroke={activo ? "var(--texto)" : "none"}
                  strokeWidth={2}
                />
              )}
              <text
                className="grafo__rotulo"
                x={no.x}
                y={no.y + no.raio + 12}
                textAnchor="middle"
              >
                {no.rotulo.length > 24 ? `${no.rotulo.slice(0, 22)}…` : no.rotulo}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="linha" style={{ flexWrap: "wrap", gap: "var(--espaco-4)" }}>
        {Object.entries(COR_POR_TIPO)
          .filter(([tipo]) => grafo.nos.some((n) => n.tipo === tipo))
          .map(([tipo, cor]) => (
            <span key={tipo} className="linha" style={{ gap: "var(--espaco-2)" }}>
              <span
                style={{
                  width: 9,
                  height: 9,
                  borderRadius: tipo === "incidente" ? 2 : "50%",
                  background: cor,
                  display: "inline-block",
                }}
              />
              <span className="terciario">{tipo}</span>
            </span>
          ))}
        <span className="terciario">
          {grafo.nos.length} nós · {grafo.arestas.length} relações
        </span>
      </div>

      {detalhe ? (
        <div className="mensagem mensagem--info">
          <div className="pilha" style={{ gap: 2 }}>
            <strong>{detalhe.rotulo}</strong>
            <span className="terciario">{detalhe.tipo}</span>
          </div>
        </div>
      ) : (
        <p className="terciario">
          Passe o cursor sobre um nó para realçar as suas relações.
        </p>
      )}
    </div>
  );
}
