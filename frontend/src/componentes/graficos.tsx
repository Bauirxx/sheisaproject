/**
 * Gráficos do painel (§17).
 *
 * Desenhados em SVG à mão, sem biblioteca de visualização. Não é ascetismo:
 * são três formas simples, e uma dependência de gráficos traria centenas de
 * kilobytes e um sistema de temas próprio a competir com o desta interface.
 *
 * Duas regras que valem mais do que o aspecto:
 *
 * **O eixo começa em zero e o máximo é o máximo real.** Um eixo truncado faz
 * uma variação de 2% parecer uma crise — num painel de segurança isso não é
 * uma escolha estética, é induzir em erro quem decide.
 *
 * **Zero é desenhado como zero.** Dias sem actividade aparecem vazios, não
 * interpolados: a série vem contínua da API precisamente para que o silêncio
 * se veja.
 */

import type { ReactNode } from "react";

/** Paleta por severidade, alinhada com os distintivos do resto da interface. */
const COR_DA_SEVERIDADE: Record<string, string> = {
  CRITICA: "var(--sev-critica, #dc2626)",
  ALTA: "var(--sev-alta, #f97316)",
  MEDIA: "var(--sev-media, #f59e0b)",
  BAIXA: "var(--sev-baixa, #22c55e)",
  INFO: "var(--sev-info, #38bdf8)",
};

// Linha dos alertas na cor de acção da interface: sao o sinal em bruto,
// nao um nivel de gravidade, e por isso ficam fora da escala de severidade.
const COR_NEUTRA = "var(--primaria)";

function Moldura({
  titulo,
  nota,
  children,
}: {
  titulo: string;
  nota?: string;
  children: ReactNode;
}) {
  return (
    <div className="cartao pilha" style={{ gap: "var(--espaco-3)" }}>
      <div className="pilha" style={{ gap: 0 }}>
        <h3>{titulo}</h3>
        {nota ? <span className="terciario">{nota}</span> : null}
      </div>
      {children}
    </div>
  );
}

function SemDados({ texto }: { texto: string }) {
  return <p className="terciario">{texto}</p>;
}

/**
 * Barras horizontais para distribuições categóricas.
 *
 * Horizontais e não verticais porque as etiquetas são palavras
 * ("TENTATIVA_INTRUSAO"), e num gráfico vertical teriam de ser rodadas ou
 * abreviadas — em ambos os casos ficam menos legíveis do que o número.
 */
export function BarrasCategoricas({
  titulo,
  nota,
  dados,
  colorir,
}: {
  titulo: string;
  nota?: string;
  dados: Record<string, number>;
  colorir?: (chave: string) => string;
}) {
  const entradas = Object.entries(dados)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);

  if (entradas.length === 0) {
    return (
      <Moldura titulo={titulo} nota={nota}>
        <SemDados texto="Sem registos no período." />
      </Moldura>
    );
  }

  const maximo = Math.max(...entradas.map(([, v]) => v));
  const total = entradas.reduce((s, [, v]) => s + v, 0);

  return (
    <Moldura titulo={titulo} nota={nota}>
      <div className="pilha" style={{ gap: "var(--espaco-2)" }}>
        {entradas.map(([chave, valor]) => (
          <div key={chave} className="pilha" style={{ gap: 2 }}>
            <div className="linha linha--espalhada">
              <span className="secundario">{chave.replaceAll("_", " ").toLowerCase()}</span>
              <span className="mono">
                {valor}
                <span className="terciario">
                  {" "}
                  ({Math.round((valor / total) * 100)}%)
                </span>
              </span>
            </div>
            <div
              style={{
                height: 8,
                background: "var(--contorno-suave)",
                borderRadius: 4,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${(valor / maximo) * 100}%`,
                  height: "100%",
                  background: colorir?.(chave) ?? COR_NEUTRA,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </Moldura>
  );
}

export function corDaSeveridade(chave: string): string {
  return COR_DA_SEVERIDADE[chave] ?? COR_NEUTRA;
}

interface PontoDaSerie {
  dia: string;
  incidentes: number;
  incidentes_graves: number;
  alertas: number;
}

/**
 * Série temporal de incidentes e alertas.
 *
 * Os alertas vêm numa escala própria porque são tipicamente uma ordem de
 * grandeza mais numerosos: partilhar o eixo faria a linha dos incidentes
 * colar-se ao fundo e deixar de dizer nada. As duas escalas estão declaradas
 * na legenda, para que ninguém compare as alturas como se fossem comparáveis.
 */
export function SerieTemporal({ dados }: { dados: PontoDaSerie[] }) {
  if (dados.length === 0) {
    return (
      <Moldura titulo="Tendência">
        <SemDados texto="Sem série disponível." />
      </Moldura>
    );
  }

  const L = 640;
  const A = 160;
  const margem = { topo: 12, baixo: 24, esquerda: 8, direita: 8 };
  const largura = L - margem.esquerda - margem.direita;
  const altura = A - margem.topo - margem.baixo;

  const maxIncidentes = Math.max(1, ...dados.map((d) => d.incidentes));
  const maxAlertas = Math.max(1, ...dados.map((d) => d.alertas));

  const x = (i: number) =>
    margem.esquerda + (dados.length === 1 ? largura / 2 : (i / (dados.length - 1)) * largura);
  const y = (v: number, max: number) => margem.topo + altura - (v / max) * altura;

  const caminho = (campo: (d: PontoDaSerie) => number, max: number) =>
    dados.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(campo(d), max).toFixed(1)}`).join(" ");

  const totalIncidentes = dados.reduce((s, d) => s + d.incidentes, 0);
  const totalAlertas = dados.reduce((s, d) => s + d.alertas, 0);

  // `dados[0]` é seguro porque o caso vazio já retornou acima, mas o
  // `noUncheckedIndexedAccess` não o sabe. Extrair aqui é preferível a um
  // `!`: se um dia o guarda mudar, isto continua correcto.
  const primeiroDia = dados.at(0)?.dia ?? "";
  const ultimoDia = dados.at(-1)?.dia ?? "";

  return (
    <Moldura
      titulo="Tendência"
      nota={`${dados.length} dias · ${totalIncidentes} incidentes · ${totalAlertas} alertas`}
    >
      <svg
        viewBox={`0 0 ${L} ${A}`}
        style={{ width: "100%", height: "auto" }}
        role="img"
        aria-label={`Série temporal de ${dados.length} dias: ${totalIncidentes} incidentes e ${totalAlertas} alertas.`}
      >
        {/* Linha de base: torna visível que o eixo começa em zero. */}
        <line
          x1={margem.esquerda}
          y1={margem.topo + altura}
          x2={L - margem.direita}
          y2={margem.topo + altura}
          stroke="currentColor"
          strokeOpacity={0.2}
        />
        <path
          d={caminho((d) => d.alertas, maxAlertas)}
          fill="none"
          stroke={COR_NEUTRA}
          strokeOpacity={0.45}
          strokeWidth={1.5}
        />
        <path
          d={caminho((d) => d.incidentes, maxIncidentes)}
          fill="none"
          stroke={corDaSeveridade("ALTA")}
          strokeWidth={2}
        />
        <path
          d={caminho((d) => d.incidentes_graves, maxIncidentes)}
          fill="none"
          stroke={corDaSeveridade("CRITICA")}
          strokeWidth={2}
          strokeDasharray="4 3"
        />
        {/* Primeiro e último dia, para ancorar a série no tempo. */}
        <text x={margem.esquerda} y={A - 6} fontSize="10" fill="currentColor" opacity={0.6}>
          {primeiroDia}
        </text>
        <text
          x={L - margem.direita}
          y={A - 6}
          fontSize="10"
          textAnchor="end"
          fill="currentColor"
          opacity={0.6}
        >
          {ultimoDia}
        </text>
      </svg>

      <div className="linha" style={{ gap: "var(--espaco-4)", flexWrap: "wrap" }}>
        <Legenda cor={corDaSeveridade("ALTA")} texto={`Incidentes (máx. ${maxIncidentes})`} />
        <Legenda
          cor={corDaSeveridade("CRITICA")}
          texto="Graves (alta e crítica)"
          tracejado
        />
        <Legenda cor={COR_NEUTRA} texto={`Alertas (escala própria, máx. ${maxAlertas})`} />
      </div>
    </Moldura>
  );
}

function Legenda({
  cor,
  texto,
  tracejado,
}: {
  cor: string;
  texto: string;
  tracejado?: boolean;
}) {
  return (
    <span className="linha terciario" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
      <svg width="20" height="6" aria-hidden="true">
        <line
          x1="0"
          y1="3"
          x2="20"
          y2="3"
          stroke={cor}
          strokeWidth="2"
          strokeDasharray={tracejado ? "4 3" : undefined}
        />
      </svg>
      {texto}
    </span>
  );
}

/** Formata uma duração em segundos de forma legível. */
export function duracaoLegivel(segundos: number | null): string {
  if (segundos === null || segundos === undefined) return "—";
  if (segundos < 60) return `${segundos}s`;
  if (segundos < 3600) return `${Math.round(segundos / 60)} min`;
  if (segundos < 86400) {
    const h = Math.floor(segundos / 3600);
    const m = Math.round((segundos % 3600) / 60);
    return m ? `${h}h ${m}min` : `${h}h`;
  }
  return `${Math.floor(segundos / 86400)}d ${Math.round((segundos % 86400) / 3600)}h`;
}
