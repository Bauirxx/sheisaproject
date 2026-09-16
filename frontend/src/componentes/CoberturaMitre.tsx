/**
 * Cobertura MITRE ATT&CK observada (§11).
 *
 * Mostra as técnicas que os incidentes registados de facto envolveram,
 * dispostas ao longo da cadeia de ataque. Serve a pergunta que um catálogo de
 * 709 técnicas não responde: *o que é que nos está a acontecer, e em que fase*.
 *
 * A distinção que dá sentido a este ecrã:
 *
 * **Afirmada** — a fonte de detecção declarou a técnica (o Wazuh traz
 * `rule.mitre.id`), ou um analista confirmou-a.
 * **Hipótese** — o motor inferiu-a a partir dos grupos de regra.
 *
 * Apresentá-las como a mesma coisa seria transformar suposição em facto, que é
 * precisamente o que o §11 proíbe. Por isso são duas contagens, com cores
 * diferentes, e a legenda di-lo por palavras.
 *
 * As tácticas vêm ordenadas pelo servidor, que lê essa ordem da matriz do
 * próprio bundle da MITRE — não de uma lista fixa que envelhece. Na versão 19
 * a MITRE substituiu `defense-evasion` por `stealth` e acrescentou
 * `defense-impairment`; uma ordem fixa teria desenhado a cadeia errada.
 */

import { useQuery } from "@tanstack/react-query";

import { pedir } from "@/api/cliente";
import { Carregando, Erro, Vazio } from "@/componentes/comuns";

interface Taccica {
  id: string;
  tactic_id: string;
  shortname: string;
  name: string;
  description: string;
  url: string | null;
  ordering: number;
}

interface EntradaDeCobertura {
  technique_id: string;
  name: string;
  tactic: string | null;
  incidentes_afirmados: number;
  incidentes_hipotese: number;
}

export function CoberturaMitre() {
  const tacticas = useQuery({
    queryKey: ["mitre-tacticas"],
    queryFn: () => pedir<Taccica[]>("/mitre/tactics"),
    staleTime: 60 * 60 * 1000,
  });

  const cobertura = useQuery({
    queryKey: ["mitre-cobertura"],
    queryFn: () => pedir<EntradaDeCobertura[]>("/mitre/coverage"),
  });

  if (tacticas.isPending || cobertura.isPending) return <Carregando />;
  if (tacticas.error) return <Erro erro={tacticas.error} />;
  if (cobertura.error) return <Erro erro={cobertura.error} />;

  const observadas = cobertura.data ?? [];

  if (observadas.length === 0) {
    return (
      <Vazio
        titulo="Nenhuma técnica observada"
        detalhe="Assim que um incidente for associado a técnicas ATT&CK — pela fonte de detecção, por um analista ou por inferência do motor — a cadeia de ataque aparece aqui."
      />
    );
  }

  // Agrupa por táctica, mantendo a ordem canónica que o servidor fornece.
  // As técnicas cuja táctica não consta são reunidas no fim, em vez de serem
  // descartadas: o que foi observado tem de aparecer.
  const porTaccica = new Map<string, EntradaDeCobertura[]>();
  for (const entrada of observadas) {
    const chave = entrada.tactic ?? "(sem táctica atribuída)";
    const lista = porTaccica.get(chave) ?? [];
    lista.push(entrada);
    porTaccica.set(chave, lista);
  }

  const ordenadas = (tacticas.data ?? [])
    .slice()
    .sort((a, b) => a.ordering - b.ordering)
    .filter((t) => porTaccica.has(t.name));

  const semTaccica = porTaccica.get("(sem táctica atribuída)") ?? [];

  const totalAfirmadas = observadas.reduce((s, e) => s + e.incidentes_afirmados, 0);
  const totalHipoteses = observadas.reduce((s, e) => s + e.incidentes_hipotese, 0);

  return (
    <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
      <div className="linha" style={{ gap: "var(--espaco-4)", flexWrap: "wrap" }}>
        <span className="terciario">
          {observadas.length} técnicas observadas em {ordenadas.length} fases da
          cadeia
        </span>
        <span className="linha terciario" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
          <span
            aria-hidden="true"
            style={{
              width: 10,
              height: 10,
              borderRadius: 2,
              background: "var(--sev-alta)",
              display: "inline-block",
            }}
          />
          {totalAfirmadas} afirmadas (declaradas pela fonte ou confirmadas)
        </span>
        <span className="linha terciario" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
          <span
            aria-hidden="true"
            style={{
              width: 10,
              height: 10,
              borderRadius: 2,
              border: "1px dashed var(--sev-media)",
              display: "inline-block",
            }}
          />
          {totalHipoteses} hipóteses do motor (não confirmam que a técnica ocorreu)
        </span>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: "var(--espaco-3)",
          alignItems: "start",
        }}
      >
        {ordenadas.map((taccica, indice) => (
          <div key={taccica.id} className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
            <div className="pilha" style={{ gap: 0 }}>
              <span className="terciario mono">
                {indice + 1}. {taccica.tactic_id}
              </span>
              <strong>{taccica.name}</strong>
            </div>
            {(porTaccica.get(taccica.name) ?? []).map((t) => (
              <CartaoDaTecnica key={t.technique_id} entrada={t} />
            ))}
          </div>
        ))}

        {semTaccica.length > 0 ? (
          <div className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
            <strong className="terciario">Sem táctica atribuída</strong>
            {semTaccica.map((t) => (
              <CartaoDaTecnica key={t.technique_id} entrada={t} />
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function CartaoDaTecnica({ entrada }: { entrada: EntradaDeCobertura }) {
  const soHipoteses =
    entrada.incidentes_afirmados === 0 && entrada.incidentes_hipotese > 0;

  return (
    <div
      style={{
        padding: "var(--espaco-2)",
        borderRadius: "var(--raio-pequeno)",
        background: "var(--contorno-suave)",
        // Contorno tracejado quando só existem hipóteses: a diferença entre
        // facto e suposição tem de se ver sem ler os números.
        border: soHipoteses ? "1px dashed var(--sev-media)" : "1px solid transparent",
      }}
    >
      <div className="linha linha--espalhada" style={{ gap: "var(--espaco-2)" }}>
        <span className="mono">{entrada.technique_id}</span>
        <span className="terciario">
          {entrada.incidentes_afirmados > 0 ? entrada.incidentes_afirmados : null}
          {entrada.incidentes_afirmados > 0 && entrada.incidentes_hipotese > 0
            ? " + "
            : null}
          {entrada.incidentes_hipotese > 0 ? `${entrada.incidentes_hipotese}?` : null}
        </span>
      </div>
      <div className="secundario" style={{ fontSize: "var(--texto-sm)" }}>
        {entrada.name}
      </div>
    </div>
  );
}
