/**
 * Registo manual de incidente (§4.13, tela 4 · RF04).
 *
 * Existe porque nem tudo chega por detecção automática: uma denúncia interna,
 * um telefonema, uma comunicação de terceiros. O §4.3 lista o
 * "utilizador/analista" ao lado do QRadar, do NetScout e do Suricata como fonte
 * legítima.
 *
 * A prioridade fica deliberadamente por omissão: o servidor deriva-a da
 * severidade segundo a política da organização. Oferecer o campo convidaria a
 * escolher uma combinação incoerente — severidade crítica com prioridade P4 —
 * que depois nenhuma fila sabe ordenar.
 */

import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { consulta, pedir } from "@/api/cliente";
import type { Activo, Incidente, Pagina, UtilizadorResumo } from "@/api/tipos";
import { Erro } from "@/componentes/comuns";
import { CATEGORIAS, SEVERIDADES } from "@/componentes/listagem";

export function IncidenteNovo() {
  const navegar = useNavigate();

  const [titulo, definirTitulo] = useState("");
  const [descricao, definirDescricao] = useState("");
  const [categoria, definirCategoria] = useState("OUTRO");
  const [severidade, definirSeveridade] = useState("MEDIA");
  const [responsavel, definirResponsavel] = useState("");
  const [activos, definirActivos] = useState<string[]>([]);
  const [detectadoEm, definirDetectadoEm] = useState("");

  // As listas auxiliares podem falhar por falta de permissão sem que isso
  // impeça o registo: os campos correspondentes ficam simplesmente vazios.
  const { data: utilizadores } = useQuery({
    queryKey: ["utilizadores-para-atribuir"],
    queryFn: () =>
      pedir<Pagina<UtilizadorResumo>>(`/users${consulta({ size: 100 })}`),
    retry: false,
  });

  const { data: inventario } = useQuery({
    queryKey: ["activos-para-associar"],
    queryFn: () => pedir<Pagina<Activo>>(`/assets${consulta({ size: 100 })}`),
    retry: false,
  });

  const criar = useMutation({
    mutationFn: () =>
      pedir<Incidente>("/incidents", {
        metodo: "POST",
        corpo: {
          title: titulo.trim(),
          description: descricao.trim(),
          category: categoria,
          severity: severidade,
          ...(responsavel ? { assignee_id: responsavel } : {}),
          ...(activos.length ? { asset_ids: activos } : {}),
          // `datetime-local` não traz fuso; converte-se para ISO com o fuso do
          // navegador, que é o do analista que está a registar.
          ...(detectadoEm
            ? { detected_at: new Date(detectadoEm).toISOString() }
            : {}),
        },
      }),
    onSuccess: (incidente) => navegar(`/incidentes/${incidente.id}`),
  });

  const submeter = (evento: FormEvent) => {
    evento.preventDefault();
    criar.mutate();
  };

  const alternarActivo = (id: string) => {
    definirActivos((actuais) =>
      actuais.includes(id) ? actuais.filter((a) => a !== id) : [...actuais, id],
    );
  };

  return (
    <>
      <div className="pagina__cabecalho">
        <div className="pagina__titulo">
          <h1>Registar incidente</h1>
          <p className="pagina__descricao">
            Para ocorrências que não chegaram por detecção automática — uma
            denúncia interna, uma comunicação de terceiros, um achado durante
            uma verificação.
          </p>
        </div>
        <div className="pagina__accoes">
          <Link to="/incidentes" className="botao">
            Cancelar
          </Link>
        </div>
      </div>

      <form onSubmit={submeter} style={{ maxWidth: "760px" }}>
        <div className="cartao pilha">
          <div className="campo">
            <label className="campo__etiqueta" htmlFor="titulo">
              Título
            </label>
            <input
              id="titulo"
              className="entrada"
              required
              minLength={4}
              maxLength={300}
              value={titulo}
              onChange={(e) => definirTitulo(e.target.value)}
              placeholder="Ex.: Acesso não autorizado ao servidor de ficheiros"
            />
          </div>

          <div className="campo">
            <label className="campo__etiqueta" htmlFor="descricao">
              Descrição
            </label>
            <textarea
              id="descricao"
              className="area-texto"
              value={descricao}
              onChange={(e) => definirDescricao(e.target.value)}
              placeholder="O que se sabe até agora: quem reportou, o que foi observado, que sistemas estão envolvidos."
            />
            <span className="campo__ajuda">
              Este texto entra no relatório do incidente.
            </span>
          </div>

          <div className="grelha grelha--3">
            <div className="campo">
              <label className="campo__etiqueta" htmlFor="categoria">
                Categoria
              </label>
              <select
                id="categoria"
                className="selector"
                value={categoria}
                onChange={(e) => definirCategoria(e.target.value)}
              >
                {CATEGORIAS.map((c) => (
                  <option key={c.valor} value={c.valor}>
                    {c.rotulo}
                  </option>
                ))}
              </select>
              <span className="campo__ajuda">Taxonomia eCSIRT.net/ENISA.</span>
            </div>

            <div className="campo">
              <label className="campo__etiqueta" htmlFor="severidade">
                Severidade
              </label>
              <select
                id="severidade"
                className="selector"
                value={severidade}
                onChange={(e) => definirSeveridade(e.target.value)}
              >
                {SEVERIDADES.map((s) => (
                  <option key={s.valor} value={s.valor}>
                    {s.rotulo}
                  </option>
                ))}
              </select>
              <span className="campo__ajuda">
                A prioridade e o prazo derivam daqui.
              </span>
            </div>

            <div className="campo">
              <label className="campo__etiqueta" htmlFor="detectado">
                Detectado em
              </label>
              <input
                id="detectado"
                className="entrada"
                type="datetime-local"
                value={detectadoEm}
                onChange={(e) => definirDetectadoEm(e.target.value)}
              />
              <span className="campo__ajuda">
                Quando ocorreu, não quando está a registar. Em branco, usa agora.
              </span>
            </div>
          </div>

          {utilizadores ? (
            <div className="campo">
              <label className="campo__etiqueta" htmlFor="responsavel">
                Responsável
              </label>
              <select
                id="responsavel"
                className="selector"
                value={responsavel}
                onChange={(e) => definirResponsavel(e.target.value)}
              >
                <option value="">Sem responsável, por agora</option>
                {utilizadores.itens
                  .filter((u) => u.is_active)
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.full_name} — {u.role?.name ?? "sem perfil"}
                    </option>
                  ))}
              </select>
            </div>
          ) : null}

          {inventario && inventario.itens.length > 0 ? (
            <div className="campo">
              <label className="campo__etiqueta">Activos afectados</label>
              <div
                className="pilha"
                style={{
                  gap: "var(--espaco-2)",
                  maxHeight: "190px",
                  overflowY: "auto",
                  border: "1px solid var(--contorno)",
                  borderRadius: "var(--raio)",
                  padding: "var(--espaco-3)",
                }}
              >
                {inventario.itens.map((activo) => (
                  <label
                    key={activo.id}
                    className="linha"
                    style={{ gap: "var(--espaco-2)", cursor: "pointer" }}
                  >
                    <input
                      type="checkbox"
                      checked={activos.includes(activo.id)}
                      onChange={() => alternarActivo(activo.id)}
                    />
                    <span className="mono">{activo.identifier}</span>
                    <span className="secundario truncar">{activo.name}</span>
                    <span className="terciario">
                      {activo.criticality.toLowerCase()}
                    </span>
                  </label>
                ))}
              </div>
              <span className="campo__ajuda">
                A criticidade do activo entra na pontuação de risco.
              </span>
            </div>
          ) : null}

          {criar.error ? <Erro erro={criar.error} /> : null}

          <div className="linha">
            <button
              type="submit"
              className="botao botao--primario"
              disabled={criar.isPending || titulo.trim().length < 4}
            >
              {criar.isPending ? "A registar…" : "Registar incidente"}
            </button>
            <span className="terciario">
              A referência é gerada automaticamente pelo sistema.
            </span>
          </div>
        </div>
      </form>
    </>
  );
}
