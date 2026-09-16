/**
 * Edição de indicadores e activos.
 *
 * Ambos enviam só os campos alterados, pela mesma razão que a edição de
 * incidente: a auditoria regista valor anterior e novo a partir do que mudou
 * de facto, e submeter o formulário inteiro encheria o registo de campos
 * "alterados" para o mesmo valor.
 *
 * **Primeira e última observação não são editáveis.** São calculadas a partir
 * de avistamentos reais — cada vez que o indicador aparece num evento — e um
 * campo escrito à mão destruiria a única coisa que as torna confiáveis. O
 * mesmo vale para a contagem de avistamentos.
 *
 * **Permitir um indicador exige motivo.** A lista de permitidos suprime
 * alertas futuros que o contenham; sem o motivo registado, ninguém consegue
 * mais tarde perceber porque é que um endereço deixou de gerar alertas.
 */

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { pedir } from "@/api/cliente";
import type { Activo, Indicador } from "@/api/tipos";
import { useSessao } from "@/autenticacao/contexto";
import { Erro, instante } from "@/componentes/comuns";

const REPUTACOES = [
  { valor: "DESCONHECIDA", rotulo: "Desconhecida" },
  { valor: "BENIGNA", rotulo: "Benigna" },
  { valor: "SUSPEITA", rotulo: "Suspeita" },
  { valor: "MALICIOSA", rotulo: "Maliciosa" },
];

const CONFIANCAS = [
  { valor: "BAIXA", rotulo: "Baixa" },
  { valor: "MEDIA", rotulo: "Média" },
  { valor: "ALTA", rotulo: "Alta" },
  { valor: "CONFIRMADA", rotulo: "Confirmada" },
];

const CRITICIDADES = [
  { valor: "BAIXA", rotulo: "Baixa" },
  { valor: "MEDIA", rotulo: "Média" },
  { valor: "ALTA", rotulo: "Alta" },
  { valor: "CRITICA", rotulo: "Crítica" },
];

const TIPOS_DE_ACTIVO = [
  { valor: "SERVIDOR", rotulo: "Servidor" },
  { valor: "ESTACAO", rotulo: "Estação de trabalho" },
  { valor: "EQUIPAMENTO_REDE", rotulo: "Equipamento de rede" },
  { valor: "APLICACAO", rotulo: "Aplicação" },
  { valor: "BASE_DADOS", rotulo: "Base de dados" },
  { valor: "SERVICO_CLOUD", rotulo: "Serviço cloud" },
  { valor: "DISPOSITIVO_MOVEL", rotulo: "Dispositivo móvel" },
  { valor: "OUTRO", rotulo: "Outro" },
];

// ------------------------------------------------------------- indicadores
export function EditarIndicador({
  indicador,
  aoFechar,
}: {
  indicador: Indicador;
  aoFechar: () => void;
}) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();

  const [reputacao, definirReputacao] = useState(indicador.reputation);
  const [confianca, definirConfianca] = useState(indicador.confidence);
  const [contexto, definirContexto] = useState(indicador.context ?? "");
  const [etiquetas, definirEtiquetas] = useState(indicador.tags.join(", "));

  const [permitido, definirPermitido] = useState(indicador.is_allowlisted);
  const [motivo, definirMotivo] = useState(indicador.allowlist_reason ?? "");

  const invalidar = async () => {
    await clienteDeDados.invalidateQueries({ queryKey: ["indicadores"] });
    await clienteDeDados.invalidateQueries({ queryKey: ["indicador", indicador.id] });
  };

  function alteracoes(): Record<string, unknown> {
    const mudou: Record<string, unknown> = {};
    if (reputacao !== indicador.reputation) mudou.reputation = reputacao;
    if (confianca !== indicador.confidence) mudou.confidence = confianca;
    if (contexto !== (indicador.context ?? "")) mudou.context = contexto;
    const lista = etiquetas.split(",").map((t) => t.trim()).filter(Boolean);
    if (lista.join(" ") !== indicador.tags.join(" ")) mudou.tags = lista;
    return mudou;
  }

  const guardar = useMutation({
    mutationFn: () =>
      pedir<Indicador>(`/iocs/${indicador.id}`, {
        metodo: "PATCH",
        corpo: alteracoes(),
      }),
    onSuccess: async () => {
      await invalidar();
      aoFechar();
    },
  });

  const alterarPermissao = useMutation({
    mutationFn: () =>
      pedir<Indicador>(`/iocs/${indicador.id}/allowlist`, {
        metodo: "POST",
        corpo: { is_allowlisted: permitido, reason: motivo },
      }),
    onSuccess: invalidar,
  });

  if (!pode("iocs:manage")) return null;

  const porGravar = Object.keys(alteracoes()).length;
  const permissaoMudou = permitido !== indicador.is_allowlisted;

  return (
    <div className="pilha" style={{ gap: "var(--espaco-4)" }}>
      <form
        className="pilha"
        style={{ gap: "var(--espaco-3)" }}
        onSubmit={(e) => {
          e.preventDefault();
          guardar.mutate();
        }}
      >
        <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
          <label className="campo">
            <span className="campo__etiqueta">Reputação</span>
            <select
              className="selector"
              value={reputacao}
              onChange={(e) => definirReputacao(e.target.value)}
            >
              {REPUTACOES.map((r) => (
                <option key={r.valor} value={r.valor}>
                  {r.rotulo}
                </option>
              ))}
            </select>
          </label>
          <label className="campo">
            <span className="campo__etiqueta">Confiança</span>
            <select
              className="selector"
              value={confianca}
              onChange={(e) => definirConfianca(e.target.value)}
            >
              {CONFIANCAS.map((c) => (
                <option key={c.valor} value={c.valor}>
                  {c.rotulo}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="campo">
          <span className="campo__etiqueta">Contexto</span>
          <textarea
            className="area-texto"
            value={contexto}
            maxLength={4000}
            placeholder="O que se sabe sobre este indicador e de onde veio."
            onChange={(e) => definirContexto(e.target.value)}
          />
        </label>

        <label className="campo">
          <span className="campo__etiqueta">Etiquetas</span>
          <input
            type="text"
            value={etiquetas}
            placeholder="separadas por vírgula"
            onChange={(e) => definirEtiquetas(e.target.value)}
          />
        </label>

        {/* Só leitura: derivam de avistamentos, não de escrita manual. */}
        <div className="propriedades">
          <div className="propriedade">
            <span className="propriedade__rotulo">Primeira observação</span>
            <span className="propriedade__valor">
              {indicador.first_seen ? instante(indicador.first_seen) : "—"}
            </span>
          </div>
          <div className="propriedade">
            <span className="propriedade__rotulo">Última observação</span>
            <span className="propriedade__valor">
              {indicador.last_seen ? instante(indicador.last_seen) : "—"}
            </span>
          </div>
          <div className="propriedade">
            <span className="propriedade__rotulo">Avistamentos</span>
            <span className="propriedade__valor mono">{indicador.sighting_count}</span>
          </div>
        </div>
        <p className="terciario">
          Estes três valores são calculados a partir de avistamentos reais e não
          são editáveis: escrevê-los à mão destruiria o que os torna confiáveis.
        </p>

        {guardar.error ? <Erro erro={guardar.error} /> : null}
        <div className="linha" style={{ gap: "var(--espaco-2)" }}>
          <button
            className="botao botao--primario botao--pequeno"
            disabled={guardar.isPending || porGravar === 0}
          >
            {guardar.isPending
              ? "A guardar…"
              : porGravar === 0
                ? "Sem alterações"
                : `Guardar ${porGravar}`}
          </button>
          <button
            type="button"
            className="botao botao--discreto botao--pequeno"
            onClick={aoFechar}
          >
            Fechar
          </button>
        </div>
      </form>

      {/* A lista de permitidos é uma decisão separada, com consequência
          operacional própria, e por isso tem o seu próprio botão. */}
      <div className="cartao pilha" style={{ gap: "var(--espaco-2)" }}>
        <strong>Lista de permitidos</strong>
        <p className="terciario">
          Permitir este indicador suprime alertas futuros que o contenham.
        </p>
        <label className="linha" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={permitido}
            onChange={(e) => definirPermitido(e.target.checked)}
          />
          <span>Tratar como benigno</span>
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Motivo (obrigatório)</span>
          <textarea
            className="area-texto"
            value={motivo}
            minLength={5}
            maxLength={2000}
            placeholder="Porque é que este indicador é legítimo."
            onChange={(e) => definirMotivo(e.target.value)}
          />
        </label>
        {alterarPermissao.error ? <Erro erro={alterarPermissao.error} /> : null}
        <div className="linha">
          <button
            type="button"
            className="botao botao--pequeno"
            disabled={
              alterarPermissao.isPending || !permissaoMudou || motivo.trim().length < 5
            }
            onClick={() => alterarPermissao.mutate()}
          >
            {alterarPermissao.isPending
              ? "A aplicar…"
              : permitido
                ? "Marcar como benigno"
                : "Remover da lista"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------- activos
export function EditarActivo({
  activo,
  aoFechar,
}: {
  activo: Activo;
  aoFechar: () => void;
}) {
  const clienteDeDados = useQueryClient();
  const { pode } = useSessao();

  const [nome, definirNome] = useState(activo.name);
  const [tipo, definirTipo] = useState(activo.asset_type ?? "OUTRO");
  const [criticidade, definirCriticidade] = useState(activo.criticality);
  const [hostname, definirHostname] = useState(activo.hostname ?? "");
  const [ip, definirIp] = useState(activo.ip_address ?? "");
  const [so, definirSo] = useState(activo.operating_system ?? "");
  const [dono, definirDono] = useState(activo.owner ?? "");
  const [servico, definirServico] = useState(activo.business_service ?? "");
  const [agente, definirAgente] = useState(activo.wazuh_agent_id ?? "");
  const [descricao, definirDescricao] = useState(activo.description ?? "");
  const [activoSim, definirActivoSim] = useState(activo.is_active ?? true);

  function alteracoes(): Record<string, unknown> {
    const m: Record<string, unknown> = {};
    if (nome !== activo.name) m.name = nome;
    if (tipo !== (activo.asset_type ?? "OUTRO")) m.asset_type = tipo;
    if (criticidade !== activo.criticality) m.criticality = criticidade;
    if (hostname !== (activo.hostname ?? "")) m.hostname = hostname || null;
    if (ip !== (activo.ip_address ?? "")) m.ip_address = ip || null;
    if (so !== (activo.operating_system ?? "")) m.operating_system = so || null;
    if (dono !== (activo.owner ?? "")) m.owner = dono || null;
    if (servico !== (activo.business_service ?? "")) {
      m.business_service = servico || null;
    }
    if (agente !== (activo.wazuh_agent_id ?? "")) {
      m.wazuh_agent_id = agente || null;
    }
    if (descricao !== (activo.description ?? "")) m.description = descricao;
    if (activoSim !== (activo.is_active ?? true)) m.is_active = activoSim;
    return m;
  }

  const guardar = useMutation({
    mutationFn: () =>
      pedir<Activo>(`/assets/${activo.id}`, { metodo: "PATCH", corpo: alteracoes() }),
    onSuccess: async () => {
      await clienteDeDados.invalidateQueries({ queryKey: ["activos"] });
      aoFechar();
    },
  });

  if (!pode("assets:manage")) return null;

  const porGravar = Object.keys(alteracoes()).length;

  return (
    <form
      className="pilha"
      style={{ gap: "var(--espaco-3)" }}
      onSubmit={(e) => {
        e.preventDefault();
        guardar.mutate();
      }}
    >
      <label className="campo">
        <span className="campo__etiqueta">Nome</span>
        <input
          type="text"
          required
          maxLength={160}
          value={nome}
          onChange={(e) => definirNome(e.target.value)}
        />
      </label>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo">
          <span className="campo__etiqueta">Tipo</span>
          <select
            className="selector"
            value={tipo}
            onChange={(e) => definirTipo(e.target.value)}
          >
            {TIPOS_DE_ACTIVO.map((t) => (
              <option key={t.valor} value={t.valor}>
                {t.rotulo}
              </option>
            ))}
          </select>
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Criticidade</span>
          <select
            className="selector"
            value={criticidade}
            onChange={(e) => definirCriticidade(e.target.value)}
          >
            {CRITICIDADES.map((c) => (
              <option key={c.valor} value={c.valor}>
                {c.rotulo}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="terciario">
        A criticidade entra directamente na pontuação de triagem dos alertas que
        afectem este activo.
      </p>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo">
          <span className="campo__etiqueta">Hostname</span>
          <input
            type="text"
            maxLength={255}
            value={hostname}
            onChange={(e) => definirHostname(e.target.value)}
          />
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Endereço IP</span>
          <input
            type="text"
            maxLength={45}
            value={ip}
            onChange={(e) => definirIp(e.target.value)}
          />
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Agente Wazuh</span>
          <input
            type="text"
            maxLength={32}
            value={agente}
            placeholder="ex.: 003"
            onChange={(e) => definirAgente(e.target.value)}
          />
        </label>
      </div>
      <p className="terciario">
        O identificador do agente Wazuh é o que liga um alerta recebido a este
        activo sem ter de adivinhar pelo endereço, que muda com DHCP.
      </p>

      <div className="linha" style={{ gap: "var(--espaco-3)", flexWrap: "wrap" }}>
        <label className="campo">
          <span className="campo__etiqueta">Sistema operativo</span>
          <input
            type="text"
            maxLength={120}
            value={so}
            onChange={(e) => definirSo(e.target.value)}
          />
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Responsável</span>
          <input
            type="text"
            maxLength={120}
            value={dono}
            onChange={(e) => definirDono(e.target.value)}
          />
        </label>
        <label className="campo">
          <span className="campo__etiqueta">Serviço de negócio</span>
          <input
            type="text"
            maxLength={160}
            value={servico}
            onChange={(e) => definirServico(e.target.value)}
          />
        </label>
      </div>

      <label className="campo">
        <span className="campo__etiqueta">Descrição</span>
        <textarea
          className="area-texto"
          value={descricao}
          maxLength={4000}
          onChange={(e) => definirDescricao(e.target.value)}
        />
      </label>

      <label className="linha" style={{ gap: "var(--espaco-2)", alignItems: "center" }}>
        <input
          type="checkbox"
          checked={activoSim}
          onChange={(e) => definirActivoSim(e.target.checked)}
        />
        <span>Activo em serviço</span>
      </label>

      {guardar.error ? <Erro erro={guardar.error} /> : null}
      <div className="linha" style={{ gap: "var(--espaco-2)" }}>
        <button
          className="botao botao--primario botao--pequeno"
          disabled={guardar.isPending || porGravar === 0}
        >
          {guardar.isPending
            ? "A guardar…"
            : porGravar === 0
              ? "Sem alterações"
              : `Guardar ${porGravar}`}
        </button>
        <button
          type="button"
          className="botao botao--discreto botao--pequeno"
          onClick={aoFechar}
        >
          Fechar
        </button>
      </div>
    </form>
  );
}
