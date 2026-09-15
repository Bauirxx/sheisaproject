/**
 * Tipos da API, escritos à mão a partir das respostas reais.
 *
 * São deliberadamente um subconjunto: só está aqui o que a interface consome.
 * Declarar o esquema inteiro daria a ilusão de cobertura e obrigaria a manter
 * sincronizado o que ninguém lê.
 */

// ------------------------------------------------------------------ comuns
export interface Pagina<T> {
  itens: T[];
  total: number;
  pagina: number;
  tamanho: number;
  total_paginas: number;
}

export interface ErroApi {
  codigo: string;
  mensagem: string;
  detalhes?: Record<string, unknown> | null;
}

export type Severidade = "INFO" | "BAIXA" | "MEDIA" | "ALTA" | "CRITICA";
export type Prioridade = "P1" | "P2" | "P3" | "P4";

export type EstadoIncidente =
  | "NOVO"
  | "ABERTO"
  | "TRIAGEM"
  | "INVESTIGACAO"
  | "CONTENCAO"
  | "ERRADICACAO"
  | "RECUPERACAO"
  | "RESOLVIDO"
  | "ENCERRADO"
  | "SUSPENSO"
  | "DUPLICADO"
  | "FALSO_POSITIVO"
  | "ESCALADO";

export type EstadoAlerta =
  | "NOVO"
  | "EM_TRIAGEM"
  | "CORRELACIONADO"
  | "PROMOVIDO"
  | "DESCARTADO"
  | "FALSO_POSITIVO"
  | "DUPLICADO";

export interface ResumoUtilizador {
  id: string;
  nome: string;
  email: string;
}

// ---------------------------------------------------------------- sessão
export interface Perfil {
  id: string;
  name: string;
  description: string;
}

export interface Utilizador {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  must_change_password: boolean;
  role: Perfil | null;
  team: { id: string; name: string } | null;
  last_login_at: string | null;
  permissions: string[];
}

/** O que `GET /users` devolve: sem a lista de permissões. */
export interface UtilizadorResumo {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  must_change_password: boolean;
  role: Perfil | null;
  team: { id: string; name: string } | null;
  last_login_at: string | null;
  created_at: string;
}

export interface RespostaEntrada {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_at: string;
  user: Utilizador;
}

// ---------------------------------------------------------------- alertas
/**
 * O que a **listagem** devolve.
 *
 * Deliberadamente sem a decomposição da triagem: um dicionário de factores por
 * cada uma de 25 linhas multiplicaria o tamanho da resposta para dados que só
 * se leem quando alguém abre um alerta em concreto. A decomposição vem em
 * `Alerta`, pedida ao detalhe.
 */
export interface AlertaResumo {
  id: string;
  reference: string;
  title: string;
  source_kind: string;
  source_name: string;
  severity: Severidade;
  status: EstadoAlerta;
  triage_score: number;
  false_positive_score: number;
  event_count: number;
  first_event_at: string;
  last_event_at: string;
  rule_id: string | null;
  rule_name: string | null;
  incident_id: string | null;
  correlation_outcome: string;
  asset: { id: string; identifier: string; name: string } | null;
  is_demo_data: boolean;
  tags: string[];
  created_at: string;
}

/** O que o **detalhe** devolve: tudo o do resumo, mais a explicação. */
export interface Alerta extends AlertaResumo {
  description: string;
  dedup_key: string;
  triage_factors: FactoresDeTriagem | Record<string, never>;
  triage_rationale: string;
  scored_at: string | null;
  correlation_rationale: string | null;
  correlated_at: string | null;
  incident_reference: string | null;
  transicoes_permitidas: string[];
}

/** Decomposição que o motor determinístico publica. A soma confere com o total. */
export interface FactoresDeTriagem {
  motor: string;
  versao: string;
  total_bruto: number;
  total_final: number;
  factores: Record<string, { pontos: number; razao: string; dados?: unknown }>;
}

// ------------------------------------------------------------- incidentes
export interface MetricasDoIncidente {
  tempo_ate_reconhecimento_segundos: number | null;
  tempo_ate_contencao_segundos: number | null;
  tempo_ate_resolucao_segundos: number | null;
  dentro_do_prazo: boolean | null;
  alertas_associados: number;
  observacoes: number;
  evidencias: number;
  tarefas_totais: number;
  tarefas_concluidas: number;
  accoes_executadas: number;
}

export interface IncidenteResumo {
  id: string;
  reference: string;
  title: string;
  category: string;
  severity: Severidade;
  priority: Prioridade;
  status: EstadoIncidente;
  assignee: ResumoUtilizador | null;
  detected_at: string;
  due_at: string | null;
  is_demo_data: boolean;
  created_at: string;
}

export interface Incidente extends IncidenteResumo {
  description: string;
  subtype: string | null;
  confidence: string;
  origin: string;
  source_kind: string;
  source_detail: string | null;
  /** A API devolve o identificador da equipa, não o objecto. */
  team_id: string | null;
  reporter: ResumoUtilizador | null;
  acknowledged_at: string | null;
  contained_at: string | null;
  eradicated_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  resolution_summary: string | null;
  lessons_learned: string | null;
  false_positive_reason: string | null;
  affected_users: string[];
  tags: string[];
  /** O ciclo de vida vem do servidor para o frontend não o duplicar. */
  transicoes_permitidas: EstadoIncidente[];
  metricas: MetricasDoIncidente;
  tecnicas?: TecnicaDoIncidente[];
  assets?: Activo[];
}

export interface TecnicaDoIncidente {
  id: string;
  technique: {
    technique_id: string;
    name: string;
    url: string | null;
    is_subtechnique: boolean;
    tactic_shortnames: string[];
  };
  /** `false` significa hipótese do motor; `true`, facto afirmado (§11). */
  is_asserted: boolean;
  confidence: string;
  rationale: string;
  evidence_refs: Record<string, unknown>;
}

export interface Activo {
  id: string;
  identifier: string;
  name: string;
  asset_type?: string;
  criticality: string;
  hostname: string | null;
  ip_address: string | null;
}

export interface Comentario {
  id: string;
  body: string;
  author: ResumoUtilizador | null;
  is_internal: boolean;
  is_system: boolean;
  created_at: string;
}

export interface Observacao {
  id: string;
  ioc: {
    id: string;
    ioc_type: string;
    value: string;
    reputation: string;
  };
  role: string;
  context: string | null;
  observed_at: string;
  source: string | null;
}

export interface Evidencia {
  id: string;
  name: string;
  description: string;
  evidence_type: string;
  original_filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  integrity_verified_at: string | null;
  integrity_ok: boolean | null;
  source: string;
  collected_at: string | null;
  uploaded_by: ResumoUtilizador | null;
  created_at: string;
}

export interface EntradaDaLinhaTemporal {
  instante: string;
  tipo: string;
  titulo: string;
  detalhe: string;
  autor: string | null;
  referencia: string | null;
  recurso_id: string | null;
  dados: Record<string, unknown>;
}

// --------------------------------------------------------------- resposta
export interface Aprovacao {
  id: string;
  decision: string;
  required_permission: string;
  requested_at: string;
  decided_at: string | null;
  decided_by: ResumoUtilizador | null;
  justification: string | null;
  expires_at: string | null;
}

export interface Accao {
  id: string;
  reference: string;
  incident_id: string;
  action_kind: string;
  title: string;
  rationale: string;
  target: Record<string, unknown>;
  status: string;
  risk_level: string;
  proposed_by: ResumoUtilizador | null;
  approvals: Aprovacao[];
  /** §4: a API diz se a acção é mesmo executável, e porque não, se não for. */
  executavel: boolean;
  motivo_nao_executavel: string | null;
  created_at: string;
}

// ----------------------------------------------------------- recomendações
export type TipoDeRecomendacao =
  | "TRIAGEM"
  | "CLASSIFICACAO"
  | "PRIORIZACAO"
  | "CORRELACAO"
  | "TECNICA_MITRE"
  | "PLAYBOOK"
  | "FALSO_POSITIVO"
  | "PROXIMO_PASSO";

export interface Recomendacao {
  id: string;
  kind: TipoDeRecomendacao;
  status: "PENDENTE" | "ACEITE" | "REJEITADA" | "EXPIRADA";
  target_type: "alert" | "incident";
  target_id: string;
  title: string;
  summary: string;
  explanation: string;
  confidence: number;
  factors: {
    motor: string;
    versao: string;
    total: number;
    factores: Record<string, { pontos: number; razao: string; dados?: unknown }>;
  };
  evidence_refs: Record<string, unknown>;
  proposed_change: Record<string, unknown>;
  engine: string;
  engine_version: string;
  decided_at: string | null;
  decided_by: ResumoUtilizador | null;
  decision_note: string | null;
  applied: boolean;
  created_at: string;
}

export interface DecisaoSobreRecomendacao {
  recomendacao: Recomendacao;
  /** O que aconteceu de facto ao alvo. Aceitar nem sempre altera algo. */
  efeito: string;
}

// ------------------------------------------------------------------ painel
export interface Painel {
  periodo_dias: number;
  incidentes: {
    total: number;
    activos: number;
    criticos: number;
    em_investigacao: number;
    resolvidos: number;
    encerrados: number;
    falsos_positivos: number;
    fora_de_prazo: number;
    sem_responsavel: number;
  };
  alertas: {
    total: number;
    por_triar: number;
    no_periodo: number;
    descartados_ou_falsos_positivos: number;
    taxa_falsos_positivos_percentagem: number;
  };
  eventos: { total: number };
  resposta: {
    aprovacoes_pendentes: number;
    accoes_executadas: number;
    tarefas_pendentes: number;
  };
  inteligencia: { indicadores_adversos: number };
}

// ------------------------------------------------------------------ grafo
export interface NoDoGrafo {
  id: string;
  tipo: string;
  rotulo: string;
  dados?: Record<string, unknown>;
}

export interface ArestaDoGrafo {
  origem: string;
  destino: string;
  tipo?: string;
  rotulo?: string;
}

export interface Grafo {
  nos: NoDoGrafo[];
  arestas: ArestaDoGrafo[];
}

// -------------------------------------------------------------- relatórios
export interface Relatorio {
  id: string;
  reference: string;
  title: string;
  kind: string;
  parameters: Record<string, unknown>;
  period_start: string | null;
  period_end: string | null;
  incident_id: string | null;
  record_count: number;
  created_at: string;
}

export interface RelatorioDetalhado extends Relatorio {
  content: Record<string, unknown>;
}

// ------------------------------------------------------------- integrações
/**
 * Integração com um sistema externo (§26).
 *
 * `status` reflecte verificação real, não declaração: só passa a `ACTIVA`
 * depois de um teste de ligação bem-sucedido ou de ter recebido eventos.
 * `variaveis_em_falta` lista os nomes das variáveis de ambiente esperadas que
 * não estão definidas — os valores nunca são expostos pela API.
 */
export interface Integracao {
  id: string;
  name: string;
  kind: string;
  direction: string;
  description: string;
  status: string;
  is_enabled: boolean;
  config: Record<string, unknown>;
  secret_env_vars: string[];
  variaveis_em_falta: string[];
  last_check_at: string | null;
  last_check_ok: boolean | null;
  last_check_detail: string | null;
  last_error: string | null;
  events_received: number;
  last_event_at: string | null;
  actions_executed: number;
  actions_failed: number;
  supported_actions: string[];
  chaves_activas: number;
}

export interface Notificacao {
  id: string;
  kind: string;
  severity: string;
  title: string;
  body: string;
  resource_type: string | null;
  resource_id: string | null;
  resource_reference: string | null;
  read_at: string | null;
  created_at: string;
}

// ------------------------------------------------- agregações do painel (§17)
export interface Distribuicao {
  periodo_dias: number;
  incidentes_por_severidade: Record<string, number>;
  incidentes_por_categoria: Record<string, number>;
  incidentes_por_estado: Record<string, number>;
  incidentes_por_fonte: Record<string, number>;
  alertas_por_fonte: Record<string, number>;
}

export interface PontoDaTendencia {
  dia: string;
  incidentes: number;
  incidentes_graves: number;
  alertas: number;
}

export interface MetricasDeResposta {
  periodo_dias: number;
  tempo_medio_reconhecimento_segundos: number | null;
  tempo_mediano_reconhecimento_segundos: number | null;
  incidentes_reconhecidos: number;
  tempo_medio_resolucao_segundos: number | null;
  tempo_mediano_resolucao_segundos: number | null;
  incidentes_resolvidos: number;
  cumprimento_prazo: {
    avaliados: number;
    dentro_do_prazo: number;
    percentagem: number | null;
  };
  /** A API explica que as médias só contam incidentes com o marco registado. */
  nota: string;
}

export interface CargaDeAnalista {
  utilizador_id: string;
  nome: string;
  email: string;
  incidentes_activos: number;
  incidentes_graves: number;
  tarefas_pendentes: number;
}
