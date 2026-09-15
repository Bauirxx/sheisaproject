"""Motor de recomendações determinístico (§12).

Propõe ao analista a decisão seguinte — triar, classificar, conter, associar
uma técnica, aplicar um playbook — **sem nunca a tomar por ele**. Cada
recomendação transporta a decomposição que a produziu, a confiança calculada a
partir dessa decomposição, e os registos concretos que a sustentam.

Partilha deliberadamente o vocabulário do motor de triagem
(`app.intelligence.triage`): o mesmo `Factor`, com nome, pontos e razão. Um
analista que já sabe ler a pontuação de um alerta sabe ler a confiança de uma
recomendação sem aprender nada de novo, e a soma dos factores continua a
conferir com o valor apresentado — o que permite verificar a conta ao vivo.

Quatro regras atravessam o ficheiro:

* **Não inventa.** Uma técnica MITRE só é proposta se existir no catálogo
  efectivamente carregado; um playbook só é proposto se estiver activo e os
  seus gatilhos casarem com o incidente. Sem base, não há recomendação — nunca
  há recomendação de preenchimento só para a lista não vir vazia.
* **Não insiste.** Uma recomendação rejeitada não volta a ser levantada com a
  mesma proposta. O analista decidiu; repeti-la transformaria apoio à decisão
  em ruído, e é assim que sistemas destes acabam ignorados.
* **Não ultrapassa.** A confiança de uma *inferência* está limitada a
  `MAX_CONFIDENCE_INFERENCIA`. Só uma afirmação humana, ou reportada pela
  própria fonte, é um facto — e o motor não produz factos.
* **Não decide sozinha.** A alteração proposta é aplicável mecanicamente, mas
  só depois de alguém a aceitar, com a permissão devida e registo em auditoria.

A saída deste módulo são `Proposta`s — objectos em memória, sem persistência. É
`app.services.recommendation_service` que decide o que gravar, o que actualizar
e o que ignorar por já ter sido recusado.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ALERT_OPEN_STATUSES,
    INCIDENT_TRANSITIONS,
    AlertStatus,
    IncidentCategory,
    IncidentStatus,
    Priority,
    RecommendationKind,
    Severity,
)
from app.intelligence.triage import MIN_HISTORY_FOR_FP, Factor, severity_from_score
from app.models.catalog import MitreTechnique
from app.models.incident import Incident, IncidentTechnique
from app.models.response import PlaybookExecution
from app.models.telemetry import Alert

ENGINE_NAME = "deterministico"
ENGINE_VERSION = "1.0"

#: Alvo polimórfico da recomendação. Corresponde a `Recommendation.target_type`.
TARGET_ALERT = "alert"
TARGET_INCIDENT = "incident"

#: Abaixo desta confiança a recomendação não é levantada. Interromper o
#: analista com uma sugestão que o motor mal sustenta custa-lhe mais atenção do
#: que lhe poupa — e ensina-o a ignorar a lista toda.
MIN_CONFIDENCE_TO_RAISE = 40

#: Tecto da confiança de qualquer inferência (§11). Uma associação inferida não
#: chega a "confirmada" por mais indícios que acumule: isso é reservado a quem
#: a afirma.
MAX_CONFIDENCE_INFERENCIA = 75

#: Validade por omissão. Uma recomendação descreve o estado num instante; ao fim
#: de uma semana sem decisão, o estado que a justificou provavelmente mudou e é
#: mais honesto expirá-la do que deixá-la a envelhecer como se ainda valesse.
DEFAULT_TTL_DAYS = 7

#: Taxa histórica de descarte a partir da qual se sugere falso positivo.
FP_RATE_THRESHOLD = 0.70

#: Pontuação de triagem a partir da qual um alerta em aberto merece incidente.
PROMOTE_SCORE_THRESHOLD = 65

#: Acima disto, o risco de falso positivo desaconselha a promoção mesmo com
#: pontuação alta.
PROMOTE_MAX_FP_SCORE = 50

#: Prioridade que corresponde a cada severidade. Mapa explícito e não uma
#: fórmula: a correspondência é uma política da organização, e uma política
#: lê-se melhor numa tabela do que numa expressão aritmética.
SEVERITY_TO_PRIORITY: dict[Severity, Priority] = {
    Severity.CRITICA: Priority.P1,
    Severity.ALTA: Priority.P2,
    Severity.MEDIA: Priority.P3,
    Severity.BAIXA: Priority.P4,
    Severity.INFO: Priority.P4,
}

#: Grupos de regra da fonte → técnica ATT&CK, com a frase que justifica a
#: inferência ao analista.
#:
#: É uma correspondência por indício, não uma equivalência: "o grupo de regra X
#: é compatível com a técnica Y". Por isso a associação criada é
#: `is_asserted=False` e a confiança nunca passa de `MAX_CONFIDENCE_INFERENCIA`.
#: Os identificadores são validados contra o catálogo carregado antes de
#: qualquer proposta — se o ATT&CK em uso não tiver a técnica, não se propõe.
GROUP_TO_TECHNIQUE: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (
        ("authentication_failed", "authentication_failures", "win_authentication_failed",
         "brute", "sshd"),
        "T1110",
        "Falhas de autenticação repetidas contra a mesma conta ou serviço.",
    ),
    (
        ("authentication_success", "win_authentication_success", "session_opened"),
        "T1078",
        "Utilização de credenciais válidas registada pela fonte.",
    ),
    (
        ("web_scan", "sql_injection", "web_appsec", "attack"),
        "T1190",
        "Actividade dirigida a um serviço exposto na web.",
    ),
    (
        ("shellshock", "command_execution", "powershell", "wmi"),
        "T1059",
        "Execução de comandos ou interpretadores registada pela fonte.",
    ),
    (
        ("privilege_escalation", "sudo", "adduser_to_group"),
        "T1548",
        "Manipulação de mecanismos de elevação de privilégio.",
    ),
    (
        ("syscheck", "file_integrity", "integrity"),
        "T1565",
        "Alteração de ficheiros vigiados pelo controlo de integridade.",
    ),
    (
        ("rootcheck", "rootkit"),
        "T1014",
        "Indícios de ocultação de presença no sistema.",
    ),
    (
        ("recon", "portscan", "nmap", "probe"),
        "T1046",
        "Varrimento de serviços de rede.",
    ),
    (
        ("ddos", "syn_flood", "flood"),
        "T1498",
        "Volume de tráfego compatível com negação de serviço em rede.",
    ),
    (
        ("phishing", "spam"),
        "T1566",
        "Mensagem com características de phishing.",
    ),
    (
        ("ransomware", "encrypt"),
        "T1486",
        "Cifra de dados com impacto operacional.",
    ),
    (
        ("malware", "virus", "trojan"),
        "T1204",
        "Execução de conteúdo malicioso.",
    ),
    (
        ("adduser", "useradd", "account_changed"),
        "T1136",
        "Criação ou alteração de contas.",
    ),
    (
        ("cron", "scheduled_task", "at_job"),
        "T1053",
        "Criação ou alteração de tarefas agendadas.",
    ),
    (
        ("exfiltration", "large_upload"),
        "T1041",
        "Transferência de dados compatível com exfiltração.",
    ),
)


@dataclass(slots=True)
class Proposta:
    """Recomendação calculada, ainda não persistida.

    `proposed_change` é a parte mecanicamente aplicável. Pode ser um dicionário
    vazio: há recomendações — "atribua este incidente a alguém", "registe as
    lições aprendidas" — cuja execução exige um julgamento que o motor não tem.
    Nesse caso a recomendação continua a valer como aviso, mas aceitar não
    altera nada, e o serviço di-lo em vez de fingir que aplicou.
    """

    kind: RecommendationKind
    target_type: str
    target_id: uuid.UUID
    title: str
    summary: str
    explanation: str
    confidence: int
    factors: list[Factor]
    evidence_refs: dict = field(default_factory=dict)
    proposed_change: dict = field(default_factory=dict)
    ttl_days: int | None = DEFAULT_TTL_DAYS

    def factors_as_dict(self) -> dict:
        """Decomposição no mesmo formato usado pela triagem."""
        return {
            "motor": ENGINE_NAME,
            "versao": ENGINE_VERSION,
            "total": self.confidence,
            "factores": {
                f.nome: {
                    "pontos": f.pontos,
                    "razao": f.razao,
                    **({"dados": f.dados} if f.dados else {}),
                }
                for f in self.factors
            },
        }

    @property
    def expires_at(self) -> datetime | None:
        if self.ttl_days is None:
            return None
        return datetime.now(UTC) + timedelta(days=self.ttl_days)


def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def _confidence_from(factors: list[Factor], *, tecto: int = 100) -> int:
    """Confiança = soma dos factores, limitada ao intervalo apresentável.

    Mantém a propriedade que o motor de triagem já garante: o número mostrado
    ao analista é exactamente a soma do que está por baixo dele.
    """
    return _clamp(sum(f.pontos for f in factors), 0, tecto)


def _explicacao(factors: list[Factor]) -> str:
    """Texto corrido a partir dos factores, pela ordem do contributo."""
    ordenados = sorted(factors, key=lambda f: abs(f.pontos), reverse=True)
    return " ".join(f.razao for f in ordenados if f.razao)


# ==================================================================== alertas
async def _rule_decision_history(
    session: AsyncSession, alert: Alert
) -> tuple[dict[AlertStatus, int], list[str]]:
    """Decisões já tomadas sobre outros alertas da mesma regra.

    Devolve a contagem por estado e alguns exemplos concretos. Os exemplos não
    são decoração: são o que permite ao analista ir verificar a afirmação em
    vez de ter de acreditar nela.
    """
    decididos = [
        AlertStatus.PROMOVIDO,
        AlertStatus.CORRELACIONADO,
        AlertStatus.FALSO_POSITIVO,
        AlertStatus.DESCARTADO,
    ]
    resultado = await session.execute(
        select(Alert.status, func.count())
        .where(Alert.rule_id == alert.rule_id, Alert.id != alert.id, Alert.status.in_(decididos))
        .group_by(Alert.status)
    )
    contagens = dict(resultado.all())

    exemplos = await session.execute(
        select(Alert.reference)
        .where(
            Alert.rule_id == alert.rule_id,
            Alert.id != alert.id,
            Alert.status.in_([AlertStatus.FALSO_POSITIVO, AlertStatus.DESCARTADO]),
        )
        .order_by(Alert.created_at.desc())
        .limit(5)
    )
    return contagens, [r for (r,) in exemplos.all()]


def _peso_da_amostra(total: int) -> float:
    """Quanto se pode confiar numa taxa calculada sobre `total` decisões.

    Cinco decisões chegam para a taxa ser considerada, mas não para ser levada
    a sério na totalidade: a confiança só atinge o valor pleno ao dobro do
    mínimo. Sem isto, duas decisões ao acaso produziriam uma recomendação com
    100% de confiança.
    """
    return min(1.0, total / (2 * MIN_HISTORY_FOR_FP))


async def _propor_falso_positivo(session: AsyncSession, alert: Alert) -> Proposta | None:
    """Regra historicamente ruidosa → sugerir descarte (§12, §36)."""
    if alert.status not in ALERT_OPEN_STATUSES or not alert.rule_id:
        return None

    contagens, exemplos = await _rule_decision_history(session, alert)
    total = sum(contagens.values())
    if total < MIN_HISTORY_FOR_FP:
        return None

    descartados = contagens.get(AlertStatus.FALSO_POSITIVO, 0) + contagens.get(
        AlertStatus.DESCARTADO, 0
    )
    taxa = descartados / total
    if taxa < FP_RATE_THRESHOLD:
        return None

    bruto = int(round(taxa * 100))
    confianca = _clamp(int(round(bruto * _peso_da_amostra(total))))
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    factors = [
        Factor(
            "taxa_historica_da_regra",
            bruto,
            f"{descartados} dos {total} alertas decididos da regra {alert.rule_id} foram "
            f"descartados ou marcados como falso positivo ({bruto}%).",
            {"regra": alert.rule_id, "descartados": descartados, "total_decidido": total},
        ),
        Factor(
            "ajuste_por_dimensao_da_amostra",
            confianca - bruto,
            f"Taxa calculada sobre {total} decisão/ões; a confiança plena exige "
            f"{2 * MIN_HISTORY_FOR_FP}.",
            {"decisoes": total, "amostra_plena": 2 * MIN_HISTORY_FOR_FP},
        ),
    ]

    return Proposta(
        kind=RecommendationKind.FALSO_POSITIVO,
        target_type=TARGET_ALERT,
        target_id=alert.id,
        title=f"Provável falso positivo: regra {alert.rule_id}",
        summary=(
            f"O histórico desta regra sugere descartar {alert.reference}. Confirme antes "
            f"de aceitar: o motor mede o comportamento passado da regra, não o conteúdo "
            f"deste alerta."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "regra": alert.rule_id,
            "alertas_descartados": exemplos,
            "total_decidido": total,
        },
        proposed_change={
            "operacao": "ALTERAR_ESTADO_ALERTA",
            "de": alert.status.value,
            "para": AlertStatus.FALSO_POSITIVO.value,
        },
    )


async def _propor_promocao(session: AsyncSession, alert: Alert) -> Proposta | None:
    """Alerta pontuado alto e ainda sem incidente → sugerir promoção (§6)."""
    if alert.status not in ALERT_OPEN_STATUSES or alert.incident_id is not None:
        return None
    if alert.scored_at is None or alert.triage_score < PROMOTE_SCORE_THRESHOLD:
        return None
    if alert.false_positive_score >= PROMOTE_MAX_FP_SCORE:
        return None

    penalizacao = -(alert.false_positive_score // 2)
    factors = [
        Factor(
            "pontuacao_de_triagem",
            alert.triage_score,
            alert.triage_rationale
            or f"O motor de triagem pontuou este alerta em {alert.triage_score}/100.",
            {"pontuacao": alert.triage_score, "minimo_para_promover": PROMOTE_SCORE_THRESHOLD},
        ),
        Factor(
            "risco_de_falso_positivo",
            penalizacao,
            f"Risco estimado de falso positivo: {alert.false_positive_score}%."
            if alert.false_positive_score
            else "Sem histórico adverso para esta regra.",
            {"risco_percentagem": alert.false_positive_score},
        ),
    ]
    confianca = _confidence_from(factors)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    severidade = severity_from_score(alert.triage_score)
    return Proposta(
        kind=RecommendationKind.TRIAGEM,
        target_type=TARGET_ALERT,
        target_id=alert.id,
        title=f"Promover {alert.reference} a incidente",
        summary=(
            f"Pontuação {alert.triage_score}/100 sem histórico que a desminta. "
            f"Promover cria um incidente com severidade {severidade.value}."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "alerta": alert.reference,
            "pontuacao": alert.triage_score,
            "factores_de_triagem": alert.triage_factors or {},
        },
        proposed_change={"operacao": "PROMOVER_ALERTA", "severidade": severidade.value},
    )


def _propor_severidade_do_alerta(alert: Alert) -> Proposta | None:
    """Severidade da fonte divergente da pontuação determinística."""
    if alert.status not in ALERT_OPEN_STATUSES or alert.scored_at is None:
        return None

    sugerida = severity_from_score(alert.triage_score)
    distancia = sugerida.rank - alert.severity.rank
    if distancia == 0:
        return None

    factors = [
        Factor(
            "divergencia_de_severidade",
            45,
            f"A fonte classificou como {alert.severity.value}; a pontuação de triagem "
            f"({alert.triage_score}/100) corresponde a {sugerida.value}.",
            {
                "severidade_da_fonte": alert.severity.value,
                "severidade_sugerida": sugerida.value,
                "pontuacao": alert.triage_score,
            },
        ),
        Factor(
            "distancia_entre_niveis",
            15 * abs(distancia),
            f"Divergência de {abs(distancia)} nível/níveis na escala de severidade.",
            {"niveis": abs(distancia)},
        ),
    ]
    confianca = _confidence_from(factors, tecto=85)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    sentido = "Elevar" if distancia > 0 else "Reduzir"
    return Proposta(
        kind=RecommendationKind.PRIORIZACAO,
        target_type=TARGET_ALERT,
        target_id=alert.id,
        title=f"{sentido} a severidade de {alert.reference} para {sugerida.value}",
        summary=(
            "A pontuação de triagem e a severidade declarada pela fonte não coincidem. "
            "A pontuação tem em conta o activo afectado, a reputação dos indicadores e o "
            "histórico da regra; a severidade da fonte não."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={"alerta": alert.reference, "factores_de_triagem": alert.triage_factors or {}},
        proposed_change={
            "operacao": "ALTERAR_CAMPOS",
            "alteracoes": [
                {"campo": "severity", "de": alert.severity.value, "para": sugerida.value}
            ],
        },
    )


async def gerar_para_alerta(session: AsyncSession, alert: Alert) -> list[Proposta]:
    """Todas as recomendações aplicáveis a um alerta."""
    candidatas = [
        await _propor_falso_positivo(session, alert),
        await _propor_promocao(session, alert),
        _propor_severidade_do_alerta(alert),
    ]
    return [p for p in candidatas if p is not None]


# ================================================================= incidentes
@dataclass(slots=True)
class _ContextoDoIncidente:
    """Tudo o que os geradores de incidente precisam, lido uma única vez.

    Os geradores partilham quase sempre os mesmos dados. Lê-los por gerador
    multiplicaria as consultas por incidente sem acrescentar informação.
    """

    alertas: list[Alert]
    tecnicas_associadas: set[str]
    playbooks_executados: set[uuid.UUID]

    @property
    def grupos_de_regra(self) -> set[str]:
        grupos: set[str] = set()
        for alerta in self.alertas:
            grupos.update(t.lower() for t in (alerta.tags or []))
            if alerta.rule_name:
                grupos.add(alerta.rule_name.lower())
        return grupos

    @property
    def pontuacao_maxima(self) -> int:
        return max((a.triage_score for a in self.alertas), default=0)


async def _carregar_contexto(session: AsyncSession, incident: Incident) -> _ContextoDoIncidente:
    alertas = await session.execute(
        select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.created_at)
    )
    tecnicas = await session.execute(
        select(MitreTechnique.technique_id)
        .join(IncidentTechnique, IncidentTechnique.technique_id == MitreTechnique.id)
        .where(IncidentTechnique.incident_id == incident.id)
    )
    execucoes = await session.execute(
        select(PlaybookExecution.playbook_id).where(PlaybookExecution.incident_id == incident.id)
    )
    return _ContextoDoIncidente(
        alertas=list(alertas.scalars()),
        tecnicas_associadas={t for (t,) in tecnicas.all()},
        playbooks_executados={p for (p,) in execucoes.all()},
    )


def _propor_classificacao(incident: Incident, ctx: _ContextoDoIncidente) -> Proposta | None:
    """Categoria sugerida pelos grupos de regra dos alertas do incidente."""
    from app.services.incident_service import suggest_category

    if not ctx.alertas:
        return None

    votos: dict[IncidentCategory, int] = {}
    for alerta in ctx.alertas:
        categoria = suggest_category(alerta.tags or [], alerta.rule_name)
        if categoria is IncidentCategory.OUTRO:
            continue
        votos[categoria] = votos.get(categoria, 0) + 1

    if not votos:
        return None

    melhor, suporte = max(votos.items(), key=lambda kv: kv[1])
    if melhor == incident.category:
        return None

    fraccao = suporte / len(ctx.alertas)
    factors = [
        Factor(
            "categoria_sugerida_pelos_grupos_de_regra",
            45,
            f"Os grupos de regra dos alertas apontam para {melhor.value}; o incidente "
            f"está classificado como {incident.category.value}.",
            {"sugerida": melhor.value, "actual": incident.category.value},
        ),
        Factor(
            "concordancia_entre_alertas",
            int(round(40 * fraccao)),
            f"{suporte} de {len(ctx.alertas)} alertas do incidente apontam para essa "
            f"categoria ({int(round(fraccao * 100))}%).",
            {"suporte": suporte, "total_alertas": len(ctx.alertas)},
        ),
    ]
    confianca = _confidence_from(factors, tecto=85)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    return Proposta(
        kind=RecommendationKind.CLASSIFICACAO,
        target_type=TARGET_INCIDENT,
        target_id=incident.id,
        title=f"Reclassificar {incident.reference} como {melhor.value}",
        summary=(
            "A classificação actual não corresponde ao que os alertas indicam. A "
            "categoria determina os playbooks sugeridos e a forma como o incidente "
            "entra nos relatórios."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "alertas": [a.reference for a in ctx.alertas[:10]],
            "categorias_votadas": {c.value: n for c, n in votos.items()},
        },
        proposed_change={
            "operacao": "ALTERAR_CAMPOS",
            "alteracoes": [
                {"campo": "category", "de": incident.category.value, "para": melhor.value}
            ],
        },
    )


def _propor_priorizacao(incident: Incident, ctx: _ContextoDoIncidente) -> Proposta | None:
    """Severidade e prioridade face à pontuação mais alta dos seus alertas."""
    if not ctx.alertas:
        return None

    sugerida = severity_from_score(ctx.pontuacao_maxima)
    prioridade = SEVERITY_TO_PRIORITY[sugerida]
    alteracoes: list[dict] = []
    if sugerida != incident.severity:
        alteracoes.append(
            {"campo": "severity", "de": incident.severity.value, "para": sugerida.value}
        )
    if prioridade != incident.priority:
        alteracoes.append(
            {"campo": "priority", "de": incident.priority.value, "para": prioridade.value}
        )
    if not alteracoes:
        return None

    distancia = abs(sugerida.rank - incident.severity.rank)
    factors = [
        Factor(
            "pontuacao_maxima_dos_alertas",
            45,
            f"O alerta mais bem pontuado do incidente tem {ctx.pontuacao_maxima}/100, o "
            f"que corresponde a severidade {sugerida.value}.",
            {"pontuacao_maxima": ctx.pontuacao_maxima, "severidade_sugerida": sugerida.value},
        ),
        Factor(
            "distancia_entre_niveis",
            15 * distancia,
            (
                f"Divergência de {distancia} nível/níveis face à severidade actual "
                f"({incident.severity.value})."
                if distancia
                else f"A severidade mantém-se; muda a prioridade para {prioridade.value}."
            ),
            {"niveis": distancia},
        ),
    ]
    confianca = _confidence_from(factors, tecto=85)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    return Proposta(
        kind=RecommendationKind.PRIORIZACAO,
        target_type=TARGET_INCIDENT,
        target_id=incident.id,
        title=f"Rever severidade e prioridade de {incident.reference}",
        summary=(
            "A severidade do incidente não acompanha a pontuação determinística dos "
            "alertas que o compõem. A prioridade decorre da severidade segundo a "
            "política da organização."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "alertas": [
                {"referencia": a.reference, "pontuacao": a.triage_score}
                for a in sorted(ctx.alertas, key=lambda a: a.triage_score, reverse=True)[:5]
            ]
        },
        proposed_change={"operacao": "ALTERAR_CAMPOS", "alteracoes": alteracoes},
    )


async def _propor_tecnicas_mitre(
    session: AsyncSession, incident: Incident, ctx: _ContextoDoIncidente
) -> Proposta | None:
    """Inferência de técnicas ATT&CK a partir dos grupos de regra (§11).

    Só propõe o que não está já associado, e só o que existe no catálogo
    carregado. A associação resultante é marcada como **inferida**, com a
    justificação anexada — nunca como facto.
    """
    grupos = ctx.grupos_de_regra
    if not grupos:
        return None

    candidatas: dict[str, tuple[str, list[str]]] = {}
    for marcadores, technique_id, frase in GROUP_TO_TECHNIQUE:
        if technique_id in ctx.tecnicas_associadas:
            continue
        casados = sorted({m for m in marcadores if any(m in g for g in grupos)})
        if casados:
            candidatas[technique_id] = (frase, casados)

    if not candidatas:
        return None

    # Validação contra o catálogo: o que não existe no ATT&CK carregado não é
    # proposto. É esta consulta que impede o motor de inventar uma técnica.
    existentes = await session.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id.in_(sorted(candidatas)))
    )
    encontradas = {t.technique_id: t for t in existentes.scalars()}
    if not encontradas:
        return None

    detalhes = []
    for technique_id, tecnica in sorted(encontradas.items()):
        frase, casados = candidatas[technique_id]
        detalhes.append(
            {
                "tecnica": technique_id,
                "nome": tecnica.name,
                "razao": frase,
                "grupos_de_regra": casados,
            }
        )

    factors = [
        Factor(
            "grupos_de_regra_compativeis",
            35,
            f"Os grupos de regra dos alertas são compatíveis com {len(encontradas)} "
            f"técnica(s) ainda não associada(s).",
            {"tecnicas": sorted(encontradas)},
        ),
        Factor(
            "corroboracao_entre_alertas",
            min(25, 5 * len(ctx.alertas)),
            f"Inferência sustentada por {len(ctx.alertas)} alerta(s) do incidente.",
            {"alertas": len(ctx.alertas)},
        ),
        Factor(
            "limite_de_inferencia",
            0,
            f"Associação inferida, nunca afirmada: a confiança está limitada a "
            f"{MAX_CONFIDENCE_INFERENCIA} (§11).",
            {"tecto": MAX_CONFIDENCE_INFERENCIA},
        ),
    ]
    confianca = _confidence_from(factors, tecto=MAX_CONFIDENCE_INFERENCIA)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    nomes = ", ".join(f"{d['tecnica']} ({d['nome']})" for d in detalhes[:3])
    return Proposta(
        kind=RecommendationKind.TECNICA_MITRE,
        target_type=TARGET_INCIDENT,
        target_id=incident.id,
        title=f"Associar {len(detalhes)} técnica(s) ATT&CK a {incident.reference}",
        summary=(
            f"Compatível com {nomes}. Aceitar associa as técnicas ao incidente marcadas "
            f"como inferidas, com a justificação anexada — não como facto confirmado."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "tecnicas_propostas": detalhes,
            "alertas": [a.reference for a in ctx.alertas[:10]],
        },
        proposed_change={
            "operacao": "ASSOCIAR_TECNICAS",
            "tecnicas": [d["tecnica"] for d in detalhes],
        },
    )


async def _propor_playbook(
    session: AsyncSession, incident: Incident, ctx: _ContextoDoIncidente
) -> Proposta | None:
    """Playbook aplicável e ainda não executado para este incidente."""
    from app.playbooks.engine import suggest_playbooks

    if incident.status in (
        IncidentStatus.RESOLVIDO,
        IncidentStatus.ENCERRADO,
        IncidentStatus.FALSO_POSITIVO,
        IncidentStatus.DUPLICADO,
    ):
        return None

    sugestoes = [
        (playbook, razao)
        for playbook, razao in await suggest_playbooks(session, incident)
        if playbook.id not in ctx.playbooks_executados
    ]
    if not sugestoes:
        return None

    # O playbook mais específico é o que satisfez mais critérios de gatilho: a
    # razão devolvida pelo motor de playbooks enumera-os separados por ';'.
    playbook, razao = max(sugestoes, key=lambda s: s[1].count(";"))
    criterios = razao.count(";") + 1

    factors = [
        Factor(
            "gatilhos_satisfeitos",
            40 + 15 * criterios,
            f"'{playbook.name}' está activo e satisfaz {criterios} critério(s) de "
            f"gatilho. {razao}",
            {"playbook": playbook.name, "criterios": criterios},
        ),
        Factor(
            "ainda_nao_executado",
            10,
            "Este playbook ainda não foi executado sobre o incidente.",
            {"execucoes_anteriores": 0},
        ),
    ]
    confianca = _confidence_from(factors, tecto=85)
    if confianca < MIN_CONFIDENCE_TO_RAISE:
        return None

    return Proposta(
        kind=RecommendationKind.PLAYBOOK,
        target_type=TARGET_INCIDENT,
        target_id=incident.id,
        title=f"Aplicar o playbook '{playbook.name}' a {incident.reference}",
        summary=(
            f"{razao} As acções de resposta que exijam aprovação continuam a exigi-la: "
            f"a execução suspende-se nesses passos em vez de os contornar."
        ),
        explanation=_explicacao(factors),
        confidence=confianca,
        factors=factors,
        evidence_refs={
            "playbook": playbook.name,
            "outros_aplicaveis": [p.name for p, _ in sugestoes if p.id != playbook.id],
        },
        proposed_change={
            "operacao": "EXECUTAR_PLAYBOOK",
            "playbook_id": str(playbook.id),
            "playbook": playbook.name,
        },
    )


def _propor_proximo_passo(incident: Incident, ctx: _ContextoDoIncidente) -> Proposta | None:
    """O passo seguinte no ciclo de vida, ou a lacuna que o impede.

    Devolve **uma** recomendação, a mais urgente. Um incidente parado costuma
    ter várias coisas por fazer ao mesmo tempo; listá-las todas devolveria ao
    analista exactamente o problema que ele veio resolver — decidir por onde
    começar.

    As transições propostas são validadas contra `INCIDENT_TRANSITIONS`: o
    motor não sugere um caminho que o ciclo de vida não permita.
    """
    agora = datetime.now(UTC)
    permitidas = INCIDENT_TRANSITIONS.get(incident.status, frozenset())
    encerrados = (
        IncidentStatus.RESOLVIDO,
        IncidentStatus.ENCERRADO,
        IncidentStatus.FALSO_POSITIVO,
        IncidentStatus.DUPLICADO,
    )

    def transicao(destino: IncidentStatus) -> dict:
        return {
            "operacao": "TRANSICAO_ESTADO",
            "de": incident.status.value,
            "para": destino.value,
        }

    # 1. Prazo ultrapassado num incidente por resolver: escalar.
    if (
        incident.due_at is not None
        and incident.resolved_at is None
        and incident.due_at < agora
        and IncidentStatus.ESCALADO in permitidas
    ):
        horas = int((agora - incident.due_at).total_seconds() // 3600)
        factors = [
            Factor(
                "prazo_ultrapassado",
                70,
                f"O prazo do incidente expirou há {horas}h e o incidente continua em "
                f"{incident.status.value}.",
                {"horas_de_atraso": horas, "prazo": incident.due_at.isoformat()},
            )
        ]
        return Proposta(
            kind=RecommendationKind.PROXIMO_PASSO,
            target_type=TARGET_INCIDENT,
            target_id=incident.id,
            title=f"Escalar {incident.reference}: prazo ultrapassado",
            summary=(
                f"Passaram {horas}h sobre o prazo derivado da severidade "
                f"{incident.severity.value} sem resolução."
            ),
            explanation=_explicacao(factors),
            confidence=_confidence_from(factors),
            factors=factors,
            evidence_refs={"prazo": incident.due_at.isoformat()},
            proposed_change=transicao(IncidentStatus.ESCALADO),
            ttl_days=2,
        )

    # 2. Incidente novo: iniciar triagem.
    if incident.status is IncidentStatus.NOVO and IncidentStatus.TRIAGEM in permitidas:
        minutos = int((agora - incident.detected_at).total_seconds() // 60)
        factors = [
            Factor(
                "incidente_por_triar",
                55,
                f"Detectado há {minutos} minuto(s) e ainda em NOVO — nenhum analista o "
                f"reconheceu.",
                {"minutos_desde_deteccao": minutos},
            ),
            Factor(
                "alertas_a_aguardar",
                min(20, 5 * len(ctx.alertas)),
                f"Agrega {len(ctx.alertas)} alerta(s).",
                {"alertas": len(ctx.alertas)},
            ),
        ]
        return Proposta(
            kind=RecommendationKind.PROXIMO_PASSO,
            target_type=TARGET_INCIDENT,
            target_id=incident.id,
            title=f"Iniciar a triagem de {incident.reference}",
            summary=(
                "O incidente ainda não foi reconhecido. A passagem a TRIAGEM marca o "
                "instante de reconhecimento, que é a base do MTTA nos relatórios."
            ),
            explanation=_explicacao(factors),
            confidence=_confidence_from(factors),
            factors=factors,
            evidence_refs={"alertas": [a.reference for a in ctx.alertas[:10]]},
            proposed_change=transicao(IncidentStatus.TRIAGEM),
            ttl_days=2,
        )

    # 3. Incidente grave em investigação sem contenção.
    if (
        incident.status is IncidentStatus.INVESTIGACAO
        and incident.severity.rank >= Severity.ALTA.rank
        and incident.contained_at is None
        and IncidentStatus.CONTENCAO in permitidas
    ):
        factors = [
            Factor(
                "severidade_sem_contencao",
                60,
                f"Incidente de severidade {incident.severity.value} em investigação sem "
                f"qualquer marco de contenção registado.",
                {"severidade": incident.severity.value},
            )
        ]
        return Proposta(
            kind=RecommendationKind.PROXIMO_PASSO,
            target_type=TARGET_INCIDENT,
            target_id=incident.id,
            title=f"Passar {incident.reference} a contenção",
            summary=(
                "Num incidente desta severidade, conter primeiro e investigar depois "
                "limita o impacto. O marco de contenção alimenta as métricas de resposta."
            ),
            explanation=_explicacao(factors),
            confidence=_confidence_from(factors),
            factors=factors,
            evidence_refs={"severidade": incident.severity.value},
            proposed_change=transicao(IncidentStatus.CONTENCAO),
            ttl_days=3,
        )

    # 4. Contido há muito tempo sem avançar: erradicar.
    if (
        incident.status is IncidentStatus.CONTENCAO
        and incident.contained_at is not None
        and IncidentStatus.ERRADICACAO in permitidas
    ):
        horas = int((agora - incident.contained_at).total_seconds() // 3600)
        if horas >= 24:
            factors = [
                Factor(
                    "contencao_prolongada",
                    50,
                    f"Contido há {horas}h sem passar a erradicação.",
                    {"horas_em_contencao": horas},
                )
            ]
            return Proposta(
                kind=RecommendationKind.PROXIMO_PASSO,
                target_type=TARGET_INCIDENT,
                target_id=incident.id,
                title=f"Avançar {incident.reference} para erradicação",
                summary=(
                    "A contenção limita o impacto mas não remove a causa. Um incidente "
                    "que fica contido indefinidamente continua a consumir a excepção "
                    "que o contém."
                ),
                explanation=_explicacao(factors),
                confidence=_confidence_from(factors),
                factors=factors,
                evidence_refs={"contido_em": incident.contained_at.isoformat()},
                proposed_change=transicao(IncidentStatus.ERRADICACAO),
                ttl_days=3,
            )

    # 5. Sem responsável: não há transição a propor, mas há lacuna a apontar.
    if incident.assignee_id is None and incident.status not in encerrados:
        factors = [
            Factor(
                "incidente_sem_responsavel",
                50,
                f"O incidente está em {incident.status.value} sem responsável atribuído.",
                {"estado": incident.status.value},
            )
        ]
        return Proposta(
            kind=RecommendationKind.PROXIMO_PASSO,
            target_type=TARGET_INCIDENT,
            target_id=incident.id,
            title=f"Atribuir um responsável a {incident.reference}",
            summary=(
                "Sem responsável, nenhum prazo é de ninguém. A escolha da pessoa depende "
                "de carga e competência, pelo que o motor aponta a lacuna mas não a "
                "preenche."
            ),
            explanation=_explicacao(factors),
            confidence=_confidence_from(factors),
            factors=factors,
            evidence_refs={"estado": incident.status.value},
            proposed_change={},
            ttl_days=3,
        )

    # 6. Resolvido sem lições aprendidas (§36).
    if incident.status is IncidentStatus.RESOLVIDO and not incident.lessons_learned:
        factors = [
            Factor(
                "resolucao_sem_licoes",
                45,
                "O incidente foi resolvido sem registo de lições aprendidas.",
                {
                    "resolvido_em": (
                        incident.resolved_at.isoformat() if incident.resolved_at else None
                    )
                },
            )
        ]
        return Proposta(
            kind=RecommendationKind.PROXIMO_PASSO,
            target_type=TARGET_INCIDENT,
            target_id=incident.id,
            title=f"Registar as lições aprendidas de {incident.reference}",
            summary=(
                "É o registo do §36 que faz o incidente seguinte custar menos. Sem ele, "
                "o encerramento perde a única parte que se aproveita."
            ),
            explanation=_explicacao(factors),
            confidence=_confidence_from(factors),
            factors=factors,
            evidence_refs={},
            proposed_change={},
            ttl_days=None,
        )

    return None


async def gerar_para_incidente(session: AsyncSession, incident: Incident) -> list[Proposta]:
    """Todas as recomendações aplicáveis a um incidente."""
    ctx = await _carregar_contexto(session, incident)
    candidatas = [
        _propor_classificacao(incident, ctx),
        _propor_priorizacao(incident, ctx),
        await _propor_tecnicas_mitre(session, incident, ctx),
        await _propor_playbook(session, incident, ctx),
        _propor_proximo_passo(incident, ctx),
    ]
    return [p for p in candidatas if p is not None]
