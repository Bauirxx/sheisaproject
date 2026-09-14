"""Regras de correlação, playbooks e inventário iniciais.

Não são dados de demonstração: são configuração operacional com que a
plataforma arranca útil em vez de vazia. Uma instalação sem regras de
correlação nunca correlacionaria nada, e o §9 ficaria por cumprir na prática.

Tudo o que é criado aqui é editável pelo administrador. As funções são
idempotentes e nunca sobrepõem alterações feitas depois: se uma regra já existe
com o mesmo nome, é deixada como está.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ActionKind,
    ActionRiskLevel,
    AssetCriticality,
    AssetType,
    CorrelationStrategy,
    IncidentCategory,
    PlaybookStepType,
    Severity,
)
from app.models.catalog import Asset
from app.models.response import Playbook, PlaybookStep
from app.models.telemetry import CorrelationRule

# ---------------------------------------------------------------- correlação
CORRELATION_RULES: tuple[dict, ...] = (
    {
        "name": "Força bruta persistente",
        "description": (
            "Várias detecções da mesma regra de autenticação falhada num curto "
            "intervalo indicam uma tentativa sustentada, não ruído isolado."
        ),
        "priority": 10,
        "strategy": CorrelationStrategy.LIMIAR,
        "window_minutes": 30,
        "min_alerts": 3,
        "conditions": {
            "rule_groups_any": [
                "authentication_failures", "authentication_failed", "win_authentication_failed",
            ],
        },
        "resulting_severity": Severity.ALTA,
        "resulting_category": IncidentCategory.TENTATIVA_INTRUSAO.value,
        "incident_title_template": "Tentativa de acesso por força bruta",
    },
    {
        "name": "Mesmo actor em vários alvos",
        "description": (
            "Alertas distintos que partilham um artefacto — tipicamente o "
            "endereço do atacante — dentro da mesma janela. Responde à pergunta "
            "'é a mesma origem a atacar vários sistemas?'."
        ),
        "priority": 20,
        "strategy": CorrelationStrategy.ENTIDADE_PARTILHADA,
        "window_minutes": 60,
        "min_alerts": 2,
        "match_fields": [],  # usa os indicadores extraídos
        "conditions": {"severity_min": Severity.MEDIA.value},
        "resulting_category": IncidentCategory.INTRUSAO.value,
        "incident_title_template": "Actividade coordenada com origem comum",
    },
    {
        "name": "Convergência de detecções num activo",
        "description": (
            "Detecções de naturezas diferentes a incidir no mesmo activo. "
            "Sugere um sistema sob ataque por vários vectores, e não uma "
            "assinatura ruidosa a repetir-se."
        ),
        "priority": 30,
        "strategy": CorrelationStrategy.ACTIVO_ALVO,
        "window_minutes": 120,
        "min_alerts": 3,
        "conditions": {"severity_min": Severity.BAIXA.value},
        "resulting_severity": Severity.ALTA,
        "resulting_category": IncidentCategory.INTRUSAO.value,
        "incident_title_template": "Activo sob ataque por múltiplos vectores",
    },
    {
        "name": "Cadeia de ataque: acesso, execução e comando",
        "description": (
            "Progressão compatível com uma cadeia de ataque: autenticação "
            "comprometida, seguida de execução e de comunicação com exterior. "
            "É a regra que transforma sinais soltos numa narrativa."
        ),
        "priority": 5,
        "strategy": CorrelationStrategy.SEQUENCIA_TEMPORAL,
        "window_minutes": 180,
        "min_alerts": 3,
        "sequence": ["authentication", "execution", "trojan"],
        "resulting_severity": Severity.CRITICA,
        "resulting_category": IncidentCategory.INTRUSAO.value,
        "incident_title_template": "Cadeia de ataque em progressão",
    },
)


async def seed_correlation_rules(session: AsyncSession) -> tuple[int, int]:
    existing = {
        r.name for r in (await session.execute(select(CorrelationRule))).scalars()
    }
    created = kept = 0
    for spec in CORRELATION_RULES:
        if spec["name"] in existing:
            kept += 1
            continue
        session.add(
            CorrelationRule(
                name=spec["name"],
                description=spec["description"],
                is_enabled=True,
                priority=spec["priority"],
                strategy=spec["strategy"],
                window_minutes=spec["window_minutes"],
                min_alerts=spec["min_alerts"],
                match_fields=spec.get("match_fields", []),
                conditions=spec.get("conditions", {}),
                sequence=spec.get("sequence", []),
                resulting_severity=spec.get("resulting_severity"),
                resulting_category=spec.get("resulting_category"),
                incident_title_template=spec["incident_title_template"],
            )
        )
        created += 1
    await session.flush()
    return created, kept


# ----------------------------------------------------------------- playbooks
PLAYBOOKS: tuple[dict, ...] = (
    {
        "name": "Resposta a endereço IP malicioso",
        "description": (
            "Procedimento para um incidente cujo indicador principal é um "
            "endereço externo. Enriquece, avalia o impacto e, mediante "
            "aprovação, bloqueia."
        ),
        "trigger_category": IncidentCategory.INTRUSAO,
        "trigger_min_severity": Severity.MEDIA,
        "trigger_conditions": {"requires_ioc_types": ["IP"]},
        "success_criteria": (
            "O endereço está bloqueado na fronteira e não se observa novo "
            "tráfego com origem nele durante 30 minutos."
        ),
        "rollback_criteria": (
            "Se o bloqueio afectar tráfego legítimo, remover a regra e "
            "reclassificar o indicador."
        ),
        "steps": [
            {"name": "Enriquecer o indicador", "step_type": PlaybookStepType.ENRIQUECER_IOC,
             "parameters": {"ioc_types": ["IP"]},
             "description": "Reúne o que a plataforma já sabe sobre o endereço."},
            {"name": "Consultar reputação", "step_type": PlaybookStepType.CONSULTAR_REPUTACAO,
             "parameters": {},
             "description": "Consulta fontes de threat intelligence configuradas."},
            {"name": "Identificar activos afectados",
             "step_type": PlaybookStepType.IDENTIFICAR_ACTIVOS, "parameters": {},
             "description": "Determina que sistemas comunicaram com o endereço."},
            {"name": "Tarefa de análise para o analista",
             "step_type": PlaybookStepType.CRIAR_TAREFA,
             "parameters": {
                 "titulo": "Validar o impacto do endereço malicioso",
                 "descricao": "Confirmar se houve comunicação bem-sucedida e o seu alcance.",
             }},
            {"name": "Solicitar aprovação de bloqueio",
             "step_type": PlaybookStepType.SOLICITAR_APROVACAO,
             "risk_level": ActionRiskLevel.CRITICO, "requires_approval": True,
             "parameters": {"motivo": "O bloqueio de um endereço pode afectar tráfego legítimo."}},
            {"name": "Bloquear o endereço", "step_type": PlaybookStepType.EXECUTAR_ACCAO,
             "action_kind": ActionKind.BLOQUEAR_IP, "risk_level": ActionRiskLevel.CRITICO,
             "requires_approval": True, "abort_on_failure": True,
             "parameters": {}},
            {"name": "Registar o resultado", "step_type": PlaybookStepType.REGISTAR_NOTA,
             "parameters": {"texto": "Bloqueio aplicado e resultado registado no incidente."}},
        ],
    },
    {
        "name": "Contenção de força bruta",
        "description": (
            "Resposta a tentativas de autenticação sustentadas contra um "
            "serviço exposto."
        ),
        "trigger_category": IncidentCategory.TENTATIVA_INTRUSAO,
        "trigger_min_severity": Severity.MEDIA,
        "success_criteria": "As tentativas cessam e a conta visada está protegida.",
        "rollback_criteria": "Se a origem for legítima, repor o acesso de imediato.",
        "steps": [
            {"name": "Identificar a origem e a conta visada",
             "step_type": PlaybookStepType.ENRIQUECER_IOC,
             "parameters": {"ioc_types": ["IP", "UTILIZADOR"]}},
            {"name": "Determinar se houve autenticação bem-sucedida",
             "step_type": PlaybookStepType.CRIAR_TAREFA,
             "parameters": {
                 "titulo": "Verificar se alguma tentativa teve êxito",
                 "descricao": "Procurar autenticações bem-sucedidas da mesma origem.",
             }},
            {"name": "Solicitar aprovação para suspender a conta",
             "step_type": PlaybookStepType.SOLICITAR_APROVACAO,
             "risk_level": ActionRiskLevel.CRITICO, "requires_approval": True,
             "parameters": {"motivo": "Suspender uma conta interrompe o trabalho do utilizador."}},
            {"name": "Desactivar a conta visada",
             "step_type": PlaybookStepType.EXECUTAR_ACCAO,
             "action_kind": ActionKind.DESACTIVAR_UTILIZADOR,
             "risk_level": ActionRiskLevel.CRITICO, "requires_approval": True,
             "abort_on_failure": False, "parameters": {}},
            {"name": "Notificar a equipa", "step_type": PlaybookStepType.NOTIFICAR,
             "risk_level": ActionRiskLevel.BAIXO,
             "parameters": {"mensagem": "Contenção de força bruta em curso."}},
        ],
    },
    {
        "name": "Contenção de código malicioso",
        "description": "Resposta a malware detectado num activo monitorizado.",
        "trigger_category": IncidentCategory.CODIGO_MALICIOSO,
        "trigger_min_severity": Severity.ALTA,
        "success_criteria": "O activo está isolado e os artefactos recolhidos.",
        "rollback_criteria": "Remover o isolamento após confirmação de limpeza.",
        "steps": [
            {"name": "Recolher artefactos do activo",
             "step_type": PlaybookStepType.EXECUTAR_ACCAO,
             "action_kind": ActionKind.RECOLHER_ARTEFACTOS,
             "risk_level": ActionRiskLevel.BAIXO, "abort_on_failure": False,
             "parameters": {}},
            {"name": "Identificar activos afectados",
             "step_type": PlaybookStepType.IDENTIFICAR_ACTIVOS, "parameters": {}},
            {"name": "Solicitar aprovação de isolamento",
             "step_type": PlaybookStepType.SOLICITAR_APROVACAO,
             "risk_level": ActionRiskLevel.CRITICO, "requires_approval": True,
             "parameters": {"motivo": "O isolamento retira o sistema de produção."}},
            {"name": "Isolar o activo", "step_type": PlaybookStepType.EXECUTAR_ACCAO,
             "action_kind": ActionKind.ISOLAR_ACTIVO,
             "risk_level": ActionRiskLevel.CRITICO, "requires_approval": True,
             "parameters": {}},
            {"name": "Tarefa de erradicação", "step_type": PlaybookStepType.CRIAR_TAREFA,
             "parameters": {
                 "titulo": "Remover o código malicioso e validar a limpeza",
                 "descricao": "Executar remoção, confirmar ausência de persistência.",
             }},
        ],
    },
)


async def seed_playbooks(session: AsyncSession) -> tuple[int, int]:
    existing = {p.name for p in (await session.execute(select(Playbook))).scalars()}
    created = kept = 0

    for spec in PLAYBOOKS:
        if spec["name"] in existing:
            kept += 1
            continue

        playbook = Playbook(
            name=spec["name"],
            description=spec["description"],
            is_enabled=True,
            trigger_category=spec.get("trigger_category"),
            trigger_min_severity=spec.get("trigger_min_severity", Severity.BAIXA),
            trigger_conditions=spec.get("trigger_conditions", {}),
            # Nunca automático por omissão: automação silenciosa numa
            # plataforma de segurança é um risco, não uma funcionalidade.
            auto_execute=False,
            success_criteria=spec.get("success_criteria", ""),
            rollback_criteria=spec.get("rollback_criteria", ""),
        )
        session.add(playbook)
        await session.flush()

        for index, step in enumerate(spec["steps"], start=1):
            session.add(
                PlaybookStep(
                    playbook_id=playbook.id,
                    ordering=index,
                    name=step["name"],
                    description=step.get("description", ""),
                    step_type=step["step_type"],
                    parameters=step.get("parameters", {}),
                    action_kind=step.get("action_kind"),
                    risk_level=step.get("risk_level", ActionRiskLevel.BAIXO),
                    requires_approval=step.get("requires_approval", False),
                    abort_on_failure=step.get("abort_on_failure", True),
                )
            )
        created += 1

    await session.flush()
    return created, kept


# ------------------------------------------------------------------- activos
#: Inventário do laboratório. Representa os sistemas monitorizados pelo Wazuh
#: no ambiente de ensaio; num INCM real seria substituído pelo inventário da
#: organização.
LAB_ASSETS: tuple[dict, ...] = (
    {
        "identifier": "srv-web-01", "name": "Servidor Web institucional",
        "asset_type": AssetType.SERVIDOR, "criticality": AssetCriticality.ALTA,
        "hostname": "srv-web-01", "ip_address": "10.10.5.21",
        "operating_system": "Ubuntu Server 22.04", "wazuh_agent_id": "003",
        "business_service": "Portal público", "owner": "Direcção de Sistemas",
        "description": "Aloja o portal institucional. Exposto à Internet.",
        "tags": ["producao", "exposto"],
    },
    {
        "identifier": "srv-bd-01", "name": "Servidor de base de dados",
        "asset_type": AssetType.BASE_DADOS, "criticality": AssetCriticality.CRITICA,
        "hostname": "srv-bd-01", "ip_address": "10.10.5.30",
        "operating_system": "Ubuntu Server 22.04", "wazuh_agent_id": "004",
        "business_service": "Sistemas de gestão", "owner": "Direcção de Sistemas",
        "description": "Base de dados central. Sem exposição directa à Internet.",
        "tags": ["producao", "dados-sensiveis"],
    },
    {
        "identifier": "est-financas-07", "name": "Estação de trabalho — Finanças",
        "asset_type": AssetType.ESTACAO, "criticality": AssetCriticality.MEDIA,
        "hostname": "est-financas-07", "ip_address": "10.10.20.107",
        "operating_system": "Windows 11", "wazuh_agent_id": "011",
        "business_service": "Administrativo", "owner": "Departamento Financeiro",
        "description": "Posto de trabalho com acesso a aplicações financeiras.",
        "tags": ["posto-de-trabalho"],
    },
    {
        "identifier": "fw-perimetro", "name": "Firewall de perímetro",
        "asset_type": AssetType.EQUIPAMENTO_REDE, "criticality": AssetCriticality.CRITICA,
        "hostname": "fw-perimetro", "ip_address": "10.10.1.1",
        "operating_system": "pfSense", "business_service": "Infraestrutura de rede",
        "owner": "Direcção de Sistemas",
        "description": "Controla o tráfego entre a rede interna e a Internet.",
        "tags": ["rede", "fronteira"],
    },
)


async def seed_lab_assets(session: AsyncSession) -> tuple[int, int]:
    existing = {a.identifier for a in (await session.execute(select(Asset))).scalars()}
    created = kept = 0
    for spec in LAB_ASSETS:
        if spec["identifier"] in existing:
            kept += 1
            continue
        session.add(Asset(**spec, is_active=True))
        created += 1
    await session.flush()
    return created, kept
