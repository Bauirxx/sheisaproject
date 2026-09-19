"""Catálogo de permissões e perfis (§22).

O controlo de acesso é declarado num único sítio, em vez de espalhado por
verificações ad-hoc nas rotas. Cada permissão é uma string `recurso:acção`.

Princípio inegociável: **a autorização é verificada no backend**. O frontend
esconde o que o utilizador não pode fazer por cortesia, não por segurança — uma
chamada directa à API sem a permissão devida devolve 403 e fica registada na
auditoria com resultado NEGADO.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Permission(StrEnum):
    # --- alertas e eventos ---
    ALERTS_READ = "alerts:read"
    ALERTS_TRIAGE = "alerts:triage"          # mudar estado, descartar, marcar FP
    ALERTS_PROMOTE = "alerts:promote"        # criar/ligar incidente a partir do alerta
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"          # usado por chaves de API de fontes

    # --- comunicações de incidente vindas de fora (§5 · §37) ---
    REPORTS_INBOX_READ = "reports_inbox:read"
    REPORTS_INBOX_TRIAGE = "reports_inbox:triage"   # aceitar, recusar, duplicar

    # --- incidentes ---
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_TRANSITION = "incidents:transition"
    INCIDENTS_ASSIGN = "incidents:assign"
    INCIDENTS_CLOSE = "incidents:close"
    INCIDENTS_RELATE = "incidents:relate"
    INCIDENTS_DELETE = "incidents:delete"

    # --- investigação ---
    COMMENTS_CREATE = "comments:create"
    TASKS_READ = "tasks:read"
    TASKS_MANAGE = "tasks:manage"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_UPLOAD = "evidence:upload"
    EVIDENCE_DELETE = "evidence:delete"
    OBSERVATIONS_MANAGE = "observations:manage"

    # --- inteligência ---
    IOCS_READ = "iocs:read"
    IOCS_MANAGE = "iocs:manage"
    THREATINTEL_READ = "threatintel:read"
    THREATINTEL_MANAGE = "threatintel:manage"
    MITRE_READ = "mitre:read"
    MITRE_MAP = "mitre:map"
    RECOMMENDATIONS_READ = "recommendations:read"
    RECOMMENDATIONS_DECIDE = "recommendations:decide"

    # --- activos ---
    ASSETS_READ = "assets:read"
    ASSETS_MANAGE = "assets:manage"

    # --- automação e resposta ---
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_MANAGE = "playbooks:manage"
    PLAYBOOKS_EXECUTE = "playbooks:execute"
    ACTIONS_READ = "actions:read"
    ACTIONS_PROPOSE = "actions:propose"
    ACTIONS_APPROVE = "actions:approve"              # acções de risco moderado
    ACTIONS_APPROVE_CRITICAL = "actions:approve_critical"  # acções críticas (§13)
    ACTIONS_EXECUTE = "actions:execute"

    # --- observabilidade e governo ---
    DASHBOARD_READ = "dashboard:read"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    AUDIT_READ = "audit:read"

    # --- administração ---
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    ROLES_MANAGE = "roles:manage"
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_MANAGE = "integrations:manage"
    SETTINGS_MANAGE = "settings:manage"
    CORRELATION_MANAGE = "correlation:manage"


class RoleName(StrEnum):
    ADMINISTRADOR = "ADMINISTRADOR"
    ANALISTA_SOC = "ANALISTA_SOC"
    INVESTIGADOR = "INVESTIGADOR"
    GESTOR = "GESTOR"
    AUDITOR = "AUDITOR"
    OPERADOR = "OPERADOR"


P = Permission

#: Leitura transversal partilhada pelos perfis operacionais.
_READ_OPERACIONAL: Final[frozenset[Permission]] = frozenset({
    P.ALERTS_READ, P.EVENTS_READ, P.INCIDENTS_READ, P.TASKS_READ,
    P.REPORTS_INBOX_READ,
    P.EVIDENCE_READ, P.IOCS_READ, P.THREATINTEL_READ, P.MITRE_READ,
    P.ASSETS_READ, P.PLAYBOOKS_READ, P.ACTIONS_READ,
    P.RECOMMENDATIONS_READ, P.DASHBOARD_READ, P.REPORTS_READ,
})

#: Perfis pré-definidos. São semente inicial: o administrador pode ajustar as
#: permissões de cada perfil em tempo de execução (as permissões efectivas vêm
#: sempre da base de dados, nunca deste mapa).
ROLE_PERMISSIONS: Final[dict[RoleName, frozenset[Permission]]] = {
    # Acesso total. Único perfil que pode gerir utilizadores e integrações.
    RoleName.ADMINISTRADOR: frozenset(Permission),

    # Primeira linha: tria alertas e conduz incidentes. Pode propor acções de
    # resposta mas não aprovar as suas próprias - separação de funções.
    RoleName.ANALISTA_SOC: _READ_OPERACIONAL | {
        P.ALERTS_TRIAGE, P.ALERTS_PROMOTE,
        P.REPORTS_INBOX_TRIAGE,
        P.INCIDENTS_CREATE, P.INCIDENTS_UPDATE, P.INCIDENTS_TRANSITION,
        P.INCIDENTS_ASSIGN, P.INCIDENTS_RELATE,
        P.COMMENTS_CREATE, P.TASKS_MANAGE,
        P.EVIDENCE_UPLOAD, P.OBSERVATIONS_MANAGE,
        P.IOCS_MANAGE, P.MITRE_MAP,
        P.RECOMMENDATIONS_DECIDE,
        P.PLAYBOOKS_EXECUTE, P.ACTIONS_PROPOSE,
        P.REPORTS_GENERATE,
    },

    # Segunda linha: análise aprofundada. Acrescenta gestão de threat intel e
    # encerramento de incidentes.
    RoleName.INVESTIGADOR: _READ_OPERACIONAL | {
        P.ALERTS_TRIAGE, P.ALERTS_PROMOTE,
        P.REPORTS_INBOX_TRIAGE,
        P.INCIDENTS_CREATE, P.INCIDENTS_UPDATE, P.INCIDENTS_TRANSITION,
        P.INCIDENTS_ASSIGN, P.INCIDENTS_RELATE, P.INCIDENTS_CLOSE,
        P.COMMENTS_CREATE, P.TASKS_MANAGE,
        P.EVIDENCE_UPLOAD, P.OBSERVATIONS_MANAGE,
        P.IOCS_MANAGE, P.THREATINTEL_MANAGE, P.MITRE_MAP,
        P.RECOMMENDATIONS_DECIDE,
        P.PLAYBOOKS_EXECUTE, P.ACTIONS_PROPOSE,
        P.REPORTS_GENERATE, P.ASSETS_MANAGE,
    },

    # Coordenação: não investiga, mas decide. É quem aprova acções disruptivas.
    RoleName.GESTOR: _READ_OPERACIONAL | {
        P.INCIDENTS_ASSIGN, P.INCIDENTS_CLOSE, P.INCIDENTS_TRANSITION,
        P.COMMENTS_CREATE, P.TASKS_MANAGE,
        P.ACTIONS_APPROVE, P.ACTIONS_APPROVE_CRITICAL,
        P.REPORTS_GENERATE, P.AUDIT_READ, P.USERS_READ,
        P.PLAYBOOKS_MANAGE,
    },

    # Só leitura, incluindo o registo de auditoria. Não pode alterar nada -
    # é o que dá valor probatório à sua consulta.
    RoleName.AUDITOR: _READ_OPERACIONAL | {
        P.AUDIT_READ, P.USERS_READ, P.INTEGRATIONS_READ, P.REPORTS_GENERATE,
    },

    # Registo manual de ocorrências e acompanhamento. Perfil mínimo.
    RoleName.OPERADOR: frozenset({
        P.INCIDENTS_READ, P.INCIDENTS_CREATE, P.COMMENTS_CREATE,
        P.ALERTS_READ, P.TASKS_READ, P.EVIDENCE_READ, P.EVIDENCE_UPLOAD,
        P.DASHBOARD_READ, P.ASSETS_READ,
    }),
}

#: Descrições apresentadas na interface de administração.
ROLE_DESCRIPTIONS: Final[dict[RoleName, str]] = {
    RoleName.ADMINISTRADOR: (
        "Acesso total à plataforma, incluindo gestão de utilizadores, perfis, "
        "integrações e configurações."
    ),
    RoleName.ANALISTA_SOC: (
        "Triagem de alertas e condução de incidentes. Pode propor acções de "
        "resposta, mas não aprová-las."
    ),
    RoleName.INVESTIGADOR: (
        "Análise aprofundada de incidentes, gestão de threat intelligence e "
        "encerramento de investigações."
    ),
    RoleName.GESTOR: (
        "Coordenação operacional. Aprova acções de resposta, incluindo acções "
        "críticas, e consulta o registo de auditoria."
    ),
    RoleName.AUDITOR: (
        "Consulta integral em modo de leitura, incluindo o registo de "
        "auditoria. Não pode alterar dados."
    ),
    RoleName.OPERADOR: (
        "Registo manual de ocorrências e acompanhamento do respectivo estado."
    ),
}

PERMISSION_DESCRIPTIONS: Final[dict[Permission, str]] = {
    P.ALERTS_READ: "Consultar alertas",
    P.ALERTS_TRIAGE: "Triar alertas (descartar, marcar falso positivo)",
    P.ALERTS_PROMOTE: "Promover alertas a incidente",
    P.EVENTS_READ: "Consultar eventos brutos",
    P.EVENTS_INGEST: "Submeter eventos para ingestão",
    P.REPORTS_INBOX_READ: "Consultar comunicações de incidente recebidas de fora",
    P.REPORTS_INBOX_TRIAGE: (
        "Triar comunicações externas (aceitar ligando a incidente, recusar, duplicar)"
    ),
    P.INCIDENTS_READ: "Consultar incidentes",
    P.INCIDENTS_CREATE: "Registar incidentes",
    P.INCIDENTS_UPDATE: "Editar incidentes",
    P.INCIDENTS_TRANSITION: "Alterar o estado de incidentes",
    P.INCIDENTS_ASSIGN: "Atribuir responsável a incidentes",
    P.INCIDENTS_CLOSE: "Encerrar incidentes",
    P.INCIDENTS_RELATE: "Relacionar incidentes entre si",
    P.INCIDENTS_DELETE: "Eliminar incidentes",
    P.COMMENTS_CREATE: "Adicionar comentários",
    P.TASKS_READ: "Consultar tarefas",
    P.TASKS_MANAGE: "Criar e gerir tarefas",
    P.EVIDENCE_READ: "Consultar e descarregar evidências",
    P.EVIDENCE_UPLOAD: "Carregar evidências",
    P.EVIDENCE_DELETE: "Eliminar evidências",
    P.OBSERVATIONS_MANAGE: "Registar observações (avistamentos de artefactos)",
    P.IOCS_READ: "Consultar indicadores de compromisso",
    P.IOCS_MANAGE: "Criar e editar indicadores de compromisso",
    P.THREATINTEL_READ: "Consultar threat intelligence",
    P.THREATINTEL_MANAGE: "Gerir fontes e registos de threat intelligence",
    P.MITRE_READ: "Consultar o catálogo MITRE ATT&CK",
    P.MITRE_MAP: "Associar técnicas MITRE a incidentes",
    P.RECOMMENDATIONS_READ: "Consultar recomendações do motor de inteligência",
    P.RECOMMENDATIONS_DECIDE: "Aceitar ou rejeitar recomendações",
    P.ASSETS_READ: "Consultar activos",
    P.ASSETS_MANAGE: "Gerir o inventário de activos",
    P.PLAYBOOKS_READ: "Consultar playbooks",
    P.PLAYBOOKS_MANAGE: "Criar e editar playbooks",
    P.PLAYBOOKS_EXECUTE: "Executar playbooks",
    P.ACTIONS_READ: "Consultar acções de resposta",
    P.ACTIONS_PROPOSE: "Propor acções de resposta",
    P.ACTIONS_APPROVE: "Aprovar acções de risco moderado",
    P.ACTIONS_APPROVE_CRITICAL: "Aprovar acções críticas",
    P.ACTIONS_EXECUTE: "Executar acções aprovadas",
    P.DASHBOARD_READ: "Consultar o painel",
    P.REPORTS_READ: "Consultar relatórios",
    P.REPORTS_GENERATE: "Gerar relatórios",
    P.AUDIT_READ: "Consultar o registo de auditoria",
    P.USERS_READ: "Consultar utilizadores",
    P.USERS_MANAGE: "Criar, editar e desactivar utilizadores",
    P.ROLES_MANAGE: "Gerir perfis e permissões",
    P.INTEGRATIONS_READ: "Consultar integrações",
    P.INTEGRATIONS_MANAGE: "Configurar integrações",
    P.SETTINGS_MANAGE: "Alterar configurações da plataforma",
    P.CORRELATION_MANAGE: "Gerir regras de correlação",
}
