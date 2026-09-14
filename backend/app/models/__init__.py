"""Registo central dos modelos.

Importar este pacote garante que todos os modelos estão registados no
`Base.metadata` antes de o Alembic ou os testes o consultarem. A ordem de
importação segue as dependências entre módulos.
"""

from app.models.base import Base
from app.models.identity import (
    ApiKey,
    Permission,
    Role,
    Team,
    User,
    UserSession,
    role_permissions,
)
from app.models.catalog import (
    Asset,
    Campaign,
    Ioc,
    MitreTactic,
    MitreTechnique,
)
from app.models.system import (
    AuditLog,
    Integration,
    Notification,
    Report,
)
from app.models.telemetry import Alert, CorrelationRule, Event
from app.models.incident import (
    Incident,
    IncidentRelation,
    IncidentTechnique,
    incident_assets,
)
from app.models.investigation import (
    Comment,
    Evidence,
    Observation,
    Task,
    task_dependencies,
)
from app.models.intelligence import Recommendation
from app.models.response import (
    Action,
    ActionApproval,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
    PlaybookStepExecution,
)

__all__ = [
    "Action",
    "ActionApproval",
    "Alert",
    "ApiKey",
    "Asset",
    "AuditLog",
    "Base",
    "Campaign",
    "Comment",
    "CorrelationRule",
    "Event",
    "Evidence",
    "Incident",
    "IncidentRelation",
    "IncidentTechnique",
    "Integration",
    "Ioc",
    "MitreTactic",
    "MitreTechnique",
    "Notification",
    "Observation",
    "Permission",
    "Playbook",
    "PlaybookExecution",
    "PlaybookStep",
    "PlaybookStepExecution",
    "Recommendation",
    "Report",
    "Role",
    "Task",
    "Team",
    "User",
    "UserSession",
    "incident_assets",
    "role_permissions",
    "task_dependencies",
]
