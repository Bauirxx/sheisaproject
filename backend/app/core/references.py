"""Geração de identificadores legíveis (INC-000125).

Atribuídos por sequências do PostgreSQL. A alternativa óbvia —
`SELECT max(numero) + 1` — é uma condição de corrida: sob ingestão concorrente
dois incidentes receberiam a mesma referência. As sequências são atómicas e não
são revertidas por um rollback, o que é o comportamento desejado: preferimos um
buraco na numeração a uma referência duplicada.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class ReferenceKind:
    INCIDENT = ("INC", "incident_reference_seq", 6)
    ALERT = ("ALT", "alert_reference_seq", 6)
    CAMPAIGN = ("CMP", "campaign_reference_seq", 4)
    ACTION = ("ACT", "action_reference_seq", 6)
    PLAYBOOK_EXECUTION = ("EXE", "playbook_execution_reference_seq", 6)
    REPORT = ("REL", "report_reference_seq", 5)


async def next_reference(session: AsyncSession, kind: tuple[str, str, int]) -> str:
    """Devolve a próxima referência formatada, ex.: ``INC-000125``."""
    prefix, sequence, width = kind
    result = await session.execute(text(f"SELECT nextval('{sequence}')"))
    number = result.scalar_one()
    return f"{prefix}-{number:0{width}d}"
