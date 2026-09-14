"""auditoria: bloquear tambem TRUNCATE

Revision ID: 0003_audit_trunc
Revises: 0002_seq_audit
Create Date: 2026-09-14

Os gatilhos BEFORE UPDATE/DELETE de 0002 sao de nivel *linha* e o TRUNCATE nao
os dispara - um TRUNCATE apagaria toda a auditoria sem encontrar resistencia.
Fecha-se a lacuna com um gatilho de nivel *statement*.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_audit_trunc"
down_revision: str | None = "0002_seq_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_no_truncate
        BEFORE TRUNCATE ON audit_logs
        FOR EACH STATEMENT EXECUTE FUNCTION sheisa_audit_logs_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON audit_logs")
