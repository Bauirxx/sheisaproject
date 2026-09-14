"""sequencias de referencia e auditoria imutavel

Revision ID: 0002_seq_audit
Revises: 098a75fc68d8
Create Date: 2026-09-14

Duas garantias que não podem viver na camada aplicacional:

1. **Sequências de referência.** Os identificadores legíveis (INC-000125) são
   atribuídos por sequências do PostgreSQL. Gerar o próximo número com
   `SELECT max(...)+1` seria uma condição de corrida sob ingestão concorrente,
   e é exactamente sob carga que a plataforma tem de continuar correcta.

2. **Auditoria imutável.** Um gatilho recusa `UPDATE` e `DELETE` sobre
   `audit_logs`. O §16 exige que a auditoria seja central e fiável; se um bug
   (ou um utilizador com acesso à base de dados) puder reescrever o registo, a
   auditoria deixa de ter valor probatório. Esta é a diferença entre "registamos
   o que aconteceu" e "o que registámos não pode ser alterado".
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_seq_audit"
down_revision: str | None = "098a75fc68d8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: (nome da sequência, valor inicial)
SEQUENCES: tuple[tuple[str, int], ...] = (
    ("incident_reference_seq", 1),
    ("alert_reference_seq", 1),
    ("campaign_reference_seq", 1),
    ("action_reference_seq", 1),
    ("playbook_execution_reference_seq", 1),
    ("report_reference_seq", 1),
)


def upgrade() -> None:
    for name, start in SEQUENCES:
        op.execute(f"CREATE SEQUENCE IF NOT EXISTS {name} START WITH {start} INCREMENT BY 1")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION sheisa_audit_logs_immutable()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'O registo de auditoria e imutavel: % nao e permitido em audit_logs.',
                TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION sheisa_audit_logs_immutable();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION sheisa_audit_logs_immutable();
        """
    )

    # Índice para pesquisa textual em incidentes (§27: pesquisa). `pg_trgm`
    # permite pesquisa por semelhança em título e descrição sem exigir uma
    # configuração de dicionário em português.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(
        "CREATE INDEX ix_incidents_title_trgm ON incidents "
        "USING gin (title gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX ix_alerts_title_trgm ON alerts "
        "USING gin (title gin_trgm_ops)"
    )
    op.execute(
        "CREATE INDEX ix_iocs_value_trgm ON iocs "
        "USING gin (value gin_trgm_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_iocs_value_trgm")
    op.execute("DROP INDEX IF EXISTS ix_alerts_title_trgm")
    op.execute("DROP INDEX IF EXISTS ix_incidents_title_trgm")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS sheisa_audit_logs_immutable()")
    for name, _ in SEQUENCES:
        op.execute(f"DROP SEQUENCE IF EXISTS {name}")
