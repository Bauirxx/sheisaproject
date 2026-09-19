"""comunicacoes de incidente vindas de fora

Revision ID: 0006_comunicacoes
Revises: 0005_instantes_reais
Create Date: 2026-09-19

Cria a tabela das comunicacoes externas e a ligacao muitos-para-muitos aos
incidentes (§5 · §37 do briefing, inspirado no RTIR).

**Porque muitos-para-muitos.** As duas direccoes acontecem: varias comunicacoes
sobre a mesma campanha convergem num incidente, e uma comunicacao sobre um
incidente que atinge vários sistemas pode dar origem a mais do que um. Um campo
`incident_id` na comunicacao forcaria uma escolha que nao existe.

**A sequencia da referencia.** `COM-00001` e gerado por sequencia do PostgreSQL,
como as restantes: `SELECT max(numero) + 1` seria uma condicao de corrida e duas
submissoes simultaneas receberiam a mesma referencia -- que e justamente o que o
comunicante vai citar ao pedir o estado. Preferimos um buraco na numeracao a uma
referencia duplicada.

A sequencia e criada aqui e nao na 0002 porque uma migracao ja aplicada nao se
reescreve: quem tem a base no 0005 nunca voltaria a correr a 0002.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_comunicacoes"
down_revision: str | None = "0005_instantes_reais"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEQUENCIA = "incident_report_reference_seq"


def upgrade() -> None:
    op.execute(f"CREATE SEQUENCE IF NOT EXISTS {SEQUENCIA} START WITH 1 INCREMENT BY 1")

    op.create_table('incident_reports',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('reference', sa.String(length=24), nullable=False),
    sa.Column('reporter_name', sa.String(length=160), nullable=False),
    sa.Column('reporter_email', sa.String(length=254), nullable=False),
    sa.Column('reporter_organisation', sa.String(length=160), nullable=False),
    sa.Column('reporter_phone', sa.String(length=40), nullable=False),
    sa.Column('channel', sa.Enum('PORTAL', 'EMAIL', 'API', 'MANUAL', name='reportchannel', native_enum=False, length=40), nullable=False),
    sa.Column('submitted_from_ip', sa.String(length=45), nullable=True),
    sa.Column('subject', sa.String(length=300), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('claimed_category', sa.Enum('CONTEUDO_ABUSIVO', 'CODIGO_MALICIOSO', 'RECOLHA_INFORMACAO', 'TENTATIVA_INTRUSAO', 'INTRUSAO', 'DISPONIBILIDADE', 'SEGURANCA_INFORMACAO', 'FRAUDE', 'VULNERABILIDADE', 'OUTRO', name='incidentcategory', native_enum=False, length=40), nullable=True),
    sa.Column('claimed_severity', sa.Enum('INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA', name='severity', native_enum=False, length=40), nullable=True),
    sa.Column('reported_indicators', sa.Text(), nullable=False),
    sa.Column('channel_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.Enum('RECEBIDA', 'EM_TRIAGEM', 'ACEITE', 'RECUSADA', 'DUPLICADA', name='reportstatus', native_enum=False, length=40), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('triaged_by_id', sa.UUID(), nullable=True),
    sa.Column('triaged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('triage_note', sa.Text(), nullable=False),
    sa.Column('duplicate_of_id', sa.UUID(), nullable=True),
    sa.Column('tracking_token_hash', sa.String(length=64), nullable=False),
    sa.Column('tracking_views', sa.Integer(), nullable=False),
    sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.ForeignKeyConstraint(['duplicate_of_id'], ['incident_reports.id'], name=op.f('fk_incident_reports_duplicate_of_id_incident_reports'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['triaged_by_id'], ['users.id'], name=op.f('fk_incident_reports_triaged_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_reports')),
    sa.UniqueConstraint('reference', name='uq_incident_reports_reference')
    )
    op.create_index(op.f('ix_incident_reports_channel'), 'incident_reports', ['channel'], unique=False)
    op.create_index(op.f('ix_incident_reports_created_at'), 'incident_reports', ['created_at'], unique=False)
    op.create_index(op.f('ix_incident_reports_received_at'), 'incident_reports', ['received_at'], unique=False)
    op.create_index(op.f('ix_incident_reports_reference'), 'incident_reports', ['reference'], unique=False)
    op.create_index('ix_incident_reports_reporter_email', 'incident_reports', ['reporter_email'], unique=False)
    op.create_index(op.f('ix_incident_reports_status'), 'incident_reports', ['status'], unique=False)
    op.create_index('ix_incident_reports_status_received', 'incident_reports', ['status', 'received_at'], unique=False)
    op.create_index(op.f('ix_incident_reports_tracking_token_hash'), 'incident_reports', ['tracking_token_hash'], unique=False)
    op.create_table('report_incidents',
    sa.Column('report_id', sa.UUID(), nullable=False),
    sa.Column('incident_id', sa.UUID(), nullable=False),
    sa.Column('linked_at', sa.DateTime(timezone=True), server_default=sa.text('clock_timestamp()'), nullable=False),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_report_incidents_incident_id_incidents'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['report_id'], ['incident_reports.id'], name=op.f('fk_report_incidents_report_id_incident_reports'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('report_id', 'incident_id', name=op.f('pk_report_incidents'))
    )


def downgrade() -> None:
    op.drop_table('report_incidents')
    op.drop_index(op.f('ix_incident_reports_tracking_token_hash'), table_name='incident_reports')
    op.drop_index('ix_incident_reports_status_received', table_name='incident_reports')
    op.drop_index(op.f('ix_incident_reports_status'), table_name='incident_reports')
    op.drop_index('ix_incident_reports_reporter_email', table_name='incident_reports')
    op.drop_index(op.f('ix_incident_reports_reference'), table_name='incident_reports')
    op.drop_index(op.f('ix_incident_reports_received_at'), table_name='incident_reports')
    op.drop_index(op.f('ix_incident_reports_created_at'), table_name='incident_reports')
    op.drop_index(op.f('ix_incident_reports_channel'), table_name='incident_reports')
    op.drop_table('incident_reports')
    op.execute(f"DROP SEQUENCE IF EXISTS {SEQUENCIA}")
