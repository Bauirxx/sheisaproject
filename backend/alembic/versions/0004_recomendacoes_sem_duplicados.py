"""recomendacoes: no maximo uma pendente por tipo e alvo

Revision ID: 0004_reco_unica
Revises: 0003_audit_trunc
Create Date: 2026-09-15

O motor de recomendacoes e re-executavel: correr a geracao duas vezes sobre o
mesmo alerta ou incidente tem de produzir o mesmo resultado, e nao duas copias
da mesma sugestao. O servico ja reutiliza a recomendacao pendente existente,
mas duas geracoes concorrentes conseguiriam inserir as duas antes de qualquer
uma ver a outra.

A garantia fica onde nao depende de ordem de execucao: um indice unico parcial.
E parcial de proposito - o historico de recomendacoes ja decididas (aceites,
rejeitadas, expiradas) tem de poder acumular varias entradas do mesmo tipo
sobre o mesmo alvo, porque e esse historico que impede o motor de insistir numa
proposta que ja foi recusada.

`status` e VARCHAR com CHECK (ver `enum_column`), pelo que a condicao do indice
compara directamente com a cadeia de caracteres.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_reco_unica"
down_revision: str | None = "0003_audit_trunc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE UNIQUE INDEX uq_recommendations_pendente_por_alvo
        ON recommendations (kind, target_type, target_id)
        WHERE status = 'PENDENTE';
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_recommendations_pendente_por_alvo")
