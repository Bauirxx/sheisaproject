"""instantes reais: created_at e updated_at com clock_timestamp()

Revision ID: 0005_instantes_reais
Revises: 0004_reco_unica
Create Date: 2026-09-17

`now()` do PostgreSQL nao devolve a hora actual: devolve a hora de **inicio da
transaccao**, e repete-a em todas as chamadas dentro dela. Um pedido que crie um
incidente, mude o estado tres vezes e escreva um comentario grava tudo com o
mesmo instante - o do inicio.

Isto partia a linha temporal do incidente. A auditoria regista a hora real
(`datetime.now(UTC)` em Python), mas comentarios, evidencias, tarefas e accoes
usavam `now()`. Ao ordenar tudo no mesmo eixo, os comentarios caiam para o
inicio: no cenario de demonstracao, "Estado alterado de RESOLVIDO para
ENCERRADO" aparecia antes de "Criar incidente". Sem erro nenhum - so uma
historia contada ao contrario, que e o que se mostra numa defesa.

`clock_timestamp()` devolve a hora real no instante da chamada. A alteracao e
so do valor por omissao das colunas: nenhum dado existente e reescrito, e o
downgrade repoe `now()`.

`updated_at` muda em conjunto com `created_at`. Mudar so um criava uma
inconsistencia nova: uma linha criada e alterada na mesma transaccao ficaria
com `updated_at` anterior ao `created_at`.

As colunas sao encontradas pelo catalogo em vez de listadas, para que uma tabela
acrescentada antes desta migracao nao fique esquecida.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0005_instantes_reais"
down_revision: str | None = "0004_reco_unica"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _trocar_valor_por_omissao(de: str, para: str) -> None:
    op.execute(
        f"""
        DO $$
        DECLARE coluna record;
        BEGIN
          FOR coluna IN
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND column_name IN ('created_at', 'updated_at')
              AND column_default = '{de}'
          LOOP
            EXECUTE format(
              'ALTER TABLE %I ALTER COLUMN %I SET DEFAULT {para}',
              coluna.table_name, coluna.column_name
            );
          END LOOP;
        END $$;
        """
    )


def upgrade() -> None:
    _trocar_valor_por_omissao("now()", "clock_timestamp()")


def downgrade() -> None:
    _trocar_valor_por_omissao("clock_timestamp()", "now()")
