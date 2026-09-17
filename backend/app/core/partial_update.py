"""Edição parcial (PATCH): o que `null` pode e não pode apagar.

Num PATCH, omitir um campo quer dizer "não mexer"; enviá-lo a `null` quer dizer
"apagar". Os esquemas de edição declaram todos os campos como opcionais — é o que
permite omiti-los —, e por isso aceitam também `null` em campos que a base de
dados exige preenchidos. Aplicado com `setattr`, o objecto ficava inválido e a
rota rebentava ao serializar a resposta ou ao gravar: HTTP 500 para um erro do
cliente.

A decisão sobre o que pode ser apagado vem do modelo, e não de uma lista em cada
esquema: a coluna declarada `nullable=False` é a fonte de verdade, e uma lista
paralela ficaria desactualizada à primeira coluna nova.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import inspect

from app.core.errors import ValidationError


def reject_nulls_for_required(target: object, changes: dict[str, Any]) -> None:
    """Recusa com 422 os campos enviados a `null` que o modelo exige preenchidos.

    Campos que não são colunas (relações, valores tratados à parte pela rota) são
    ignorados: não é aqui que se decide sobre eles.
    """
    columns = inspect(type(target)).columns
    required = sorted(
        name
        for name, value in changes.items()
        if value is None and name in columns and not columns[name].nullable
    )
    if required:
        raise ValidationError(
            "Estes campos não podem ficar vazios: " + ", ".join(required) + ".",
            code="CAMPO_OBRIGATORIO",
            details={"campos": required},
        )
