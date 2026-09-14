"""Saída do motor de inteligência operacional (§12).

Toda a recomendação transporta obrigatoriamente:

* **explicação** — em texto, legível por um analista;
* **confiança** — 0-100, calculada, não estimada à mão;
* **dados utilizados** — que registos concretos sustentam a conclusão;
* **decomposição por factor** — quanto cada critério contribuiu;
* **decisão** — aceite ou rejeitada, por quem e quando.

O motor é determinístico: a mesma entrada produz a mesma saída, e cada
pontuação é reproduzível a partir dos factores registados. Numa defesa
académica isto é verificável ao vivo; um modelo generativo não o seria.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import RecommendationKind, RecommendationStatus
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk


class Recommendation(Base, TimestampMixin):
    __tablename__ = "recommendations"
    __table_args__ = (
        Index("ix_recommendations_target", "target_type", "target_id"),
        Index("ix_recommendations_status_kind", "status", "kind"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[RecommendationKind] = mapped_column(
        enum_column(RecommendationKind), nullable=False, index=True
    )
    status: Mapped[RecommendationStatus] = mapped_column(
        enum_column(RecommendationStatus), nullable=False,
        default=RecommendationStatus.PENDENTE, index=True,
    )

    #: Alvo polimórfico: "incident" | "alert" | "ioc". Evita uma tabela de
    #: recomendações por tipo de alvo sem perder a integridade, porque o
    #: serviço valida a existência do alvo antes de gravar.
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)

    title: Mapped[str] = mapped_column(String(250), nullable=False)
    #: A recomendação em si, em português, dirigida ao analista.
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    #: Porque é que o motor chegou aqui.
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    #: 0-100. Calculada a partir dos factores, nunca atribuída arbitrariamente.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    #: Contribuição de cada critério: {"regra_historico_fp": -25, ...}
    factors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Registos concretos consultados: {"alerts": [...], "incidents": [...]}
    evidence_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Alteração proposta, aplicável mecanicamente se o analista aceitar.
    #: Ex.: {"field": "severity", "from": "MEDIA", "to": "ALTA"}
    proposed_change: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Identificação da versão do motor que a produziu. Permite reavaliar
    #: recomendações antigas quando a lógica muda (§36 - APRENDER).
    engine: Mapped[str] = mapped_column(String(60), nullable=False, default="deterministico")
    engine_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")

    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Se a alteração proposta chegou a ser aplicada ao alvo.
    applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    decided_by: Mapped["User | None"] = relationship(lazy="selectin")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Recommendation {self.kind} conf={self.confidence}>"
