"""Comunicações de incidente vindas de fora (§5 · §37 · RTIR).

A distinção que o RTIR acerta, e que a maioria das ferramentas modernas perdeu:
**a comunicação não é o incidente.** É matéria-prima. Várias comunicações podem
descrever o mesmo incidente — e uma comunicação pode não descrever incidente
nenhum. Por isso a relação é muitos-para-muitos e não um campo, e por isso a
comunicação tem ciclo de vida próprio.

**Quem comunica não é utilizador da plataforma.** É a diferença de natureza entre
uma ferramenta de SOC interno e uma de CSIRT: um regulador recebe comunicações de
constituintes que nunca terão conta aqui. Por isso os dados do comunicante são
campos de texto e não uma chave estrangeira para `users` — e por isso existe um
código de acompanhamento, que é a única forma de alguém sem conta voltar a saber
o estado do que comunicou.

O código é o que permite cumprir a regra do §37: *o utilizador externo nunca deve
aceder a dados internos.* Não dá acesso a nada — identifica apenas a
comunicação de quem a fez, e o que se devolve é o estado dela, nunca o incidente
a que foi ligada, nem quem a triou.

**O que o comunicante afirma fica separado do que o analista conclui.** Os campos
`claimed_category` e `claimed_severity` guardam a classificação de quem comunica;
a da plataforma vive no incidente. Fundi-los faria uma afirmação de terceiros
passar por avaliação própria, que é o que o §4 proíbe.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    IncidentCategory,
    ReportChannel,
    ReportStatus,
    Severity,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk

#: Ligação muitos-para-muitos entre comunicações e incidentes.
#:
#: Muitos-para-muitos porque as duas direcções acontecem na prática: várias
#: comunicações sobre a mesma campanha convergem num incidente, e uma única
#: comunicação sobre um incidente em vários sistemas pode dar origem a mais do
#: que um. Um campo `incident_id` na comunicação forçaria uma escolha falsa.
report_incidents = Table(
    "report_incidents",
    Base.metadata,
    Column(
        "report_id",
        PGUUID(as_uuid=True),
        ForeignKey("incident_reports.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "incident_id",
        PGUUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "linked_at",
        DateTime(timezone=True),
        nullable=False,
        server_default=func.clock_timestamp(),
    ),
)


class IncidentReport(Base, TimestampMixin):
    """Comunicação de incidente recebida do exterior."""

    __tablename__ = "incident_reports"
    __table_args__ = (
        UniqueConstraint("reference", name="uq_incident_reports_reference"),
        Index("ix_incident_reports_status_received", "status", "received_at"),
        # A procura por quem comunicou é a consulta natural quando chega uma
        # segunda comunicação da mesma origem.
        Index("ix_incident_reports_reporter_email", "reporter_email"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Identificador legível (COM-00042), dado ao comunicante.
    reference: Mapped[str] = mapped_column(String(24), nullable=False, index=True)

    # --------------------------------------------------------- quem comunicou
    #: Nome declarado. Não é verificado, e a interface di-lo.
    reporter_name: Mapped[str] = mapped_column(String(160), nullable=False)
    reporter_email: Mapped[str] = mapped_column(String(254), nullable=False)
    reporter_organisation: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    reporter_phone: Mapped[str] = mapped_column(String(40), nullable=False, default="")

    channel: Mapped[ReportChannel] = mapped_column(
        enum_column(ReportChannel), nullable=False, index=True
    )
    #: Endereço de onde a submissão partiu. Serve para investigar abuso do
    #: formulário público, que é a superfície mais exposta da plataforma.
    submitted_from_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # ----------------------------------------------------------- o que diz
    subject: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    #: Classificação **afirmada pelo comunicante**, não a da plataforma.
    claimed_category: Mapped[IncidentCategory | None] = mapped_column(
        enum_column(IncidentCategory), nullable=True
    )
    claimed_severity: Mapped[Severity | None] = mapped_column(
        enum_column(Severity), nullable=True
    )
    #: Indicadores em texto livre, como o comunicante os escreveu (IP, domínio,
    #: URL). Não são promovidos a IOC automaticamente: um valor não verificado
    #: no catálogo global contaminaria a triagem de tudo o que o toque.
    reported_indicators: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Campos por canal, preservados como chegaram (cabeçalhos de email, por
    #: exemplo). Serve de prova de origem, como o `raw_payload` do evento.
    channel_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # --------------------------------------------------------------- triagem
    status: Mapped[ReportStatus] = mapped_column(
        enum_column(ReportStatus), nullable=False, default=ReportStatus.RECEBIDA, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp(), index=True
    )
    triaged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Porque foi aceite, recusada ou marcada duplicada. Obrigatória na recusa:
    #: uma comunicação recusada sem motivo é indistinguível de uma esquecida.
    triage_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Quando é duplicada, qual é a original.
    duplicate_of_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incident_reports.id", ondelete="SET NULL"), nullable=True
    )

    # ------------------------------------------------------- acompanhamento
    #: Hash do código dado ao comunicante. Como nas chaves de ingestão,
    #: persiste-se apenas o resumo: o código em claro é mostrado uma única vez,
    #: e nem o administrador o pode recuperar depois.
    tracking_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: Quantas vezes o comunicante consultou o estado. Um número alto sem
    #: resposta nossa é o sinal de que alguém está à espera.
    tracking_views: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Se o aviso de recepção chegou a ser enviado, e quando. `None` significa
    #: que não foi — nunca se assume envio sem confirmação do servidor de email.
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ------------------------------------------------------------- relações
    triaged_by = relationship("User", foreign_keys=[triaged_by_id], lazy="selectin")
    duplicate_of = relationship("IncidentReport", remote_side=[id], lazy="selectin")
    incidents = relationship(
        "Incident", secondary=report_incidents, lazy="selectin", viewonly=False
    )

    def __repr__(self) -> str:  # pragma: no cover - diagnóstico
        return f"<IncidentReport {self.reference} {self.status.value}>"
