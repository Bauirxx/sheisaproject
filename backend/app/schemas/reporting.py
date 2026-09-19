"""Esquemas das comunicações de incidente (§5 · §37).

Há dois públicos, e a separação é a parte que importa. `ReportPublicStatus` é o
que se devolve a quem comunicou — alguém sem conta na plataforma — e contém
deliberadamente **menos** campos do que o modelo tem: nada de incidente ligado,
nada de quem triou, nada da nota de triagem. `ReportRead` é a vista interna.

Manter os dois como esquemas distintos é o que impede a fuga: com um único
esquema e um `exclude` na rota, acrescentar um campo ao modelo expunha-o ao
exterior por omissão, e ninguém o notava.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.core.enums import (
    IncidentCategory,
    ReportChannel,
    ReportStatus,
    Severity,
)
from app.schemas.common import ApiInput, ApiModel, Email


# ================================================================== submissão
class ReportSubmit(ApiInput):
    """Corpo da submissão pública.

    Os limites não são decorativos: este é o único ponto de escrita da
    plataforma sem autenticação, pelo que o tamanho de cada campo é a primeira
    defesa contra alguém encher a base de dados por um formulário aberto.

    `claimed_category` e `claimed_severity` são opcionais de propósito. Quem
    comunica um incidente muitas vezes não sabe classificá-lo, e obrigá-lo a
    escolher produziria classificações inventadas — piores do que a ausência.
    """

    reporter_name: str = Field(min_length=2, max_length=160)
    reporter_email: Email
    reporter_organisation: str = Field(default="", max_length=160)
    reporter_phone: str = Field(default="", max_length=40)

    subject: str = Field(min_length=5, max_length=300)
    description: str = Field(min_length=20, max_length=20_000)

    claimed_category: IncidentCategory | None = None
    claimed_severity: Severity | None = None
    #: Endereços, domínios ou URLs em texto livre, como quem comunica os
    #: escreveu. Não são validados nem promovidos a IOC.
    reported_indicators: str = Field(default="", max_length=4_000)


class ReportSubmitted(ApiModel):
    """Resposta à submissão: a referência e o código, uma única vez."""

    referencia: str
    codigo_de_acompanhamento: str
    aviso: str


# ============================================================== acompanhamento
class ReportPublicStatus(ApiModel):
    """Estado devolvido a quem comunicou (§37).

    Os campos ausentes são a característica principal deste esquema, não uma
    omissão: o incidente ligado, quem triou e a nota de triagem ficam de fora
    porque são dados internos.
    """

    referencia: str
    estado: ReportStatus
    #: Frase escrita para ser lida por alguém de fora da organização.
    situacao: str
    recebida_em: datetime
    avaliada_em: datetime | None = None
    aviso_de_recepcao_enviado: bool


# =================================================================== interno
class ReportIncidentLink(ApiModel):
    """Incidente ligado, no mínimo necessário para navegar até ele."""

    id: uuid.UUID
    reference: str
    title: str
    status: str
    severity: str


class ReportListItem(ApiModel):
    """Linha da fila de comunicações."""

    id: uuid.UUID
    reference: str
    status: ReportStatus
    channel: ReportChannel
    subject: str
    reporter_name: str
    reporter_email: str
    reporter_organisation: str
    claimed_category: IncidentCategory | None = None
    claimed_severity: Severity | None = None
    received_at: datetime
    triaged_at: datetime | None = None
    #: Quantas vezes quem comunicou foi ver o estado. Um número alto numa
    #: comunicação ainda por triar é alguém à espera.
    tracking_views: int
    acknowledged_at: datetime | None = None
    incidents: list[ReportIncidentLink] = Field(default_factory=list)


class ReportRead(ReportListItem):
    """Detalhe, com o que a listagem não traz por ser volumoso."""

    description: str
    reporter_phone: str
    reported_indicators: str
    submitted_from_ip: str | None = None
    channel_metadata: dict = Field(default_factory=dict)
    triage_note: str
    duplicate_of_reference: str | None = None
    triaged_by_email: str | None = None


# =================================================================== decisões
class ReportAccept(ApiInput):
    """Aceitar exige um incidente: existente ou novo, nunca nenhum."""

    #: Ligar a este incidente. Mutuamente exclusivo com `criar_incidente`.
    incident_id: uuid.UUID | None = None
    #: Criar um incidente a partir da comunicação.
    criar_incidente: bool = False
    #: Classificação **do analista**. Sem ela, herda o que o comunicante
    #: afirmou — mas passa a constar do incidente como avaliação da plataforma.
    categoria: IncidentCategory | None = None
    severidade: Severity | None = None
    nota: str = Field(min_length=3, max_length=2_000)


class ReportReject(ApiInput):
    """Recusar exige justificação: quem comunicou vai ler o estado."""

    nota: str = Field(min_length=3, max_length=2_000)


class ReportDuplicate(ApiInput):
    original_id: uuid.UUID
    nota: str = Field(default="", max_length=2_000)


class ReportLinkIncident(ApiInput):
    incident_id: uuid.UUID
