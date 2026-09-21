"""Comunicações de incidente vindas de fora (§5 · §37 · RTIR).

Três operações, com públicos diferentes e por isso com regras diferentes.

**Submeter** é a única escrita da plataforma acessível sem autenticação. Não
confia em nada do que recebe: a classificação que o comunicante propõe fica em
campos `claimed_*` e não toca na avaliação da plataforma, os indicadores que
escreve ficam em texto e **não** são promovidos a IOC (um valor não verificado no
catálogo global contaminaria a triagem de tudo o que o tocasse), e o endereço de
origem é registado para permitir investigar abuso do formulário.

**Acompanhar** cumpre a regra do §37 — *o utilizador externo nunca deve aceder a
dados internos*. Devolve o estado da comunicação e mais nada: nem o incidente a
que foi ligada, nem quem a triou, nem a nota de triagem, que pode conter análise
interna. A comparação do código é em tempo constante, porque comparar com `==`
deixa medir quantos caracteres acertaram.

**Triar** é a decisão do analista, e segue o ciclo de vida de `REPORT_TRANSITIONS`
como todas as outras transições da plataforma. Aceitar **exige** ligar a um
incidente — marcar aceite sem ligação deixaria a comunicação fora da fila e fora
de qualquer incidente, e o trabalho desaparecia sem deixar rasto.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.config import settings
from app.core.enums import (
    REPORT_STATES_REQUIRING_INCIDENT,
    REPORT_TRANSITIONS,
    IncidentCategory,
    IncidentOrigin,
    ReportChannel,
    ReportStatus,
    Severity,
    SourceKind,
)
from app.core.errors import NotFoundError, ValidationError
from app.core.references import ReferenceKind, next_reference
from app.core.security import constant_time_equals
from app.models.identity import User
from app.models.incident import Incident
from app.models.reporting import IncidentReport
from app.services import email_service, incident_service

logger = logging.getLogger("sheisa")

#: Comprimento do código de acompanhamento em bytes de entropia.
#:
#: 24 bytes dão cerca de 32 caracteres, o que é longo demais para ser adivinhado
#: e curto o suficiente para ser copiado de um email para um formulário. O código
#: não dá acesso a nada além do estado de uma comunicação, mas é a única coisa
#: que protege esse estado de ser lido por quem tenha a referência — que é
#: sequencial e portanto trivial de enumerar.
BYTES_DO_CODIGO = 24


def _resumir(codigo: str) -> str:
    return hashlib.sha256(codigo.encode("utf-8")).hexdigest()


def gerar_codigo() -> tuple[str, str]:
    """Devolve (código em claro, resumo a persistir)."""
    bruto = secrets.token_urlsafe(BYTES_DO_CODIGO)
    return bruto, _resumir(bruto)


# =================================================================== submissão
async def submit(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    reporter_name: str,
    reporter_email: str,
    subject: str,
    description: str,
    reporter_organisation: str = "",
    reporter_phone: str = "",
    claimed_category: IncidentCategory | None = None,
    claimed_severity: Severity | None = None,
    reported_indicators: str = "",
    channel: ReportChannel = ReportChannel.PORTAL,
    submitted_from_ip: str | None = None,
    channel_metadata: dict | None = None,
    avisar: bool = True,
) -> tuple[IncidentReport, str]:
    """Registra uma comunicação e devolve-a com o código de acompanhamento.

    O código é devolvido **uma única vez**, como a chave de ingestão: a base de
    dados guarda apenas o resumo, pelo que nem o administrador o pode recuperar
    para o dar a quem o perdeu. Quem perde o código volta a comunicar.
    """
    codigo, resumo = gerar_codigo()
    referencia = await next_reference(session, ReferenceKind.INCIDENT_REPORT)

    relato = IncidentReport(
        reference=referencia,
        reporter_name=reporter_name.strip()[:160],
        reporter_email=reporter_email.strip().lower()[:254],
        reporter_organisation=reporter_organisation.strip()[:160],
        reporter_phone=reporter_phone.strip()[:40],
        channel=channel,
        submitted_from_ip=submitted_from_ip,
        subject=subject.strip()[:300],
        description=description,
        claimed_category=claimed_category,
        claimed_severity=claimed_severity,
        reported_indicators=reported_indicators,
        channel_metadata=channel_metadata or {},
        status=ReportStatus.RECEBIDA,
        received_at=datetime.now(UTC),
        tracking_token_hash=resumo,
    )
    session.add(relato)
    await session.flush()

    # O actor é anónimo de propósito quando a submissão vem do portal: quem
    # comunicou não é utilizador da plataforma, e inventar-lhe uma identidade no
    # registo faria parecer que alguém autenticado o fez.
    await audit.record(
        session,
        ctx,
        action="RECEBER_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=(
            f"Comunicação {relato.reference} recebida por {channel.value} de "
            f"{relato.reporter_email}: {relato.subject[:120]}"
        ),
        new_value={"estado": relato.status.value, "canal": channel.value},
        changed_fields=["status"],
    )

    # O aviso automático só faz sentido para uma submissão deliberada (o
    # portal): quem preencheu o formulário fica à espera da referência e do
    # código. Uma comunicação **recolhida da caixa** não o dispara, e é uma
    # decisão de segurança, não de estilo: responder automaticamente a tudo o
    # que entra numa caixa transforma-a numa máquina de auto-resposta — envia a
    # newsletters, a notificações, a qualquer remetente. Quem tria decide se e
    # quando responde. Foi o que causou o envio em cadeia observado ao apontar a
    # recolha a uma caixa com correio pessoal.
    if avisar:
        await _avisar_da_recepcao(session, relato, codigo)
    return relato, codigo


async def _avisar_da_recepcao(
    session: AsyncSession, relato: IncidentReport, codigo: str
) -> None:
    """Envia o aviso de recepção, se o canal estiver configurado.

    **Nunca faz falhar a submissão.** Perder uma comunicação porque o servidor de
    correio está em baixo seria trocar o essencial pelo acessório: a comunicação
    já está registada e tem referência. Uma falha de envio é registada e
    `acknowledged_at` fica `None`, que é a resposta honesta — a interface mostra
    "aviso não enviado" em vez de afirmar um envio que não houve.

    O SMTP é síncrono e bloqueia; corre numa linha de execução separada para não
    parar o ciclo de eventos enquanto o servidor responde.
    """
    if not settings.envio_de_email_configurado:
        return

    # Construído por linhas e unido no fim: uma cadeia com sequências de
    # escape atravessa várias camadas de ferramentas até chegar ao ficheiro,
    # e é uma fonte fiável de erros. Uma lista não tem esse problema.
    corpo = "\n".join([
        f"{relato.reporter_name},",
        "",
        "A sua comunicação foi recebida e está na fila para ser avaliada por",
        "um analista.",
        "",
        f"Referência: {relato.reference}",
        f"Código de acompanhamento: {codigo}",
        "",
        "Guarde os dois: é com eles que pode consultar o estado. O código não",
        "pode voltar a ser mostrado, porque guardamos apenas o seu resumo.",
        "",
        f"Assunto comunicado: {relato.subject}",
        "",
        "Se tiver informação nova, responda a esta mensagem.",
        "",
        "-- ",
        "Mensagem gerada automaticamente ao receber a sua comunicação.",
    ])

    try:
        await asyncio.to_thread(
            email_service.enviar,
            para=relato.reporter_email,
            assunto=f"[{relato.reference}] Comunicação recebida",
            corpo=corpo,
        )
    except Exception:
        # Registado e não levantado: a submissão está feita e não se desfaz por
        # causa disto. O estado fica visível em `acknowledged_at`.
        logger.exception(
            "Falhou o aviso de recepção da comunicação %s para %s",
            relato.reference,
            relato.reporter_email,
        )
        return

    relato.acknowledged_at = datetime.now(UTC)
    await session.flush()


# ===================================================== recolha do correio
async def recolher_do_email(
    session: AsyncSession, ctx: AuditContext
) -> dict:
    """Lê a caixa de segurança e cria uma comunicação por mensagem nova.

    Devolve o que aconteceu, item a item, em vez de um número: quem corre isto
    precisa de saber *o que* foi criado e *o que* foi ignorado e porquê. Um
    "recolhidas: 3" não diz se as outras sete foram duplicados ou falhas.

    **O duplicado é detectado pelo `Message-ID`.** O POP3 não guarda estado de
    lida, e uma mensagem reentregue pelo servidor de origem chegaria outra vez.
    Sem esta verificação, cada reentrega criava uma comunicação nova e quem
    comunicou recebia outro aviso de recepção com outra referência.

    O SMTP e o POP3 são síncronos e bloqueiam; a recolha corre numa linha de
    execução separada para não parar o ciclo de eventos.
    """
    if not settings.recolha_de_email_configurada:
        raise email_service.EmailNaoConfigurado(
            "A recolha de correio não está configurada: faltam SHEISA_POP3_HOST, "
            "SHEISA_POP3_USER ou SHEISA_POP3_PASSWORD."
        )

    mensagens = await asyncio.to_thread(email_service.recolher)
    resultados: list[dict] = []

    for mensagem in mensagens:
        # O que a plataforma enviou, respostas automáticas e devoluções não são
        # comunicações de ninguém. Registado com o motivo em vez de descartado em
        # silêncio: "ignorada" sem razão é indistinguível de "perdida".
        if mensagem.motivo_para_ignorar:
            resultados.append({
                "estado": "ignorada",
                "remetente": mensagem.remetente_email,
                "assunto": mensagem.assunto,
                "detalhe": mensagem.motivo_para_ignorar,
            })
            continue

        if mensagem.message_id:
            ja_existe = await session.execute(
                select(IncidentReport.reference).where(
                    IncidentReport.channel_metadata["message_id"].astext
                    == mensagem.message_id
                )
            )
            anterior = ja_existe.scalar_one_or_none()
            if anterior is not None:
                resultados.append({
                    "estado": "duplicado_ignorado",
                    "remetente": mensagem.remetente_email,
                    "assunto": mensagem.assunto,
                    "detalhe": f"Já registada como {anterior}.",
                })
                continue

        # O assunto e o corpo entram como estão. A plataforma não classifica por
        # palavras-chave: uma categoria inferida do assunto seria apresentada com
        # a mesma confiança de uma afirmada, e o §4 proíbe-o.
        descricao = mensagem.corpo or "(mensagem sem corpo legível)"
        if mensagem.truncada:
            descricao += (
                "\n\n[A mensagem original excedeu o limite e foi truncada. "
                "Os cabeçalhos completos estão preservados nos metadados.]"
            )
        if mensagem.anexos:
            descricao += (
                "\n\nAnexos indicados na mensagem, não recolhidos como "
                "evidência: " + ", ".join(mensagem.anexos)
            )

        relato, _codigo = await submit(
            session,
            ctx,
            reporter_name=mensagem.remetente_nome or mensagem.remetente_email,
            reporter_email=mensagem.remetente_email,
            subject=mensagem.assunto,
            description=descricao,
            channel=ReportChannel.EMAIL,
            channel_metadata={
                "message_id": mensagem.message_id,
                # Prova de origem, como o `raw_payload` de um evento. Inclui os
                # cabeçalhos de autenticação, que a plataforma **não**
                # interpreta — o campo `From` de um email é trivial de
                # falsificar, e quem tria é que decide se acredita.
                "cabecalhos": mensagem.cabecalhos,
                "anexos": mensagem.anexos,
                "truncada": mensagem.truncada,
            },
            # Não responde automaticamente ao remetente: ver a explicação em
            # `submit`. É a diferença entre confirmar uma submissão do portal e
            # responder a tudo o que cai numa caixa de correio.
            avisar=False,
        )
        resultados.append({
            "estado": "criada",
            "referencia": relato.reference,
            "remetente": mensagem.remetente_email,
            "assunto": mensagem.assunto,
        })

    criadas = sum(1 for r in resultados if r["estado"] == "criada")
    return {
        "lidas": len(mensagens),
        "criadas": criadas,
        "ignoradas": len(mensagens) - criadas,
        "resultados": resultados,
    }


# ================================================================ acompanhamento
async def track(
    session: AsyncSession, *, reference: str, codigo: str
) -> IncidentReport:
    """Devolve a comunicação se a referência **e** o código corresponderem.

    A mesma resposta para referência inexistente e para código errado: distinguir
    as duas permitiria enumerar referências válidas, que são sequenciais.
    """
    resultado = await session.execute(
        select(IncidentReport).where(IncidentReport.reference == reference.strip().upper())
    )
    relato = resultado.scalar_one_or_none()

    if relato is None or not constant_time_equals(
        relato.tracking_token_hash, _resumir(codigo)
    ):
        raise NotFoundError("Comunicação", reference)

    relato.tracking_views += 1
    await session.flush()
    return relato


def estado_publico(relato: IncidentReport) -> dict:
    """O que se diz a quem comunicou, e nada mais (§37).

    Deliberadamente não inclui o incidente ligado, a identidade de quem triou,
    nem a nota de triagem — que é análise interna e pode conter hipóteses.
    A frase por estado é escrita para ser lida por alguém de fora.
    """
    frases = {
        ReportStatus.RECEBIDA: (
            "Recebida. Está na fila para ser avaliada por um analista."
        ),
        ReportStatus.EM_TRIAGEM: (
            "Em avaliação por um analista."
        ),
        ReportStatus.ACEITE: (
            "Aceite. Foi integrada no tratamento de um incidente e está a ser "
            "acompanhada."
        ),
        ReportStatus.RECUSADA: (
            "Avaliada e encerrada sem tratamento como incidente. Se tiver "
            "informação nova, comunique-a de novo."
        ),
        ReportStatus.DUPLICADA: (
            "Descreve uma situação já comunicada anteriormente e está a ser "
            "acompanhada nessa comunicação."
        ),
    }
    return {
        "referencia": relato.reference,
        "estado": relato.status.value,
        "situacao": frases[relato.status],
        "recebida_em": relato.received_at,
        "avaliada_em": relato.triaged_at,
        "aviso_de_recepcao_enviado": relato.acknowledged_at is not None,
    }


# ====================================================================== triagem
async def get_report(session: AsyncSession, report_id: uuid.UUID) -> IncidentReport:
    relato = await session.get(IncidentReport, report_id)
    if relato is None:
        raise NotFoundError("Comunicação", report_id)
    return relato


def _exigir_transicao(relato: IncidentReport, destino: ReportStatus) -> None:
    """Valida o grafo de estados. Chamada no início de cada decisão."""
    permitidas = REPORT_TRANSITIONS.get(relato.status, frozenset())
    if destino not in permitidas:
        from app.core.errors import InvalidTransitionError

        raise InvalidTransitionError(
            relato.status.value, destino.value, [e.value for e in permitidas]
        )


def _aplicar_estado(
    relato: IncidentReport, destino: ReportStatus, *, analista: User, nota: str = ""
) -> ReportStatus:
    """Passagem única por onde toda a mudança de estado tem de ir.

    Existe para a regra não viver dentro de cada decisão. `_exigir_transicao`
    valida o grafo; aqui valida-se o que o grafo não sabe dizer — que
    `REPORT_STATES_REQUIRING_INCIDENT` exige uma ligação a existir de facto. A
    verificação corre **depois** de quem chama ter ligado o incidente, e é por
    isso que atribuir o estado também acontece aqui: separar as duas coisas
    deixaria uma porta futura a marcar o estado sem passar pela verificação, que
    é exactamente como esta regra se perdeu nos alertas (defeito 54).

    Devolve o estado anterior, para o registo de auditoria.
    """
    if destino in REPORT_STATES_REQUIRING_INCIDENT and not relato.incidents:
        raise ValidationError(
            f"Uma comunicação só fica {destino.value} estando ligada a pelo menos "
            "um incidente. Sem ligação, saía da fila sem aparecer em incidente "
            "nenhum e o trabalho desaparecia sem deixar rasto.",
            code="ESTADO_EXIGE_INCIDENTE",
        )

    anterior = relato.status
    relato.status = destino
    relato.triaged_by_id = analista.id
    if destino is not ReportStatus.EM_TRIAGEM:
        relato.triaged_at = datetime.now(UTC)
    if nota:
        relato.triage_note = nota
    return anterior


async def _recarregar(session: AsyncSession, relato: IncidentReport) -> IncidentReport:
    """Relê a comunicação depois de a alterar.

    `triaged_by`, `duplicate_of` e `incidents` são carregados com a consulta
    (`lazy="selectin"`), pelo que alterar a chave estrangeira **não** actualiza o
    objecto em memória: a resposta devolvia `triaged_by_email: null` logo a
    seguir a atribuir a avaliação, e a interface mostraria a comunicação como não
    avaliada a quem a acabara de assumir. É o defeito 11, noutra porta.

    O refresh é total e não limitado às relações: o flush emite o UPDATE, que
    dispara o `onupdate` de `updated_at` no servidor e deixa essa coluna
    expirada. Lê-la mais tarde, já durante a serialização, seria um acesso à base
    de dados fora do contexto assíncrono — `MissingGreenlet`.
    """
    await session.flush()
    await session.refresh(relato)
    return relato


async def comecar_triagem(
    session: AsyncSession, ctx: AuditContext, *, relato: IncidentReport, analista: User
) -> IncidentReport:
    """Marca a comunicação como em avaliação, para não ser triada duas vezes."""
    _exigir_transicao(relato, ReportStatus.EM_TRIAGEM)
    anterior = _aplicar_estado(relato, ReportStatus.EM_TRIAGEM, analista=analista)
    await session.flush()

    await audit.record(
        session,
        ctx,
        action="TRIAR_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=f"Comunicação {relato.reference} em avaliação.",
        old_value={"estado": anterior.value},
        new_value={"estado": relato.status.value},
        changed_fields=["status"],
    )
    return await _recarregar(session, relato)


async def aceitar(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    relato: IncidentReport,
    analista: User,
    nota: str,
    incident_id: uuid.UUID | None = None,
    criar_incidente: bool = False,
    categoria: IncidentCategory | None = None,
    severidade: Severity | None = None,
) -> tuple[IncidentReport, Incident]:
    """Aceita a comunicação, ligando-a a um incidente — novo ou existente.

    Exige uma das duas: ligar a um incidente que já existe (várias comunicações
    sobre a mesma campanha) ou criar um a partir dela. Não há terceira via,
    porque `ACEITE` sem incidente é um estado que mente.

    A categoria e a severidade do incidente são as que o **analista** decide. Se
    não as indicar, herdam o que o comunicante afirmou — mas o incidente passa a
    registá-las como avaliação da plataforma, e é por isso que a comunicação
    conserva os seus `claimed_*` intactos para comparação.
    """
    _exigir_transicao(relato, ReportStatus.ACEITE)

    if not nota.strip():
        raise ValidationError(
            "Aceitar uma comunicação exige uma nota: é o que explica a quem vier "
            "depois porque é que isto foi considerado relevante.",
            code="NOTA_OBRIGATORIA",
        )

    if incident_id is None and not criar_incidente:
        raise ValidationError(
            "Aceitar exige ligar a um incidente existente ou criar um novo. "
            "Marcar aceite sem incidente deixaria a comunicação fora da fila e "
            "fora de qualquer incidente.",
            code="ACEITAR_EXIGE_INCIDENTE",
        )

    if incident_id is not None:
        incidente = await incident_service.get_incident(session, incident_id)
    else:
        incidente = await incident_service.create_incident(
            session,
            ctx,
            title=relato.subject,
            description=(
                f"Incidente aberto a partir da comunicação {relato.reference}, "
                f"recebida por {relato.channel.value} de {relato.reporter_email}"
                + (f" ({relato.reporter_organisation})" if relato.reporter_organisation else "")
                + f".\n\nRelato original:\n{relato.description}"
                + (
                    f"\n\nIndicadores indicados por quem comunicou (não verificados):"
                    f"\n{relato.reported_indicators}"
                    if relato.reported_indicators.strip()
                    else ""
                )
            ),
            category=categoria or relato.claimed_category or IncidentCategory.OUTRO,
            severity=severidade or relato.claimed_severity or Severity.MEDIA,
            origin=IncidentOrigin.COMUNICACAO_EXTERNA,
            source_kind=SourceKind.MANUAL,
            source_detail=f"Comunicação {relato.reference} ({relato.channel.value})",
            detected_at=relato.received_at,
        )

    if incidente not in relato.incidents:
        relato.incidents.append(incidente)

    # Depois de ligar, nunca antes: o helper verifica que a ligação existe.
    anterior = _aplicar_estado(
        relato, ReportStatus.ACEITE, analista=analista, nota=nota.strip()
    )
    await session.flush()

    await audit.record(
        session,
        ctx,
        action="ACEITAR_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=(
            f"Comunicação {relato.reference} aceite e ligada ao incidente "
            f"{incidente.reference}"
            + (" (criado a partir dela)" if criar_incidente and incident_id is None else "")
            + f". {nota.strip()}"
        ),
        old_value={"estado": anterior.value},
        new_value={"estado": relato.status.value, "incidente": incidente.reference},
        changed_fields=["status", "incidents"],
    )
    await _recarregar(session, relato)
    return relato, incidente


async def recusar(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    relato: IncidentReport,
    analista: User,
    nota: str,
) -> IncidentReport:
    """Recusa a comunicação. A nota é obrigatória.

    Uma comunicação recusada sem motivo é indistinguível de uma esquecida — e
    quem comunicou vai ler o estado, pelo que a decisão tem de ter razão escrita.
    """
    _exigir_transicao(relato, ReportStatus.RECUSADA)

    if not nota.strip():
        raise ValidationError(
            "Recusar uma comunicação exige uma justificação escrita.",
            code="NOTA_OBRIGATORIA",
        )

    anterior = _aplicar_estado(
        relato, ReportStatus.RECUSADA, analista=analista, nota=nota.strip()
    )
    await session.flush()

    await audit.record(
        session,
        ctx,
        action="RECUSAR_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=f"Comunicação {relato.reference} recusada. {nota.strip()}",
        old_value={"estado": anterior.value},
        new_value={"estado": relato.status.value},
        changed_fields=["status"],
    )
    return await _recarregar(session, relato)


async def marcar_duplicada(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    relato: IncidentReport,
    analista: User,
    original_id: uuid.UUID,
    nota: str = "",
) -> IncidentReport:
    """Marca a comunicação como duplicada de outra.

    Não apaga nem funde: a comunicação continua a existir com o seu histórico,
    e quem a fez continua a poder acompanhá-la — vê que está a ser tratada na
    outra. É a mesma escolha que se fez nas relações entre incidentes, contra a
    fusão destrutiva do RTIR.
    """
    _exigir_transicao(relato, ReportStatus.DUPLICADA)

    if original_id == relato.id:
        raise ValidationError(
            "Uma comunicação não pode ser duplicada de si mesma.",
            code="DUPLICADO_DE_SI",
        )

    original = await get_report(session, original_id)
    if original.status is ReportStatus.DUPLICADA:
        raise ValidationError(
            f"A comunicação {original.reference} é ela própria um duplicado. "
            "Indique a original, para não criar uma cadeia que não leva a nada.",
            code="DUPLICADO_DE_DUPLICADO",
        )

    relato.duplicate_of_id = original.id
    anterior = _aplicar_estado(
        relato, ReportStatus.DUPLICADA, analista=analista, nota=nota.strip()
    )
    await session.flush()

    await audit.record(
        session,
        ctx,
        action="DUPLICAR_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=(
            f"Comunicação {relato.reference} marcada como duplicada de "
            f"{original.reference}." + (f" {nota.strip()}" if nota.strip() else "")
        ),
        old_value={"estado": anterior.value},
        new_value={"estado": relato.status.value, "duplicada_de": original.reference},
        changed_fields=["status", "duplicate_of_id"],
    )
    return await _recarregar(session, relato)


async def ligar_incidente(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    relato: IncidentReport,
    incident_id: uuid.UUID,
) -> IncidentReport:
    """Liga uma comunicação já aceite a **outro** incidente.

    Existe porque a relação é muitos-para-muitos: uma comunicação sobre um
    incidente que atinge vários sistemas pode pertencer a mais do que um.
    """
    incidente = await incident_service.get_incident(session, incident_id)

    if incidente in relato.incidents:
        raise ValidationError(
            f"A comunicação {relato.reference} já está ligada a "
            f"{incidente.reference}.",
            code="JA_LIGADA",
        )

    relato.incidents.append(incidente)
    await session.flush()

    await audit.record(
        session,
        ctx,
        action="LIGAR_COMUNICACAO",
        resource_type="comunicacao",
        resource_id=relato.id,
        resource_reference=relato.reference,
        description=(
            f"Comunicação {relato.reference} ligada também ao incidente "
            f"{incidente.reference}."
        ),
        new_value={"incidente": incidente.reference},
        changed_fields=["incidents"],
    )
    return await _recarregar(session, relato)
