"""Motor de execução de playbooks (§14).

Um playbook é uma sequência declarativa de passos. O motor executa-os por
ordem, registando o resultado de cada um.

A decisão central: **um passo que exija aprovação suspende a execução.** O
motor não espera activamente nem executa a acção em segundo plano; muda o
estado da execução para `AGUARDA_APROVACAO` e termina. Quando a aprovação for
concedida, `resume_execution` executa a acção aprovada e retoma a partir do
passo seguinte; se for recusada, `cancel_after_rejection` termina a execução.

Isto é deliberado. A alternativa — manter a execução viva à espera de um
humano — torna a automação dependente de um processo que pode morrer, e obriga
a decidir o que fazer se ninguém responder. Suspender e retomar transforma a
espera num estado persistido, visível no painel e recuperável após reinício.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    ActionKind,
    ActionStatus,
    AuditOutcome,
    IncidentStatus,
    IocType,
    PlaybookExecutionStatus,
    PlaybookStepType,
    Priority,
    Severity,
    TaskStatus,
)
from app.core.errors import (
    AuthorizationError,
    ConflictError,
    NotFoundError,
    SheisaError,
    ValidationError,
)
from app.core.permissions import Permission
from app.core.references import ReferenceKind, next_reference
from app.models.catalog import Ioc
from app.models.identity import Role, User
from app.models.incident import Incident
from app.models.investigation import Comment, Observation, Task
from app.models.response import (
    Action,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
    PlaybookStepExecution,
)
from app.services import action_service

logger = logging.getLogger("sheisa.playbooks")


async def suggest_playbooks(
    session: AsyncSession, incident: Incident
) -> list[tuple[Playbook, str]]:
    """Playbooks aplicáveis a um incidente, com a razão da sugestão.

    A sugestão é sempre acompanhada do motivo — o analista precisa de saber
    porque é que aquele procedimento lhe está a ser proposto.
    """
    result = await session.execute(
        select(Playbook)
        .where(Playbook.is_enabled.is_(True))
        .options(selectinload(Playbook.steps))
    )

    observations = await session.execute(
        select(Ioc.ioc_type)
        .join(Observation, Observation.ioc_id == Ioc.id)
        .where(Observation.incident_id == incident.id)
        .distinct()
    )
    present_types = {t.value for (t,) in observations.all()}

    suggestions: list[tuple[Playbook, str]] = []
    for playbook in result.scalars().unique():
        reasons: list[str] = []

        if playbook.trigger_category is not None:
            if playbook.trigger_category != incident.category:
                continue
            reasons.append(f"categoria {incident.category.value}")

        if incident.severity.rank < playbook.trigger_min_severity.rank:
            continue
        reasons.append(f"severidade {incident.severity.value}")

        required_iocs = playbook.trigger_conditions.get("requires_ioc_types") or []
        if required_iocs:
            if not set(required_iocs).intersection(present_types):
                continue
            reasons.append(
                "indicadores presentes: "
                + ", ".join(sorted(set(required_iocs) & present_types))
            )

        suggestions.append((playbook, "Aplicável por " + "; ".join(reasons) + "."))

    return suggestions


async def start_execution(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    playbook: Playbook,
    incident: Incident,
    triggered_automatically: bool = False,
) -> PlaybookExecution:
    """Inicia uma execução e corre os passos até ao fim ou até uma aprovação."""
    if not playbook.is_enabled:
        raise ConflictError(f"O playbook '{playbook.name}' está desactivado.")

    reference = await next_reference(session, ReferenceKind.PLAYBOOK_EXECUTION)
    execution = PlaybookExecution(
        reference=reference,
        playbook_id=playbook.id,
        incident_id=incident.id,
        status=PlaybookExecutionStatus.EM_EXECUCAO,
        # A versão é copiada: alterar o playbook depois não reescreve o que
        # foi de facto executado.
        playbook_version=playbook.version,
        started_at=datetime.now(UTC),
        triggered_by_id=ctx.actor_id,
        triggered_automatically=triggered_automatically,
        context={"incidente": incident.reference, "playbook": playbook.name},
    )
    session.add(execution)
    await session.flush()

    playbook.execution_count += 1
    playbook.last_executed_at = datetime.now(UTC)

    await audit.record(
        session, ctx,
        action="INICIAR_PLAYBOOK", resource_type="execucao_playbook",
        resource_id=execution.id, resource_reference=execution.reference,
        description=(
            f"Playbook '{playbook.name}' iniciado sobre {incident.reference} "
            f"({'automático' if triggered_automatically else 'manual'})."
        ),
    )

    return await _run_from(
        session, ctx, execution, playbook, incident, start_index=0, outcomes=[]
    )


async def resume_execution(
    session: AsyncSession, ctx: AuditContext, *, execution: PlaybookExecution
) -> PlaybookExecution:
    """Retoma uma execução suspensa à espera de aprovação."""
    if execution.status != PlaybookExecutionStatus.AGUARDA_APROVACAO:
        raise ConflictError(
            f"A execução {execution.reference} não está suspensa "
            f"(estado: {execution.status.value})."
        )

    playbook = await session.get(Playbook, execution.playbook_id)
    incident = await session.get(Incident, execution.incident_id)
    if playbook is None or incident is None:
        raise NotFoundError("Playbook ou incidente da execução")

    # Retomamos a partir do passo seguinte ao último concluído.
    completed = [
        s.ordering for s in execution.step_executions
        if s.status == TaskStatus.CONCLUIDA
    ]
    start_index = max(completed) if completed else 0

    execution.status = PlaybookExecutionStatus.EM_EXECUCAO
    await audit.record(
        session, ctx,
        action="RETOMAR_PLAYBOOK", resource_type="execucao_playbook",
        resource_id=execution.id, resource_reference=execution.reference,
        description=f"Execução {execution.reference} retomada após aprovação.",
    )

    # O resumo continua o que já estava escrito. Recomeçá-lo apagava do registo
    # final todos os passos que correram antes da pausa.
    outcomes = execution.result_summary.splitlines()

    paused = next(
        (s for s in execution.step_executions if s.ordering == start_index), None
    )
    if paused is not None and paused.action_id is not None:
        if await _execute_approved_action(session, ctx, execution, paused, outcomes):
            return execution

    return await _run_from(
        session, ctx, execution, playbook, incident, start_index, outcomes
    )


async def _execute_approved_action(
    session: AsyncSession,
    ctx: AuditContext,
    execution: PlaybookExecution,
    paused: PlaybookStepExecution,
    outcomes: list[str],
) -> bool:
    """Executa a acção que o passo suspenso deixou à espera de aprovação.

    Devolve `True` se a execução do playbook tiver de parar aqui.

    A aprovação autoriza; não executa. Sem isto o playbook retomava com a acção
    parada em APROVADA e seguia como se ela tivesse corrido: no playbook de
    bloqueio de IP, o passo seguinte escrevia "Bloqueio aplicado" num incidente
    cujo endereço nunca foi bloqueado.

    Quem executa é o playbook, iniciado por quem tinha `playbooks:execute`; o
    controlo humano é a aprovação que acabou de ser dada. É o mesmo critério pelo
    qual o motor já executa de imediato as acções de risco baixo.
    """
    action = await session.get(Action, paused.action_id)
    if action is None or action.status != ActionStatus.APROVADA:
        raise ConflictError(
            f"A execução {execution.reference} só pode ser retomada depois de "
            f"aprovada a acção do passo {paused.ordering}."
        )

    failure: str | None = None
    try:
        await action_service.execute_action(session, ctx, action=action)
    except SheisaError as exc:
        failure = action.error or exc.message
    else:
        if action.status != ActionStatus.EXECUTADA:
            failure = action.error or f"a acção terminou em {action.status.value}"

    if failure is None:
        resumo = (
            f"Autorização {action.reference} concedida."
            if action.action_kind in action_service.NO_INTEGRATION_REQUIRED
            else f"Acção {action.reference} executada após aprovação."
        )
        paused.output = {**paused.output, "resumo": resumo, "resultado": action.result}
        outcomes.append(f"{paused.ordering}. {paused.step_name}: {resumo}")
        return False

    paused.status = TaskStatus.CANCELADA
    paused.error = f"Acção {action.reference} aprovada mas não executada: {failure}"[:2000]
    outcomes.append(f"{paused.ordering}. {paused.step_name}: FALHOU — {failure}")
    await audit.record(
        session, ctx,
        action="PASSO_PLAYBOOK", resource_type="execucao_playbook",
        resource_id=execution.id, resource_reference=execution.reference,
        description=f"Passo '{paused.step_name}' falhou: {failure}",
        outcome=AuditOutcome.FALHA,
        failure_reason=failure[:500],
    )

    step = await session.get(PlaybookStep, paused.step_id) if paused.step_id else None
    if step is not None and not step.abort_on_failure:
        return False

    execution.status = PlaybookExecutionStatus.FALHADA
    execution.error = f"Interrompido no passo '{paused.step_name}': {failure}"
    execution.finished_at = datetime.now(UTC)
    execution.result_summary = "\n".join(outcomes)
    await session.flush()
    return True


async def cancel_after_rejection(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    execution: PlaybookExecution,
    action: Action,
    reason: str | None = None,
) -> PlaybookExecution:
    """Termina a execução cuja aprovação foi recusada ou caducou.

    Sem isto a execução ficava em AGUARDA_APROVACAO para sempre: o painel mostrava
    um playbook à espera de uma decisão que já tinha sido tomada, e a fila de
    quem aprova não tinha nada que o pudesse desbloquear.

    CANCELADA e não FALHADA: nada falhou. Quem tinha autoridade para decidir
    decidiu que os passos seguintes não deviam correr.
    """
    if execution.status != PlaybookExecutionStatus.AGUARDA_APROVACAO:
        raise ConflictError(
            f"A execução {execution.reference} não está suspensa "
            f"(estado: {execution.status.value})."
        )

    causa = reason or f"a acção {action.reference} foi rejeitada"
    motivo = (
        f"{causa[0].upper()}{causa[1:]} ('{action.title}'); os passos seguintes não "
        "foram executados."
    )
    execution.status = PlaybookExecutionStatus.CANCELADA
    execution.error = motivo
    execution.finished_at = datetime.now(UTC)
    execution.result_summary = "\n".join([*execution.result_summary.splitlines(), motivo])

    session.add(
        Comment(
            incident_id=execution.incident_id,
            body=f"Execução {execution.reference} interrompida. {motivo}",
            is_system=True,
        )
    )
    await audit.record(
        session, ctx,
        action="INTERROMPER_PLAYBOOK", resource_type="execucao_playbook",
        resource_id=execution.id, resource_reference=execution.reference,
        description=f"Execução {execution.reference} interrompida. {motivo}",
        old_value={"estado": PlaybookExecutionStatus.AGUARDA_APROVACAO.value},
        new_value={"estado": PlaybookExecutionStatus.CANCELADA.value},
        changed_fields=["status"],
    )
    await session.flush()
    return execution


async def _run_from(
    session: AsyncSession,
    ctx: AuditContext,
    execution: PlaybookExecution,
    playbook: Playbook,
    incident: Incident,
    start_index: int,
    outcomes: list[str],
) -> PlaybookExecution:
    """Corre os passos a partir de `start_index` (ordering baseado em 1).

    `outcomes` traz as linhas de resumo já escritas; os passos acrescentam-lhe as suas.
    """
    steps = sorted(
        [s for s in playbook.steps if s.is_enabled], key=lambda s: s.ordering
    )

    for step in steps:
        if step.ordering <= start_index:
            continue

        record = PlaybookStepExecution(
            execution_id=execution.id,
            step_id=step.id,
            ordering=step.ordering,
            # Nome e tipo copiados: se o passo for editado ou removido depois,
            # o registo do que correu continua legível.
            step_name=step.name,
            step_type=step.step_type,
            status=TaskStatus.EM_CURSO,
            started_at=datetime.now(UTC),
        )
        session.add(record)
        await session.flush()

        try:
            result, pause = await _execute_step(
                session, ctx, step, execution, incident, record
            )
            record.output = result
            record.status = TaskStatus.CONCLUIDA
            record.finished_at = datetime.now(UTC)
            outcomes.append(f"{step.ordering}. {step.name}: {result.get('resumo', 'ok')}")

            if pause:
                execution.status = PlaybookExecutionStatus.AGUARDA_APROVACAO
                execution.result_summary = "\n".join(outcomes)
                session.add(
                    Comment(
                        incident_id=incident.id,
                        body=(
                            f"Execução {execution.reference} suspensa no passo "
                            f"{step.ordering} ('{step.name}'): aguarda aprovação humana."
                        ),
                        is_system=True,
                    )
                )
                await session.flush()
                return execution

        except Exception as exc:
            logger.exception("Falha no passo %s do playbook", step.name)
            record.status = TaskStatus.CANCELADA
            record.error = str(exc)[:2000]
            record.finished_at = datetime.now(UTC)
            outcomes.append(f"{step.ordering}. {step.name}: FALHOU — {exc}")

            await audit.record(
                session, ctx,
                action="PASSO_PLAYBOOK", resource_type="execucao_playbook",
                resource_id=execution.id, resource_reference=execution.reference,
                description=f"Passo '{step.name}' falhou: {exc}",
                outcome=AuditOutcome.FALHA,
                failure_reason=str(exc)[:500],
            )

            if step.abort_on_failure:
                execution.status = PlaybookExecutionStatus.FALHADA
                execution.error = f"Interrompido no passo '{step.name}': {exc}"
                execution.finished_at = datetime.now(UTC)
                execution.result_summary = "\n".join(outcomes)
                await session.flush()
                return execution

    execution.status = PlaybookExecutionStatus.CONCLUIDA
    execution.finished_at = datetime.now(UTC)
    playbook.success_count += 1

    # Transição final declarada pelo playbook. Passa pela transição real (ver
    # `_change_incident_status`) e, se não puder ser aplicada, fica dito no
    # resumo — antes era saltada em silêncio. O resumo só é gravado depois disto:
    # gravado antes, nem a transição bem-sucedida lá ficava.
    if playbook.closing_status:
        try:
            target = IncidentStatus(playbook.closing_status)
        except ValueError:
            outcomes.append(
                f"Estado final {playbook.closing_status} não aplicado: não é um "
                "estado de incidente."
            )
        else:
            try:
                await _change_incident_status(
                    session, ctx, incident, target,
                    note=f"Estado final declarado pelo playbook {execution.reference}.",
                )
                outcomes.append(f"Incidente transitado para {target.value}.")
            except SheisaError as exc:
                outcomes.append(f"Estado final {target.value} não aplicado: {exc.message}")
    execution.result_summary = "\n".join(outcomes)

    session.add(
        Comment(
            incident_id=incident.id,
            body=(
                f"Execução {execution.reference} do playbook '{playbook.name}' "
                f"concluída.\n" + "\n".join(outcomes)
            ),
            is_system=True,
        )
    )
    await audit.record(
        session, ctx,
        action="CONCLUIR_PLAYBOOK", resource_type="execucao_playbook",
        resource_id=execution.id, resource_reference=execution.reference,
        description=f"Execução {execution.reference} concluída.",
        new_value={"resumo": execution.result_summary},
    )
    await session.flush()
    return execution


async def _execute_step(
    session: AsyncSession,
    ctx: AuditContext,
    step: PlaybookStep,
    execution: PlaybookExecution,
    incident: Incident,
    record: PlaybookStepExecution,
) -> tuple[dict, bool]:
    """Executa um passo. Devolve (resultado, suspender_execucao)."""
    kind = step.step_type

    # ------------------------------------------------- enriquecimento de IOCs
    if kind == PlaybookStepType.ENRIQUECER_IOC:
        wanted = step.parameters.get("ioc_types") or []
        stmt = (
            select(Ioc)
            .join(Observation, Observation.ioc_id == Ioc.id)
            .where(Observation.incident_id == incident.id)
            .distinct()
        )
        if wanted:
            stmt = stmt.where(Ioc.ioc_type.in_([IocType(t) for t in wanted]))
        iocs = list((await session.execute(stmt)).scalars())

        detalhes = [
            {
                "tipo": i.ioc_type.value,
                "valor": i.value,
                "reputacao": i.reputation.value,
                "avistamentos": i.sighting_count,
                "primeira_observacao": i.first_seen.isoformat() if i.first_seen else None,
                "ultima_observacao": i.last_seen.isoformat() if i.last_seen else None,
            }
            for i in iocs
        ]
        return (
            {
                "resumo": f"{len(iocs)} indicador(es) enriquecido(s) com dados internos.",
                "indicadores": detalhes,
            },
            False,
        )

    # ------------------------------------------------------ consulta externa
    if kind == PlaybookStepType.CONSULTAR_REPUTACAO:
        # Nenhuma fonte externa de threat intelligence está configurada neste
        # ambiente. Dizemo-lo explicitamente em vez de inventar um veredicto —
        # uma reputação falsa levaria a decisões de bloqueio erradas (§4).
        return (
            {
                "resumo": (
                    "Nenhuma fonte externa de reputação configurada; passo "
                    "registado sem consulta."
                ),
                "consultado": False,
                "motivo": "sem integração de threat intelligence activa",
            },
            False,
        )

    # ---------------------------------------------------- activos envolvidos
    if kind == PlaybookStepType.IDENTIFICAR_ACTIVOS:
        await session.refresh(incident, ["assets"])
        activos = [
            {
                "identificador": a.identifier,
                "nome": a.name,
                "criticidade": a.criticality.value,
                "ip": a.ip_address,
            }
            for a in incident.assets
        ]
        return (
            {
                "resumo": f"{len(activos)} activo(s) afectado(s) identificado(s).",
                "activos": activos,
            },
            False,
        )

    # ----------------------------------------------------------- criar tarefa
    if kind == PlaybookStepType.CRIAR_TAREFA:
        highest = await session.execute(
            select(Task.ordering).where(Task.incident_id == incident.id)
            .order_by(Task.ordering.desc()).limit(1)
        )
        task = Task(
            incident_id=incident.id,
            title=step.parameters.get("titulo", step.name)[:250],
            description=step.parameters.get("descricao", ""),
            status=TaskStatus.PENDENTE,
            priority=Priority(step.parameters.get("prioridade", Priority.P3.value)),
            ordering=(highest.scalar_one_or_none() or 0) + 1,
            assignee_id=incident.assignee_id,
            playbook_execution_id=execution.id,
            created_by_id=ctx.actor_id,
        )
        session.add(task)
        await session.flush()
        return ({"resumo": f"Tarefa '{task.title}' criada.", "tarefa_id": str(task.id)}, False)

    # ------------------------------------------------- solicitar aprovação
    if kind == PlaybookStepType.SOLICITAR_APROVACAO:
        # Cria uma porta de autorização real. Suspender a execução sem criar
        # nada aprovável deixaria o playbook num estado do qual nunca poderia
        # ser retomado.
        motivo = step.parameters.get("motivo", "")
        gate = await action_service.propose_action(
            session, ctx,
            incident=incident,
            action_kind=ActionKind.AUTORIZAR_PROSSEGUIMENTO,
            title=step.name,
            rationale=(
                f"Autorização necessária para prosseguir com a execução "
                f"{execution.reference}, passo {step.ordering}."
                + (f" Motivo: {motivo}" if motivo else "")
            ),
            target={"execucao": execution.reference, "passo": step.ordering},
            parameters={"motivo": motivo},
            risk_level=step.risk_level,
            proposed_by_engine=True,
            playbook_execution_id=execution.id,
        )
        record.action_id = gate.id
        return (
            {
                "resumo": (
                    f"Autorização {gate.reference} solicitada; execução suspensa "
                    "até haver decisão."
                ),
                "accao_referencia": gate.reference,
                "motivo": motivo,
            },
            True,
        )

    # ----------------------------------------------------- executar acção
    if kind == PlaybookStepType.EXECUTAR_ACCAO:
        if step.action_kind is None:
            raise ValidationError(
                f"O passo '{step.name}' é do tipo EXECUTAR_ACCAO mas não declara "
                "que acção executar."
            )

        target = await _build_target(session, incident, step)
        action = await action_service.propose_action(
            session, ctx,
            incident=incident,
            action_kind=step.action_kind,
            title=step.name,
            rationale=(
                f"Proposta pelo playbook '{execution.reference}', passo "
                f"{step.ordering} ('{step.name}')."
            ),
            target=target,
            parameters=step.parameters,
            risk_level=step.risk_level,
            proposed_by_engine=True,
            playbook_execution_id=execution.id,
        )
        record.action_id = action.id

        if action.status == ActionStatus.AGUARDA_APROVACAO:
            return (
                {
                    "resumo": (
                        f"Acção {action.reference} proposta; aguarda aprovação "
                        f"({action.risk_level.value})."
                    ),
                    "accao_id": str(action.id),
                    "accao_referencia": action.reference,
                },
                True,
            )

        # Risco baixo: executa de imediato, mas o resultado continua a ser real.
        await action_service.execute_action(session, ctx, action=action)
        return (
            {
                "resumo": f"Acção {action.reference}: {action.status.value}.",
                "accao_referencia": action.reference,
                "resultado": action.result,
            },
            False,
        )

    # --------------------------------------------------------- estado / notas
    if kind == PlaybookStepType.ALTERAR_ESTADO:
        target_status = IncidentStatus(step.parameters["estado"])
        previous = incident.status
        await _change_incident_status(
            session, ctx, incident, target_status,
            note=f"Pelo playbook {execution.reference}, passo {step.ordering}.",
            resolution_summary=step.parameters.get("resumo"),
            false_positive_reason=step.parameters.get("motivo"),
        )
        return (
            {"resumo": f"Estado alterado de {previous.value} para {target_status.value}."},
            False,
        )

    if kind == PlaybookStepType.ATRIBUIR_RESPONSAVEL:
        assignee = step.parameters.get("responsavel_id")
        if assignee:
            incident.assignee_id = uuid.UUID(assignee)
        return ({"resumo": "Responsável atribuído."}, False)

    if kind == PlaybookStepType.REGISTAR_NOTA:
        texto = step.parameters.get("texto", step.name)
        session.add(
            Comment(incident_id=incident.id, body=texto, is_system=True)
        )
        return ({"resumo": "Nota registada no incidente."}, False)

    if kind == PlaybookStepType.NOTIFICAR:
        from app.core.enums import NotificationKind
        from app.models.system import Notification

        if incident.assignee_id is not None:
            session.add(
                Notification(
                    user_id=incident.assignee_id,
                    kind=NotificationKind.ACCAO_EXECUTADA,
                    severity=Severity.MEDIA,
                    title=f"Playbook em curso sobre {incident.reference}",
                    body=step.parameters.get("mensagem", step.name),
                    resource_type="incidente",
                    resource_id=incident.id,
                    resource_reference=incident.reference,
                )
            )
            return ({"resumo": "Responsável notificado."}, False)
        return (
            {"resumo": "Sem responsável atribuído; notificação não enviada."},
            False,
        )

    raise ValidationError(f"Tipo de passo não suportado: {kind}.")


async def _change_incident_status(
    session: AsyncSession,
    ctx: AuditContext,
    incident: Incident,
    target: IncidentStatus,
    *,
    note: str,
    resolution_summary: str | None = None,
    false_positive_reason: str | None = None,
) -> None:
    """Muda o estado do incidente pela transição real, como se fosse à mão.

    O motor fazia `incident.status = ...` depois de consultar o ciclo de vida, e
    saltava tudo o resto que a transição garante: os marcos temporais de que
    dependem as métricas de resposta (`contained_at`, `resolved_at`...), o resumo
    obrigatório para RESOLVIDO, o motivo e a propagação para FALSO_POSITIVO, e a
    entrada ALTERAR_ESTADO na auditoria, que é o que a linha temporal mostra.
    Os parâmetros `resumo` e `motivo` de um passo servem estes dois casos.
    """
    from app.services import incident_service

    # Encerrar retira o incidente das filas e fecha o registo: exige
    # `incidents:close`, tal como a rota de transição. O motor chama o serviço
    # directamente, pelo que a verificação da rota não o alcança — é aqui que a
    # separação entre quem conduz e quem dá por terminado passa a valer também
    # nos playbooks. Como `AuthorizationError` é um `SheisaError`, um refuso fica
    # registado como falha honesta do passo (ou nota no resumo do estado final),
    # em vez de encerrar o incidente à revelia da permissão.
    if target is IncidentStatus.ENCERRADO and not await _actor_tem_permissao(
        session, ctx, Permission.INCIDENTS_CLOSE
    ):
        raise AuthorizationError(
            "O playbook não pode encerrar o incidente: quem o corre não tem a "
            "permissão para encerrar.",
            required=Permission.INCIDENTS_CLOSE.value,
        )

    await incident_service.transition(
        session, ctx,
        incident=incident,
        new_status=target,
        note=note,
        resolution_summary=resolution_summary,
        false_positive_reason=false_positive_reason,
    )


async def _actor_tem_permissao(
    session: AsyncSession, ctx: AuditContext, permissao: Permission
) -> bool:
    """Diz se o utilizador que corre o playbook detém a permissão dada.

    Sem actor identificado não se pode afirmar autoridade nenhuma — devolve
    falso, para que uma execução sem dono nunca encerre um incidente.
    """
    if ctx.actor_id is None:
        return False
    user = (
        await session.execute(
            select(User)
            .where(User.id == ctx.actor_id)
            .options(selectinload(User.role).selectinload(Role.permissions))
        )
    ).scalar_one_or_none()
    if user is None or user.role is None:
        return False
    return any(p.code == permissao.value for p in user.role.permissions)


async def _build_target(
    session: AsyncSession, incident: Incident, step: PlaybookStep
) -> dict:
    """Determina o alvo da acção a partir do contexto do incidente.

    Um passo pode declarar o alvo explicitamente; caso contrário, é deduzido
    das observações — tipicamente o indicador de origem mais recente.
    """
    if explicit := step.parameters.get("alvo"):
        return explicit

    kind = step.action_kind
    if kind in (ActionKind.BLOQUEAR_IP, ActionKind.DESBLOQUEAR_IP):
        from app.core.enums import ObservationRole

        result = await session.execute(
            select(Ioc.value)
            .join(Observation, Observation.ioc_id == Ioc.id)
            .where(
                Observation.incident_id == incident.id,
                Ioc.ioc_type == IocType.IP,
                Observation.role.in_([ObservationRole.ORIGEM, ObservationRole.DESTINO]),
            )
            .order_by(Observation.observed_at.desc())
            .limit(1)
        )
        if ip := result.scalar_one_or_none():
            return {"ip": ip}
        raise ValidationError(
            "Não foi possível determinar o endereço a bloquear: o incidente não "
            "tem nenhum indicador de IP observado."
        )

    if kind in (
        ActionKind.ISOLAR_ACTIVO,
        ActionKind.REMOVER_ISOLAMENTO,
        ActionKind.RECOLHER_ARTEFACTOS,
        ActionKind.EXECUTAR_VARRIMENTO,
    ):
        await session.refresh(incident, ["assets"])
        for asset in incident.assets:
            if asset.wazuh_agent_id:
                return {
                    "agent_id": asset.wazuh_agent_id,
                    "activo": asset.identifier,
                    "hostname": asset.hostname,
                }
        raise ValidationError(
            "Nenhum dos activos afectados tem agente Wazuh registado, pelo que "
            "a acção não pode ser executada sobre eles."
        )

    return {}
