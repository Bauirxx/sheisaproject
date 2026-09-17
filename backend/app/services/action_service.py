"""Acções de resposta e aprovações (§13).

Implementa `IA → RECOMENDAÇÃO → ANALISTA → APROVAÇÃO → EXECUÇÃO` com entidades
reais. Regras que o serviço faz cumprir:

* **Uma acção de risco moderado ou crítico não executa sem aprovação.** A
  verificação é feita aqui, no servidor, e não na interface.
* **Quem propõe não aprova.** Separação de funções: sem ela, a aprovação seria
  uma formalidade que o próprio autor cumpre.
* **Uma acção crítica exige justificação escrita.** Uma aprovação sem motivo
  registado não permite, mais tarde, perceber a decisão.
* **Nunca se reporta sucesso sem resposta do sistema alvo.** Se não existe
  conector, ou a integração não está activa, a execução falha de forma
  explícita (§4). Não há modo "simulado".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    ActionKind,
    ActionRiskLevel,
    ActionStatus,
    ApprovalDecision,
    AuditOutcome,
    IntegrationStatus,
    NotificationKind,
    Severity,
)
from app.core.errors import (
    ApprovalRequiredError,
    AuthorizationError,
    ConflictError,
    IntegrationNotAvailableError,
    NotFoundError,
    ValidationError,
)
from app.core.permissions import Permission
from app.core.references import ReferenceKind, next_reference
from app.integrations.registry import connectors_supporting, get_connector
from app.models.identity import User
from app.models.incident import Incident
from app.models.investigation import Comment
from app.models.response import Action, ActionApproval, PlaybookExecution
from app.models.system import Integration, Notification

#: Nível de risco por omissão de cada tipo de acção.
#:
#: A classificação reflecte o impacto operacional de errar: bloquear um IP de
#: produção ou isolar um servidor interrompe serviço, ao passo que recolher
#: artefactos é inócuo. Um administrador pode ajustar por playbook, mas nunca
#: para *baixo* do que aqui está — ver `resolve_risk_level`.
DEFAULT_RISK: dict[ActionKind, ActionRiskLevel] = {
    ActionKind.BLOQUEAR_IP: ActionRiskLevel.CRITICO,
    ActionKind.DESBLOQUEAR_IP: ActionRiskLevel.MODERADO,
    ActionKind.ISOLAR_ACTIVO: ActionRiskLevel.CRITICO,
    ActionKind.REMOVER_ISOLAMENTO: ActionRiskLevel.MODERADO,
    ActionKind.DESACTIVAR_UTILIZADOR: ActionRiskLevel.CRITICO,
    ActionKind.TERMINAR_SESSOES: ActionRiskLevel.MODERADO,
    ActionKind.EXECUTAR_VARRIMENTO: ActionRiskLevel.BAIXO,
    ActionKind.RECOLHER_ARTEFACTOS: ActionRiskLevel.BAIXO,
    ActionKind.NOTIFICAR_EQUIPA: ActionRiskLevel.BAIXO,
    ActionKind.AUTORIZAR_PROSSEGUIMENTO: ActionRiskLevel.CRITICO,
    ActionKind.ENRIQUECER_IOC: ActionRiskLevel.BAIXO,
    ActionKind.REGISTAR_NOTA: ActionRiskLevel.BAIXO,
}

#: Acções que podem ser desfeitas, e por que acção.
REVERSIBLE_BY: dict[ActionKind, ActionKind] = {
    ActionKind.BLOQUEAR_IP: ActionKind.DESBLOQUEAR_IP,
    ActionKind.ISOLAR_ACTIVO: ActionKind.REMOVER_ISOLAMENTO,
}

#: Prazo por omissão de um pedido de aprovação.
APPROVAL_TTL_HOURS = 24

#: Acções que não actuam sobre nenhum sistema externo e, por isso, não exigem
#: integração. A sua "execução" é a própria decisão humana.
NO_INTEGRATION_REQUIRED: frozenset[ActionKind] = frozenset({
    ActionKind.AUTORIZAR_PROSSEGUIMENTO,
    ActionKind.REGISTAR_NOTA,
})


def resolve_risk_level(
    action_kind: ActionKind, requested: ActionRiskLevel | None = None
) -> ActionRiskLevel:
    """Nível de risco efectivo.

    Um playbook pode *elevar* o risco de uma acção, mas nunca baixá-lo abaixo
    do valor por omissão: caso contrário, bastaria declarar `BAIXO` num
    playbook para contornar a exigência de aprovação.
    """
    baseline = DEFAULT_RISK.get(action_kind, ActionRiskLevel.MODERADO)
    if requested is None:
        return baseline
    order = [ActionRiskLevel.BAIXO, ActionRiskLevel.MODERADO, ActionRiskLevel.CRITICO]
    return order[max(order.index(baseline), order.index(requested))]


def required_permission_for(risk: ActionRiskLevel) -> str:
    return (
        Permission.ACTIONS_APPROVE_CRITICAL.value
        if risk == ActionRiskLevel.CRITICO
        else Permission.ACTIONS_APPROVE.value
    )


async def find_integration_for(
    session: AsyncSession, action_kind: ActionKind
) -> Integration | None:
    """Integração activa capaz de executar a acção."""
    connectors = connectors_supporting(action_kind)
    if not connectors:
        return None
    kinds = [c.kind for c in connectors]
    result = await session.execute(
        select(Integration).where(
            Integration.kind.in_(kinds),
            Integration.is_enabled.is_(True),
            Integration.status == IntegrationStatus.ACTIVA,
        ).limit(1)
    )
    return result.scalar_one_or_none()


async def propose_action(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incident: Incident,
    action_kind: ActionKind,
    title: str,
    rationale: str,
    target: dict,
    parameters: dict | None = None,
    risk_level: ActionRiskLevel | None = None,
    proposed_by_engine: bool = False,
    recommendation_id: uuid.UUID | None = None,
    playbook_execution_id: uuid.UUID | None = None,
) -> Action:
    """Propõe uma acção e, se necessário, abre o pedido de aprovação."""
    if not rationale.strip():
        raise ValidationError(
            "Uma acção de resposta exige justificação.", code="JUSTIFICACAO_OBRIGATORIA"
        )

    risk = resolve_risk_level(action_kind, risk_level)
    integration = await find_integration_for(session, action_kind)
    reference = await next_reference(session, ReferenceKind.ACTION)

    # A proposta de um playbook é de quem o iniciou, não de quem fez o pedido em
    # que ela calhou ser criada. A retoma corre no pedido de quem aprovou o passo
    # anterior: atribuir-lhe a proposta impedia-o de decidir a seguinte, e a
    # separação de funções passava a proteger a pessoa errada.
    proposer_id = ctx.actor_id
    if playbook_execution_id is not None:
        execution = await session.get(PlaybookExecution, playbook_execution_id)
        if execution is not None:
            proposer_id = execution.triggered_by_id

    action = Action(
        reference=reference,
        incident_id=incident.id,
        action_kind=action_kind,
        risk_level=risk,
        status=ActionStatus.PROPOSTA,
        title=title[:250],
        rationale=rationale,
        target=target,
        parameters=parameters or {},
        integration_id=integration.id if integration else None,
        proposed_by_id=proposer_id,
        proposed_by_engine=proposed_by_engine,
        recommendation_id=recommendation_id,
        playbook_execution_id=playbook_execution_id,
        is_reversible=action_kind in REVERSIBLE_BY,
    )
    session.add(action)
    await session.flush()

    if risk in (ActionRiskLevel.MODERADO, ActionRiskLevel.CRITICO):
        action.status = ActionStatus.AGUARDA_APROVACAO
        session.add(
            ActionApproval(
                action_id=action.id,
                decision=ApprovalDecision.PENDENTE,
                required_permission=required_permission_for(risk),
                requested_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=APPROVAL_TTL_HOURS),
            )
        )
        await _notify_approvers(session, incident, action)

    await session.flush()
    await audit.record(
        session, ctx,
        action="PROPOR_ACCAO", resource_type="accao",
        resource_id=action.id, resource_reference=action.reference,
        description=(
            f"Acção {action.reference} ({action_kind.value}, risco {risk.value}) "
            f"proposta para {incident.reference}. {rationale}"
        ),
        new_value={
            "tipo": action_kind.value,
            "risco": risk.value,
            "alvo": target,
            "estado": action.status.value,
        },
    )
    return action


async def _notify_approvers(
    session: AsyncSession, incident: Incident, action: Action
) -> None:
    """Notifica quem tem permissão para decidir sobre a acção."""
    from app.models.identity import Role

    required = required_permission_for(action.risk_level)
    result = await session.execute(
        select(User)
        .join(Role, Role.id == User.role_id)
        .options(selectinload(User.role).selectinload(Role.permissions))
        .where(User.is_active.is_(True))
    )
    for user in result.scalars().unique():
        if not any(p.code == required for p in user.role.permissions):
            continue
        session.add(
            Notification(
                user_id=user.id,
                kind=NotificationKind.APROVACAO_PENDENTE,
                severity=(
                    Severity.ALTA
                    if action.risk_level == ActionRiskLevel.CRITICO
                    else Severity.MEDIA
                ),
                title=f"Aprovação pendente: {action.title}",
                body=(
                    f"A acção {action.reference} ({action.action_kind.value}) sobre "
                    f"{incident.reference} aguarda decisão."
                ),
                resource_type="accao",
                resource_id=action.id,
                resource_reference=action.reference,
            )
        )


async def decide_action(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    action: Action,
    decider: User,
    approved: bool,
    justification: str | None = None,
) -> Action:
    """Regista a decisão humana sobre uma acção pendente."""
    if action.status != ActionStatus.AGUARDA_APROVACAO:
        raise ConflictError(
            f"A acção {action.reference} não está a aguardar aprovação "
            f"(estado actual: {action.status.value})."
        )

    pending = next(
        (a for a in action.approvals if a.decision == ApprovalDecision.PENDENTE), None
    )
    if pending is None:
        raise ConflictError("Não existe pedido de aprovação pendente para esta acção.")

    # Separação de funções: quem propôs não pode aprovar.
    if action.proposed_by_id is not None and action.proposed_by_id == decider.id:
        await audit.record_denied(
            session, ctx,
            action="DECIDIR_ACCAO", resource_type="accao", resource_id=action.id,
            reason="o proponente não pode aprovar a sua própria acção",
        )
        await session.commit()
        raise AuthorizationError(
            "Não pode aprovar uma acção que propôs. A decisão cabe a outro utilizador.",
        )

    held = {p.code for p in decider.role.permissions} if decider.role else set()
    if pending.required_permission not in held:
        await audit.record_denied(
            session, ctx,
            action="DECIDIR_ACCAO", resource_type="accao", resource_id=action.id,
            reason=f"permissão em falta: {pending.required_permission}",
        )
        await session.commit()
        raise AuthorizationError(required=pending.required_permission)

    if pending.expires_at is not None and pending.expires_at <= datetime.now(UTC):
        await _expire(session, action, pending)
        await session.commit()
        raise ConflictError(
            f"O pedido de aprovação da acção {action.reference} caducou e a acção "
            "foi cancelada. Proponha-a novamente."
        )

    if action.risk_level == ActionRiskLevel.CRITICO and not (justification or "").strip():
        raise ValidationError(
            "Decidir sobre uma acção crítica exige justificação escrita.",
            code="JUSTIFICACAO_OBRIGATORIA",
        )

    now = datetime.now(UTC)
    pending.decision = ApprovalDecision.APROVADA if approved else ApprovalDecision.REJEITADA
    pending.decided_at = now
    pending.decided_by_id = decider.id
    pending.justification = justification

    action.status = ActionStatus.APROVADA if approved else ActionStatus.REJEITADA

    session.add(
        Comment(
            incident_id=action.incident_id,
            author_id=decider.id,
            body=(
                f"Acção {action.reference} ({action.action_kind.value}) "
                f"{'aprovada' if approved else 'rejeitada'} por {decider.full_name}."
                + (f" Justificação: {justification}" if justification else "")
            ),
            is_system=True,
        )
    )

    await audit.record(
        session, ctx,
        action="DECIDIR_ACCAO", resource_type="accao",
        resource_id=action.id, resource_reference=action.reference,
        description=(
            f"Acção {action.reference} {'aprovada' if approved else 'rejeitada'} "
            f"por {decider.email}."
            + (f" Justificação: {justification}" if justification else "")
        ),
        old_value={"estado": ActionStatus.AGUARDA_APROVACAO.value},
        new_value={
            "estado": action.status.value,
            "decisor": decider.email,
            "justificacao": justification,
        },
        changed_fields=["status"],
    )
    return action


async def execute_action(
    session: AsyncSession, ctx: AuditContext, *, action: Action
) -> Action:
    """Executa uma acção aprovada através da integração configurada.

    Nunca devolve sucesso sem uma resposta real do sistema alvo.
    """
    if action.risk_level != ActionRiskLevel.BAIXO and action.status != ActionStatus.APROVADA:
        raise ApprovalRequiredError(
            f"A acção {action.reference} ({action.risk_level.value}) requer aprovação "
            f"antes de ser executada. Estado actual: {action.status.value}.",
        )
    if action.status in (ActionStatus.EXECUTADA, ActionStatus.EM_EXECUCAO):
        raise ConflictError(f"A acção {action.reference} já foi executada.")
    if action.status in (ActionStatus.REJEITADA, ActionStatus.CANCELADA):
        raise ConflictError(
            f"A acção {action.reference} está {action.status.value} e não pode ser executada."
        )

    # Uma porta de autorização não contacta nenhum sistema: a decisão humana
    # já registada *é* o seu resultado. Executá-la é apenas fechar o registo.
    if action.action_kind in NO_INTEGRATION_REQUIRED:
        action.status = ActionStatus.EXECUTADA
        action.executed_at = datetime.now(UTC)
        action.executed_by_id = ctx.actor_id
        action.result = {
            "sucesso": True,
            "detalhe": "Autorização registada; não houve actuação sobre sistemas externos.",
        }
        await audit.record(
            session, ctx,
            action="EXECUTAR_ACCAO", resource_type="accao",
            resource_id=action.id, resource_reference=action.reference,
            description=f"Acção {action.reference} ({action.action_kind.value}) concluída.",
        )
        return action

    action.status = ActionStatus.EM_EXECUCAO
    await session.flush()

    integration = (
        await session.get(Integration, action.integration_id)
        if action.integration_id
        else await find_integration_for(session, action.action_kind)
    )

    now = datetime.now(UTC)

    # Sem integração activa não há execução possível. Falhamos de forma
    # explícita em vez de registar um sucesso que não aconteceu (§4).
    if integration is None or not integration.is_operational:
        detail = (
            "Não existe nenhuma integração activa capaz de executar esta acção."
            if integration is None
            else (
                f"A integração '{integration.name}' está em estado "
                f"{integration.status.value} e não pode executar acções."
            )
        )
        action.status = ActionStatus.FALHADA
        action.error = detail
        action.executed_at = now
        action.executed_by_id = ctx.actor_id
        action.result = {"sucesso": False, "detalhe": detail}

        await _record_execution_comment(session, action, success=False, detail=detail)
        await audit.record(
            session, ctx,
            action="EXECUTAR_ACCAO", resource_type="accao",
            resource_id=action.id, resource_reference=action.reference,
            description=f"Execução de {action.reference} não realizada: {detail}",
            outcome=AuditOutcome.FALHA,
            failure_reason=detail,
        )
        raise IntegrationNotAvailableError(
            integration.name if integration else action.action_kind.value, detail
        )

    connector = get_connector(integration.kind)
    if connector is None:
        detail = f"Não existe cliente implementado para {integration.kind.value}."
        action.status = ActionStatus.FALHADA
        action.error = detail
        action.executed_at = now
        action.result = {"sucesso": False, "detalhe": detail}
        raise IntegrationNotAvailableError(integration.name, detail)

    try:
        outcome = await connector.execute_action(
            integration, action.action_kind, action.target, action.parameters
        )
        action.status = ActionStatus.EXECUTADA if outcome.success else ActionStatus.FALHADA
        action.result = outcome.as_dict()
        action.error = None if outcome.success else outcome.detail
        action.is_reversible = outcome.reversible or action.action_kind in REVERSIBLE_BY
        integration.actions_executed += 1
        if not outcome.success:
            integration.actions_failed += 1
        detail = outcome.detail
        success = outcome.success
    except Exception as exc:  # noqa: BLE001 - a falha é um resultado legítimo
        action.status = ActionStatus.FALHADA
        action.error = str(exc)[:2000]
        action.result = {"sucesso": False, "detalhe": str(exc)[:2000]}
        # Uma tentativa que rebenta também é uma execução tentada. Contada só como
        # falhada, a página de integrações mostrava "0 executadas (1 falhada)".
        integration.actions_executed += 1
        integration.actions_failed += 1
        detail = str(exc)
        success = False

    action.executed_at = now
    action.executed_by_id = ctx.actor_id

    if success:
        await _complete_reversion(session, ctx, inverse=action)

    await _record_execution_comment(session, action, success=success, detail=detail)
    await audit.record(
        session, ctx,
        action="EXECUTAR_ACCAO", resource_type="accao",
        resource_id=action.id, resource_reference=action.reference,
        description=(
            f"Acção {action.reference} ({action.action_kind.value}) sobre "
            f"{action.target}: {'executada' if success else 'falhada'}. {detail}"
        ),
        new_value={"estado": action.status.value, "resultado": action.result},
        outcome=AuditOutcome.SUCESSO if success else AuditOutcome.FALHA,
        failure_reason=None if success else detail[:500],
    )
    return action


async def _record_execution_comment(
    session: AsyncSession, action: Action, *, success: bool, detail: str
) -> None:
    """Deixa o resultado visível na investigação, não apenas na auditoria.

    O §37 pergunta "como é que o analista sabe o resultado?". A resposta é
    esta: o desfecho aparece na linha temporal do incidente.
    """
    session.add(
        Comment(
            incident_id=action.incident_id,
            body=(
                f"Acção {action.reference} ({action.action_kind.value}) "
                f"{'executada com sucesso' if success else 'FALHOU'}: {detail}"
            ),
            is_system=True,
        )
    )


async def get_action(session: AsyncSession, action_id: uuid.UUID) -> Action:
    result = await session.execute(
        select(Action)
        .where(Action.id == action_id)
        .options(
            selectinload(Action.approvals).selectinload(ActionApproval.decided_by)
        )
    )
    action = result.scalar_one_or_none()
    if action is None:
        raise NotFoundError("Acção", action_id)
    return action


#: Estados em que uma acção inversa ainda pode vir a ser executada.
_REVERSION_IN_PROGRESS = frozenset({
    ActionStatus.PROPOSTA, ActionStatus.AGUARDA_APROVACAO,
    ActionStatus.APROVADA, ActionStatus.EM_EXECUCAO,
})


async def revert_action(
    session: AsyncSession, ctx: AuditContext, *, action: Action, rationale: str
) -> Action:
    """Propõe a acção inversa de uma acção já executada.

    Propõe, não executa: a inversa passa pelo mesmo regime de aprovação. Por
    isso a original **não** fica REVERTIDA aqui — só quando a inversa for de facto
    executada (`_complete_reversion`). Antes ficava logo: o incidente dizia que o
    endereço fora desbloqueado com a inversa ainda por aprovar, e uma inversa
    rejeitada deixava a original impossível de reverter.
    """
    if action.status == ActionStatus.REVERTIDA:
        raise ConflictError(f"A acção {action.reference} já foi revertida.")
    if action.status != ActionStatus.EXECUTADA:
        raise ConflictError("Só é possível reverter uma acção executada com sucesso.")
    inverse_kind = REVERSIBLE_BY.get(action.action_kind)
    if inverse_kind is None:
        raise ConflictError(
            f"A acção {action.action_kind.value} não tem operação inversa definida."
        )
    if action.reverted_by_action_id is not None:
        current = await session.get(Action, action.reverted_by_action_id)
        if current is not None and current.status in _REVERSION_IN_PROGRESS:
            raise ConflictError(
                f"Já existe uma reversão em curso: {current.reference} "
                f"({current.status.value})."
            )

    incident = await session.get(Incident, action.incident_id)
    inverse = await propose_action(
        session, ctx,
        incident=incident,
        action_kind=inverse_kind,
        title=f"Reverter {action.reference}: {action.title}",
        rationale=rationale,
        target=action.target,
        parameters=action.parameters,
    )
    action.reverted_by_action_id = inverse.id
    return inverse


async def _complete_reversion(
    session: AsyncSession, ctx: AuditContext, *, inverse: Action
) -> None:
    """Dá a acção original por revertida, agora que a inversa foi executada."""
    original = (
        await session.execute(select(Action).where(Action.reverted_by_action_id == inverse.id))
    ).scalar_one_or_none()
    if original is None or original.status != ActionStatus.EXECUTADA:
        return
    original.status = ActionStatus.REVERTIDA
    original.reverted_at = datetime.now(UTC)
    await audit.record(
        session, ctx,
        action="REVERTER_ACCAO", resource_type="accao",
        resource_id=original.id, resource_reference=original.reference,
        description=(
            f"Acção {original.reference} revertida pela execução de {inverse.reference}."
        ),
        old_value={"estado": ActionStatus.EXECUTADA.value},
        new_value={"estado": ActionStatus.REVERTIDA.value},
        changed_fields=["status"],
    )


# ----------------------------------------------------------------- caducidade
async def expire_overdue_approvals(session: AsyncSession) -> int:
    """Cancela as acções cujo pedido de aprovação caducou sem decisão.

    Sem isto, um pedido caducado ficava na fila para sempre: decidi-lo devolvia
    409 sem mudar nada, e a acção continuava AGUARDA_APROVACAO. É chamado por
    quem consulta ou decide a fila — a caducidade aplica-se quando alguém olha,
    em vez de depender de um processo à parte que pode não estar a correr.
    """
    overdue = (
        await session.execute(
            select(ActionApproval)
            .where(
                ActionApproval.decision == ApprovalDecision.PENDENTE,
                ActionApproval.expires_at.is_not(None),
                ActionApproval.expires_at <= datetime.now(UTC),
            )
        )
    ).scalars().all()
    for pending in overdue:
        action = await session.get(Action, pending.action_id)
        if action is not None:
            await _expire(session, action, pending)
    await session.flush()
    return len(overdue)


async def _expire(session: AsyncSession, action: Action, pending: ActionApproval) -> None:
    """Regista a caducidade: pedido CADUCADO, acção CANCELADA, playbook terminado.

    Feito em nome do sistema — ninguém decidiu nada, o prazo é que acabou.
    """
    ctx = AuditContext.system(origin="caducidade")
    expired_at = pending.expires_at
    reason = (
        f"Pedido de aprovação caducado em {expired_at:%Y-%m-%d %H:%M} UTC sem decisão."
        if expired_at else "Pedido de aprovação caducado sem decisão."
    )
    pending.decision = ApprovalDecision.CADUCADA
    action.status = ActionStatus.CANCELADA
    action.error = reason
    session.add(
        Comment(
            incident_id=action.incident_id,
            body=f"Acção {action.reference} cancelada. {reason}",
            is_system=True,
        )
    )
    await audit.record(
        session, ctx,
        action="CADUCAR_APROVACAO", resource_type="accao",
        resource_id=action.id, resource_reference=action.reference,
        description=f"Acção {action.reference} cancelada. {reason}",
        old_value={"estado": ActionStatus.AGUARDA_APROVACAO.value},
        new_value={"estado": ActionStatus.CANCELADA.value},
        changed_fields=["status"],
    )

    if action.playbook_execution_id is not None:
        from app.core.enums import PlaybookExecutionStatus
        from app.models.response import PlaybookExecution as Execution
        from app.playbooks import engine as playbook_engine

        execution = await session.get(Execution, action.playbook_execution_id)
        if execution is not None and execution.status == PlaybookExecutionStatus.AGUARDA_APROVACAO:
            await playbook_engine.cancel_after_rejection(
                session, ctx, execution=execution, action=action,
                reason=f"o pedido de aprovação da acção {action.reference} caducou",
            )
