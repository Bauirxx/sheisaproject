"""Configuração com que a plataforma arranca (`seed_service`).

As regras de correlação, os playbooks e o inventário do laboratório não são dados
de demonstração: sem eles a plataforma arranca vazia e nunca correlaciona nada.
Por isso não chega verificar que as linhas são criadas. O que aqui se fixa é que
a configuração **funciona** com os motores reais — a regra de força bruta abre um
incidente a partir de uma ingestão Wazuh, os activos são reconhecidos pelos
alertas, e o playbook de bloqueio chega ao fim sem afirmar o que não fez.

Foi este último teste que revelou o defeito mais grave desta ronda: depois de
aprovado, o bloqueio nunca era executado, e o passo seguinte escrevia no
incidente "Bloqueio aplicado e resultado registado no incidente."
"""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.enums import ActionKind, ActionStatus, AssetCriticality, PlaybookExecutionStatus
from app.models.catalog import Asset
from app.models.response import Action, Playbook, PlaybookExecution, PlaybookStep
from app.models.telemetry import Alert, CorrelationRule
from app.services.seed_service import (
    CORRELATION_RULES,
    LAB_ASSETS,
    PLAYBOOKS,
    seed_correlation_rules,
    seed_lab_assets,
    seed_playbooks,
)
from tests.conftest import cabecalho
from tests.test_ingestao import alerta_wazuh


async def _semear_tudo(sessao) -> dict[str, tuple[int, int]]:
    resultado = {
        "regras": await seed_correlation_rules(sessao),
        "playbooks": await seed_playbooks(sessao),
        "activos": await seed_lab_assets(sessao),
    }
    await sessao.flush()
    return resultado


async def _contar(sessao, modelo) -> int:
    return (await sessao.execute(select(func.count()).select_from(modelo))).scalar_one()


# ------------------------------------------------------------ idempotência
async def test_o_arranque_cria_a_configuracao_declarada(sessao):
    resultado = await _semear_tudo(sessao)

    assert resultado == {
        "regras": (len(CORRELATION_RULES), 0),
        "playbooks": (len(PLAYBOOKS), 0),
        "activos": (len(LAB_ASSETS), 0),
    }
    regras = set((await sessao.execute(select(CorrelationRule.name))).scalars())
    assert regras == {r["name"] for r in CORRELATION_RULES}

    for spec in PLAYBOOKS:
        playbook = (
            await sessao.execute(select(Playbook).where(Playbook.name == spec["name"]))
        ).scalar_one()
        ordens = (
            await sessao.execute(
                select(PlaybookStep.ordering)
                .where(PlaybookStep.playbook_id == playbook.id)
                .order_by(PlaybookStep.ordering)
            )
        ).scalars().all()
        assert ordens == list(range(1, len(spec["steps"]) + 1)), spec["name"]


async def test_semear_de_novo_nao_duplica_nada(sessao):
    await _semear_tudo(sessao)
    antes = [await _contar(sessao, m) for m in (CorrelationRule, Playbook, PlaybookStep, Asset)]

    resultado = await _semear_tudo(sessao)

    assert resultado == {
        "regras": (0, len(CORRELATION_RULES)),
        "playbooks": (0, len(PLAYBOOKS)),
        "activos": (0, len(LAB_ASSETS)),
    }
    depois = [await _contar(sessao, m) for m in (CorrelationRule, Playbook, PlaybookStep, Asset)]
    assert depois == antes


async def test_semear_de_novo_nao_desfaz_o_que_o_administrador_mudou(sessao):
    """Voltar a correr o arranque não pode repor silenciosamente a configuração original."""
    await _semear_tudo(sessao)

    regra = (
        await sessao.execute(
            select(CorrelationRule).where(CorrelationRule.name == "Força bruta persistente")
        )
    ).scalar_one()
    regra.window_minutes = 5
    regra.is_enabled = False
    activo = (
        await sessao.execute(select(Asset).where(Asset.identifier == "srv-web-01"))
    ).scalar_one()
    activo.criticality = AssetCriticality.CRITICA
    await sessao.flush()

    await _semear_tudo(sessao)
    await sessao.refresh(regra)
    await sessao.refresh(activo)

    assert (regra.window_minutes, regra.is_enabled) == (5, False)
    assert activo.criticality is AssetCriticality.CRITICA


# ------------------------------------------------- a configuração funciona
async def test_a_regra_de_forca_bruta_semeada_abre_incidente_a_partir_do_wazuh(
    cliente, sessao, chave_ingestao
):
    """Sem esta regra, três falhas de autenticação seguidas ficavam alertas soltos."""
    await seed_correlation_rules(sessao)
    await sessao.flush()

    for numero in range(3):
        resposta = await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(id_fonte=f"forca-bruta-{numero}"),
            headers={"X-API-Key": chave_ingestao},
        )
        assert resposta.status_code == 202, resposta.text

    correlacionados = (
        await sessao.execute(select(Alert).where(Alert.incident_id.is_not(None)))
    ).scalars().all()
    assert correlacionados, "nenhum alerta foi correlacionado num incidente"
    assert all(
        (a.correlation_rationale or "").startswith("Regra 'Força bruta persistente'")
        for a in correlacionados
    ), [a.correlation_rationale for a in correlacionados]


async def test_os_activos_semeados_sao_reconhecidos_pelos_alertas(
    cliente, sessao, chave_ingestao
):
    await seed_lab_assets(sessao)
    await sessao.flush()

    await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(
            id_fonte="activo-semeado-1",
            agent={"id": "004", "name": "srv-bd-01", "ip": "10.10.5.30"},
        ),
        headers={"X-API-Key": chave_ingestao},
    )

    alerta = (await sessao.execute(select(Alert))).scalar_one()
    activo = (
        await sessao.execute(select(Asset).where(Asset.identifier == "srv-bd-01"))
    ).scalar_one()
    assert alerta.asset_id == activo.id


async def test_o_playbook_de_bloqueio_nao_afirma_um_bloqueio_que_nao_aconteceu(
    cliente, sessao, chave_ingestao, token_analista, token_gestor, token_admin
):
    """Regressão: aprovado o bloqueio, o playbook seguia sem o executar.

    O passo 7 escrevia "Bloqueio aplicado" e a execução ficava CONCLUIDA com a
    acção parada em APROVADA. Nesta suite não há integração capaz de bloquear,
    pelo que o resultado honesto é a acção falhar e o playbook parar ali — o
    passo 6 declara `abort_on_failure`.
    """
    await seed_playbooks(sessao)
    await sessao.flush()
    await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(id_fonte="playbook-semeado-1"),
        headers={"X-API-Key": chave_ingestao},
    )
    alerta = (await sessao.execute(select(Alert))).scalar_one()
    incidente = (
        await cliente.post(
            f"/api/alerts/{alerta.id}/promote",
            json={"title": "Origem externa hostil", "rationale": "Teste."},
            headers=cabecalho(token_analista),
        )
    ).json()
    playbook = (
        await sessao.execute(
            select(Playbook).where(Playbook.name == "Resposta a endereço IP malicioso")
        )
    ).scalar_one()

    execucao = await cliente.post(
        f"/api/playbooks/{playbook.id}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_analista),
    )
    assert execucao.status_code == 201, execucao.text
    assert execucao.json()["status"] == PlaybookExecutionStatus.AGUARDA_APROVACAO.value

    # Passo 5: a autorização. Passo 6: o bloqueio. Duas pessoas diferentes
    # decidem, para que este teste não dependa de a quem é atribuída a
    # proposta do passo 6 — isso é fixado em `test_playbooks.py`.
    for esperado, token in (
        (ActionKind.AUTORIZAR_PROSSEGUIMENTO, token_gestor),
        (ActionKind.BLOQUEAR_IP, token_admin),
    ):
        fila = (await cliente.get("/api/approvals", headers=cabecalho(token))).json()
        pendente = next(i for i in fila["itens"] if i["action_kind"] == esperado.value)
        decisao = await cliente.post(
            f"/api/approvals/{pendente['id']}/decide",
            json={"approved": True, "justification": "Origem confirmada como hostil."},
            headers=cabecalho(token),
        )
        assert decisao.status_code == 200, decisao.text

    sessao.expire_all()
    bloqueio = (
        await sessao.execute(select(Action).where(Action.action_kind == ActionKind.BLOQUEAR_IP))
    ).scalar_one()
    assert bloqueio.status is ActionStatus.FALHADA, (
        f"o bloqueio aprovado ficou em {bloqueio.status.value}: ninguém o executou"
    )

    registo = await sessao.get(PlaybookExecution, execucao.json()["id"])
    assert registo.status is PlaybookExecutionStatus.FALHADA
    assert "Bloquear o endereço" in (registo.error or "")

    linha = (
        await cliente.get(
            f"/api/incidents/{incidente['id']}/timeline", headers=cabecalho(token_analista)
        )
    ).json()
    assert not [e for e in linha if "Bloqueio aplicado" in (e["detalhe"] or "")], (
        "o incidente afirma um bloqueio que não aconteceu"
    )
