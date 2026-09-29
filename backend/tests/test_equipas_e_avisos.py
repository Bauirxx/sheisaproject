"""Equipas (grupos de triagem) e avisos por email a quem passa a responder.

Três coisas estão aqui fixadas:

* **Gestão de equipas.** Existiam no modelo — o incidente já tinha `team_id` —,
  mas a API só as listava: não havia como criar um grupo de triagem nem lhe
  juntar analistas.
* **Um defeito de atribuição.** Atribuir só a equipa (`{"team_id": ...}`)
  apagava o responsável: o campo ausente chegava como `None` e era tratado como
  "retirar". Nada na interface o revelava porque ela só enviava o responsável.
* **Avisos por email.** Atribuir, entregar a uma equipa ou escalar só criava uma
  notificação dentro da plataforma, e só para o responsável individual — a
  equipa não era avisada de todo, e ninguém recebia email.

O envio de correio é substituído **só na fronteira** (`email_service.enviar`),
que é onde a plataforma fala com um servidor externo. Tudo o resto — quem é
avisado, quem não é, o que fica na auditoria — corre a sério.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.enums import AuditOutcome, NotificationKind
from app.models.identity import User
from app.models.incident import Incident
from app.models.system import AuditLog, Notification
from app.services import email_service
from tests.conftest import SENHA, cabecalho


# ------------------------------------------------------------------ auxiliares
@pytest.fixture
def correio(monkeypatch) -> list[dict]:
    """Recolhe os emails que a plataforma mandaria, em vez de os mandar."""
    enviados: list[dict] = []

    def _enviar(**kw):
        enviados.append(kw)
        return f"<teste-{len(enviados)}@sheisa.local>"

    monkeypatch.setattr(email_service, "enviar", _enviar)
    return enviados


async def _utilizador(sessao, alcunha: str) -> User:
    return (
        await sessao.execute(select(User).where(User.email == f"{alcunha}@teste.local"))
    ).scalar_one()


async def _equipa(cliente, token, nome="Triagem N1", membros=()) -> dict:
    criada = await cliente.post(
        "/api/teams", json={"name": nome, "description": "Primeira linha."},
        headers=cabecalho(token),
    )
    assert criada.status_code == 201, criada.text
    equipa = criada.json()
    for membro in membros:
        juntar = await cliente.post(
            f"/api/teams/{equipa['id']}/members", json={"user_id": str(membro)},
            headers=cabecalho(token),
        )
        assert juntar.status_code == 200, juntar.text
        equipa = juntar.json()
    return equipa


async def _incidente(cliente, token, titulo="Incidente para avisos") -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": titulo, "description": "x", "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _avisos_na_auditoria(sessao, incidente_id) -> list[AuditLog]:
    return list(
        (
            await sessao.execute(
                select(AuditLog).where(
                    AuditLog.action == "AVISAR_POR_EMAIL",
                    AuditLog.resource_id == uuid.UUID(incidente_id),
                )
            )
        ).scalars()
    )


# ------------------------------------------------------- gestão de equipas
async def test_criar_equipa_e_juntar_membros(cliente, sessao, token_admin):
    analista = await _utilizador(sessao, "analista")
    investigador = await _utilizador(sessao, "investigador")

    equipa = await _equipa(cliente, token_admin, membros=[analista.id, investigador.id])

    assert {m["email"] for m in equipa["membros"]} == {
        "analista@teste.local", "investigador@teste.local"
    }
    lista = (await cliente.get("/api/teams", headers=cabecalho(token_admin))).json()
    resumo = next(e for e in lista if e["id"] == equipa["id"])
    assert resumo["total_membros"] == 2


async def test_nome_de_equipa_repetido_e_recusado(cliente, token_admin):
    await _equipa(cliente, token_admin, nome="Resposta N2")

    repetida = await cliente.post(
        "/api/teams", json={"name": "resposta n2"}, headers=cabecalho(token_admin)
    )

    assert repetida.status_code == 409, repetida.text


async def test_juntar_a_outra_equipa_tira_da_anterior(cliente, sessao, token_admin):
    """Cada pessoa pertence a uma equipa de cada vez, e a auditoria diz de onde saiu."""
    analista = await _utilizador(sessao, "analista")
    primeira = await _equipa(cliente, token_admin, nome="Equipa A", membros=[analista.id])

    segunda = await _equipa(cliente, token_admin, nome="Equipa B", membros=[analista.id])

    detalhe_a = (await cliente.get(f"/api/teams/{primeira['id']}", headers=cabecalho(token_admin))).json()
    assert detalhe_a["membros"] == []
    assert [m["email"] for m in segunda["membros"]] == ["analista@teste.local"]
    registo = (
        await sessao.execute(
            select(AuditLog).where(AuditLog.action == "JUNTAR_MEMBRO_EQUIPA")
            .order_by(AuditLog.created_at.desc())
        )
    ).scalars().first()
    assert "saiu de 'Equipa A'" in registo.description


async def test_retirar_membro_e_nao_retirar_quem_la_nao_esta(cliente, sessao, token_admin):
    analista = await _utilizador(sessao, "analista")
    equipa = await _equipa(cliente, token_admin, membros=[analista.id])
    rota = f"/api/teams/{equipa['id']}/members/{analista.id}"

    retirado = await cliente.delete(rota, headers=cabecalho(token_admin))
    outra_vez = await cliente.delete(rota, headers=cabecalho(token_admin))

    assert retirado.status_code == 200 and retirado.json()["membros"] == []
    assert outra_vez.status_code == 409, outra_vez.text


async def test_so_quem_gere_contas_gere_equipas(cliente, token_analista):
    resposta = await cliente.post(
        "/api/teams", json={"name": "Equipa não autorizada"}, headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 403, resposta.text


async def test_equipa_desactivada_nao_recebe_incidentes_nem_membros(cliente, sessao, token_admin):
    analista = await _utilizador(sessao, "analista")
    equipa = await _equipa(cliente, token_admin, nome="Equipa extinta")
    desactivar = await cliente.patch(
        f"/api/teams/{equipa['id']}", json={"is_active": False}, headers=cabecalho(token_admin)
    )
    assert desactivar.status_code == 200 and desactivar.json()["is_active"] is False
    incidente = await _incidente(cliente, token_admin)

    atribuir = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign", json={"team_id": equipa["id"]},
        headers=cabecalho(token_admin),
    )
    juntar = await cliente.post(
        f"/api/teams/{equipa['id']}/members", json={"user_id": str(analista.id)},
        headers=cabecalho(token_admin),
    )

    assert atribuir.status_code == 422 and atribuir.json()["erro"]["codigo"] == "EQUIPA_INACTIVA"
    assert juntar.status_code == 422 and juntar.json()["erro"]["codigo"] == "EQUIPA_INACTIVA"


# ------------------------------------------------ o defeito da atribuição
async def test_atribuir_so_a_equipa_nao_apaga_o_responsavel(cliente, sessao, token_admin, correio):
    """Regressão: `{"team_id": ...}` sozinho retirava o responsável."""
    analista = await _utilizador(sessao, "analista")
    equipa = await _equipa(cliente, token_admin)
    incidente = await _incidente(cliente, token_admin)
    rota = f"/api/incidents/{incidente['id']}/assign"
    await cliente.post(rota, json={"assignee_id": str(analista.id)}, headers=cabecalho(token_admin))

    resposta = await cliente.post(rota, json={"team_id": equipa["id"]}, headers=cabecalho(token_admin))

    assert resposta.status_code == 200, resposta.text
    corpo = resposta.json()
    assert corpo["assignee"] is not None and corpo["assignee"]["id"] == str(analista.id)
    assert corpo["team"] is not None and corpo["team"]["id"] == equipa["id"]


async def test_retirar_o_responsavel_explicitamente_continua_possivel(cliente, sessao, token_admin, correio):
    analista = await _utilizador(sessao, "analista")
    incidente = await _incidente(cliente, token_admin)
    rota = f"/api/incidents/{incidente['id']}/assign"
    await cliente.post(rota, json={"assignee_id": str(analista.id)}, headers=cabecalho(token_admin))

    resposta = await cliente.post(rota, json={"assignee_id": None}, headers=cabecalho(token_admin))

    assert resposta.status_code == 200 and resposta.json()["assignee"] is None


# ------------------------------------------------------ avisos por email
async def test_entregar_a_uma_equipa_avisa_cada_membro_activo_menos_o_autor(
    cliente, sessao, token_admin, correio
):
    admin = await _utilizador(sessao, "admin")
    analista = await _utilizador(sessao, "analista")
    investigador = await _utilizador(sessao, "investigador")
    criado = await cliente.post(
        "/api/users",
        json={"email": "saiu@teste.local", "full_name": "Conta Desactivada",
              "password": SENHA, "role_name": "ANALISTA_SOC"},
        headers=cabecalho(token_admin),
    )
    assert criado.status_code == 201, criado.text
    desactivado = criado.json()
    equipa = await _equipa(
        cliente, token_admin,
        membros=[admin.id, analista.id, investigador.id, uuid.UUID(desactivado["id"])],
    )
    await cliente.patch(
        f"/api/users/{desactivado['id']}", json={"is_active": False}, headers=cabecalho(token_admin)
    )
    incidente = await _incidente(cliente, token_admin)

    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign", json={"team_id": equipa["id"]},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    # O autor (admin) não é avisado; a conta desactivada também não.
    assert sorted(e["para"] for e in correio) == [
        "analista@teste.local", "investigador@teste.local"
    ]
    assert all(e["assunto"].startswith(f"[{incidente['reference']}]") for e in correio)
    for pessoa in (analista, investigador):
        notificacoes = (
            await sessao.execute(
                select(Notification).where(
                    Notification.user_id == pessoa.id,
                    Notification.kind == NotificationKind.INCIDENTE_ATRIBUIDO,
                )
            )
        ).scalars().all()
        assert len(notificacoes) == 1
    [registo] = await _avisos_na_auditoria(sessao, incidente["id"])
    assert registo.outcome is AuditOutcome.SUCESSO
    assert {e["para"] for e in registo.new_value["enviados"]} == {
        "analista@teste.local", "investigador@teste.local"
    }
    assert all(e["message_id"].startswith("<teste-") for e in registo.new_value["enviados"])


async def test_responsavel_que_tambem_e_membro_recebe_um_so_email(
    cliente, sessao, token_admin, correio
):
    analista = await _utilizador(sessao, "analista")
    investigador = await _utilizador(sessao, "investigador")
    equipa = await _equipa(cliente, token_admin, membros=[analista.id, investigador.id])
    incidente = await _incidente(cliente, token_admin)

    await cliente.post(
        f"/api/incidents/{incidente['id']}/assign",
        json={"assignee_id": str(analista.id), "team_id": equipa["id"]},
        headers=cabecalho(token_admin),
    )

    assert sorted(e["para"] for e in correio) == [
        "analista@teste.local", "investigador@teste.local"
    ]


async def test_o_email_leva_a_ligacao_e_os_dados_do_incidente(
    cliente, sessao, token_admin, correio
):
    analista = await _utilizador(sessao, "analista")
    incidente = await _incidente(cliente, token_admin, titulo="Ransomware no posto 12")

    await cliente.post(
        f"/api/incidents/{incidente['id']}/assign", json={"assignee_id": str(analista.id)},
        headers=cabecalho(token_admin),
    )

    [email] = correio
    assert incidente["reference"] in email["corpo"]
    assert "Ransomware no posto 12" in email["corpo"]
    assert f"/incidentes/{incidente['id']}" in email["corpo"]
    assert "admin@teste.local" in email["corpo"]  # quem atribuiu


async def test_escalar_para_uma_equipa_avisa_a_equipa_e_o_responsavel(
    cliente, sessao, token_admin, correio
):
    analista = await _utilizador(sessao, "analista")
    investigador = await _utilizador(sessao, "investigador")
    gestor = await _utilizador(sessao, "gestor")
    n2 = await _equipa(cliente, token_admin, nome="Resposta N2", membros=[investigador.id, gestor.id])
    incidente = await _incidente(cliente, token_admin)
    rota = f"/api/incidents/{incidente['id']}"
    await cliente.post(f"{rota}/assign", json={"assignee_id": str(analista.id)}, headers=cabecalho(token_admin))
    await cliente.post(f"{rota}/transition", json={"status": "TRIAGEM"}, headers=cabecalho(token_admin))
    correio.clear()

    escalado = await cliente.post(
        f"{rota}/transition", json={"status": "ESCALADO", "team_id": n2["id"]},
        headers=cabecalho(token_admin),
    )

    assert escalado.status_code == 200, escalado.text
    assert escalado.json()["team"]["id"] == n2["id"]
    # Uma vaga só: o escalamento; a mudança de equipa não manda uma segunda.
    assert sorted(e["para"] for e in correio) == [
        "analista@teste.local", "gestor@teste.local", "investigador@teste.local"
    ]
    assert all("escalado" in e["assunto"].lower() for e in correio)
    assert all("Resposta N2" in e["assunto"] for e in correio)
    notificacoes = (
        await sessao.execute(
            select(Notification).where(
                Notification.user_id == gestor.id,
                Notification.kind == NotificationKind.INCIDENTE_ESCALADO,
            )
        )
    ).scalars().all()
    assert len(notificacoes) == 1


async def test_equipa_na_transicao_so_quando_se_escala(cliente, token_admin, correio):
    equipa = await _equipa(cliente, token_admin)
    incidente = await _incidente(cliente, token_admin)

    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/transition",
        json={"status": "TRIAGEM", "team_id": equipa["id"]},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "ALVO_SO_AO_ESCALAR"


async def test_falha_do_servidor_de_correio_nao_desfaz_a_atribuicao(
    cliente, sessao, token_admin, monkeypatch
):
    """A atribuição fica feita; a falha fica registada com o motivo."""
    def _recusa(**_):
        raise ConnectionRefusedError("servidor de correio em baixo")

    monkeypatch.setattr(email_service, "enviar", _recusa)
    analista = await _utilizador(sessao, "analista")
    incidente = await _incidente(cliente, token_admin)

    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign", json={"assignee_id": str(analista.id)},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    guardado = await sessao.get(Incident, uuid.UUID(incidente["id"]))
    await sessao.refresh(guardado)
    assert guardado.assignee_id == analista.id
    [registo] = await _avisos_na_auditoria(sessao, incidente["id"])
    assert registo.outcome is AuditOutcome.FALHA
    assert "servidor de correio em baixo" in registo.failure_reason
    assert registo.new_value["enviados"] == []


async def test_sem_canal_configurado_diz_que_nao_enviou(
    cliente, sessao, token_admin, correio, monkeypatch
):
    """Nunca se afirma um envio que não houve — nem se tenta."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "smtp_host", "")
    analista = await _utilizador(sessao, "analista")
    incidente = await _incidente(cliente, token_admin)

    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign", json={"assignee_id": str(analista.id)},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    assert correio == []
    [registo] = await _avisos_na_auditoria(sessao, incidente["id"])
    assert registo.outcome is AuditOutcome.FALHA
    assert "não está configurado" in registo.description
    assert registo.new_value == {"nao_enviado_a": ["analista@teste.local"]}
    # A notificação interna existe na mesma.
    notificacao = (
        await sessao.execute(
            select(Notification).where(
                Notification.user_id == analista.id,
                Notification.kind == NotificationKind.INCIDENTE_ATRIBUIDO,
            )
        )
    ).scalar_one()
    assert notificacao.resource_reference == incidente["reference"]


async def test_responsavel_desactivado_nao_e_avisado_ao_escalar(
    cliente, sessao, token_admin, correio
):
    """Quem saiu da organização não continua a receber incidentes por email.

    A lista de membros de uma equipa já vem filtrada da base de dados; o caso
    que só a guarda de `aviso_service` apanha é o de um responsável atribuído
    antes e desactivado depois.
    """
    criado = await cliente.post(
        "/api/users",
        json={"email": "de-saida@teste.local", "full_name": "Analista de Saída",
              "password": SENHA, "role_name": "ANALISTA_SOC"},
        headers=cabecalho(token_admin),
    )
    assert criado.status_code == 201, criado.text
    de_saida = criado.json()
    incidente = await _incidente(cliente, token_admin)
    rota = f"/api/incidents/{incidente['id']}"
    await cliente.post(f"{rota}/assign", json={"assignee_id": de_saida["id"]}, headers=cabecalho(token_admin))
    await cliente.post(f"{rota}/transition", json={"status": "TRIAGEM"}, headers=cabecalho(token_admin))
    await cliente.patch(
        f"/api/users/{de_saida['id']}", json={"is_active": False}, headers=cabecalho(token_admin)
    )
    correio.clear()

    escalado = await cliente.post(
        f"{rota}/transition", json={"status": "ESCALADO"}, headers=cabecalho(token_admin)
    )

    assert escalado.status_code == 200, escalado.text
    assert correio == []
