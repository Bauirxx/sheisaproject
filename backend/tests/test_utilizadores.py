"""Administração: utilizadores, perfis, auditoria e notificações (`api/v1/admin.py`).

Um defeito foi encontrado ao escrever estes testes: **um administrador podia
retirar a si próprio o perfil de administrador.** A rota já impedia que se
desactivasse, com a razão de não perder o acesso — mas trocar o próprio perfil
por outro tem o mesmo efeito, e passava. Numa instalação com um só
administrador, a plataforma ficava sem ninguém capaz de gerir contas.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.core.enums import NotificationKind, Severity
from app.models.identity import User
from app.models.system import Notification
from tests.conftest import SENHA, cabecalho

SENHA_NOVA = "OutraSegura2026"


async def _criar(cliente, token, **campos):
    corpo = {
        "email": "nova.conta@soc.local",
        "full_name": "Nova Conta",
        "password": SENHA,
        "role_name": "analista_soc",
        **campos,
    }
    return await cliente.post("/api/users", json=corpo, headers=cabecalho(token))


async def _login(cliente, email, senha):
    return await cliente.post("/api/auth/login", json={"email": email, "password": senha})


# ------------------------------------------------------------ utilizadores
async def test_criar_conta_normaliza_o_email_e_recusa_o_repetido(cliente, token_admin):
    criada = await _criar(cliente, token_admin, email="Nova.Conta@SOC.local")
    assert criada.status_code == 201, criada.text
    assert criada.json()["email"] == "nova.conta@soc.local"

    repetida = await _criar(cliente, token_admin, email="nova.conta@soc.local")
    assert repetida.status_code == 409


async def test_criar_conta_com_perfil_ou_equipa_inexistente_da_404(cliente, token_admin):
    sem_perfil = await _criar(cliente, token_admin, role_name="PERFIL_INVENTADO")
    sem_equipa = await _criar(cliente, token_admin, team_id=str(uuid.uuid4()))
    assert (sem_perfil.status_code, sem_equipa.status_code) == (404, 404)


async def test_palavra_passe_fraca_e_recusada_ao_criar_e_ao_repor(
    cliente, token_admin, semente
):
    fraca = await _criar(cliente, token_admin, password="curta")
    reposta = await cliente.post(
        f"/api/users/{semente['utilizadores']['investigador']}/reset-password",
        json={"new_password": "semmaiusculas2026"},
        headers=cabecalho(token_admin),
    )
    assert (fraca.status_code, reposta.status_code) == (422, 422)


async def test_repor_a_palavra_passe_desbloqueia_e_termina_as_sessoes(
    cliente, sessao, token_admin
):
    conta = (await _criar(cliente, token_admin, must_change_password=False)).json()
    assert (await _login(cliente, "nova.conta@soc.local", SENHA)).status_code == 200
    utilizador = await sessao.get(User, uuid.UUID(conta["id"]))
    utilizador.failed_login_count = 5
    utilizador.locked_until = datetime.now(UTC) + timedelta(hours=1)
    await sessao.flush()

    resposta = await cliente.post(
        f"/api/users/{conta['id']}/reset-password",
        json={"new_password": SENHA_NOVA},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    assert "1 sessão(ões) terminada(s)" in resposta.json()["mensagem"]
    await sessao.refresh(utilizador)
    assert (utilizador.failed_login_count, utilizador.locked_until) == (0, None)
    assert utilizador.must_change_password is True
    assert (await _login(cliente, "nova.conta@soc.local", SENHA)).status_code == 401
    assert (await _login(cliente, "nova.conta@soc.local", SENHA_NOVA)).status_code == 200


async def test_administrador_nao_se_desactiva_a_si_proprio(cliente, token_admin, semente):
    resposta = await cliente.patch(
        f"/api/users/{semente['utilizadores']['admin']}",
        json={"is_active": False}, headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 422
    assert resposta.json()["erro"]["codigo"] == "AUTO_DESACTIVACAO"


async def test_administrador_nao_retira_a_si_proprio_o_perfil(
    cliente, sessao, token_admin, semente
):
    """Regressão: trocar o próprio perfil tinha o efeito que a auto-desactivação evita."""
    admin_id = semente["utilizadores"]["admin"]

    resposta = await cliente.patch(
        f"/api/users/{admin_id}", json={"role_name": "ANALISTA_SOC"},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "AUTO_DESPROMOCAO"
    utilizador = await sessao.get(User, admin_id)
    await sessao.refresh(utilizador, ["role"])
    assert utilizador.role.name == "ADMINISTRADOR"


async def test_mudar_o_perfil_de_outra_conta_tem_efeito(cliente, token_admin, semente):
    alvo = semente["utilizadores"]["investigador"]

    mudada = await cliente.patch(
        f"/api/users/{alvo}", json={"role_name": "gestor"}, headers=cabecalho(token_admin)
    )
    inexistente = await cliente.patch(
        f"/api/users/{alvo}", json={"role_name": "CHEFE"}, headers=cabecalho(token_admin)
    )

    assert mudada.status_code == 200, mudada.text
    assert mudada.json()["role"]["name"] == "GESTOR"
    assert inexistente.status_code == 404


async def test_listar_contas_filtra_por_perfil_e_texto(cliente, token_admin):
    async def emails(consulta):
        resposta = await cliente.get(f"/api/users?{consulta}", headers=cabecalho(token_admin))
        assert resposta.status_code == 200, resposta.text
        return {u["email"] for u in resposta.json()["itens"]}

    assert "gestor@teste.local" in await emails("perfil=gestor")
    assert "analista@teste.local" not in await emails("perfil=gestor")
    assert await emails("q=investigador@teste") == {"investigador@teste.local"}

    detalhe = await cliente.get(
        f"/api/users/{uuid.uuid4()}", headers=cabecalho(token_admin)
    )
    assert detalhe.status_code == 404


async def test_perfis_trazem_as_suas_permissoes_e_ha_equipa(cliente, token_admin):
    perfis = (await cliente.get("/api/roles", headers=cabecalho(token_admin))).json()
    por_nome = {p["name"]: {c["code"] for c in p["permissions"]} for p in perfis}
    assert "users:manage" in por_nome["ADMINISTRADOR"]
    assert "users:manage" not in por_nome["ANALISTA_SOC"]

    equipas = (await cliente.get("/api/roles/teams", headers=cabecalho(token_admin))).json()
    assert "SOC" in {e["name"] for e in equipas}


# ---------------------------------------------------------------- auditoria
async def test_consultar_a_auditoria_por_accao_recurso_actor_e_resultado(
    cliente, token_admin, token_analista
):
    conta = (await _criar(cliente, token_admin)).json()
    negado = await cliente.post(
        "/api/users", json={"email": "x@soc.local", "full_name": "X", "password": SENHA,
                            "role_name": "GESTOR"},
        headers=cabecalho(token_analista),
    )
    assert negado.status_code == 403

    async def entradas(consulta):
        resposta = await cliente.get(f"/api/audit?{consulta}", headers=cabecalho(token_admin))
        assert resposta.status_code == 200, resposta.text
        return resposta.json()["itens"]

    criacao = await entradas(f"accao=CRIAR_UTILIZADOR&recurso_id={conta['id']}")
    assert [e["actor_email"] for e in criacao] == ["admin@teste.local"]
    assert await entradas("actor=analista@teste&resultado=NEGADO")
    assert all(e["outcome"] == "NEGADO" for e in await entradas("resultado=NEGADO"))
    assert await entradas("q=nova.conta@soc.local")

    accoes = (await cliente.get("/api/audit/actions", headers=cabecalho(token_admin))).json()
    assert "CRIAR_UTILIZADOR" in accoes


# ------------------------------------------------------------ notificações
async def test_cada_um_ve_e_marca_so_as_suas_notificacoes(
    cliente, sessao, semente, token_analista
):
    def aviso(dono, titulo):
        return Notification(user_id=dono, kind=NotificationKind.ACCAO_EXECUTADA,
                            severity=Severity.MEDIA, title=titulo)

    minha = aviso(semente["utilizadores"]["analista"], "Para o analista")
    alheia = aviso(semente["utilizadores"]["gestor"], "Para o gestor")
    sessao.add_all([minha, alheia])
    await sessao.flush()

    lista = (await cliente.get("/api/notifications", headers=cabecalho(token_analista))).json()
    assert [n["title"] for n in lista] == ["Para o analista"]

    de_outro = await cliente.post(
        f"/api/notifications/{alheia.id}/read", headers=cabecalho(token_analista)
    )
    propria = await cliente.post(
        f"/api/notifications/{minha.id}/read", headers=cabecalho(token_analista)
    )
    assert (de_outro.status_code, propria.status_code) == (404, 200)

    nao_lidas = await cliente.get(
        "/api/notifications?apenas_nao_lidas=true", headers=cabecalho(token_analista)
    )
    assert nao_lidas.json() == []
    await sessao.refresh(alheia)
    assert alheia.read_at is None
