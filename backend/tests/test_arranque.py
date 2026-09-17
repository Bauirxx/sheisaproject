"""Inicialização da plataforma (`services/bootstrap.py`, `manage init`).

O arranque promete duas coisas que puxam em sentidos opostos, e ambas importam:

* **acrescentar permissões novas** — quando uma actualização traz uma
  funcionalidade com permissão própria, os perfis que a devem ter recebem-na;
* **não desfazer decisões do administrador** — uma permissão que ele retirou de
  um perfil não volta a ser posta por correr o arranque outra vez.

Só a segunda era cumprida. A permissão nova era criada, mas nenhum perfil já
existente a recebia — nem o ADMINISTRADOR, que é definido como "todas". Numa
instalação actualizada, a funcionalidade nova ficava recusada a toda a gente,
porque as rotas verificam as permissões guardadas na base de dados. A base de
desenvolvimento não o mostrava por ter sido inicializada depois de todas as
permissões actuais existirem.

A distinção que resolve as duas promessas: uma permissão **criada nesta
execução** nunca pode ter sido retirada por ninguém.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.permissions import ROLE_PERMISSIONS, RoleName
from app.core.permissions import Permission as P
from app.core.security import verify_password
from app.models.identity import Permission, Role, Team, User
from app.models.system import AuditLog
from app.schemas.auth import validate_password_strength
from app.services import bootstrap


async def _perfil(sessao, nome: RoleName) -> Role:
    return (await sessao.execute(select(Role).where(Role.name == nome.value))).scalar_one()


async def _perfis_com(sessao, codigo: P) -> set[str]:
    perfis = (await sessao.execute(select(Role))).scalars().all()
    return {r.name for r in perfis if codigo.value in {p.code for p in r.permissions}}


def _perfis_que_devem_ter(codigo: P) -> set[str]:
    return {nome.value for nome, codigos in ROLE_PERMISSIONS.items() if codigo in codigos}


# ------------------------------------------------------ permissões e perfis
async def test_correr_de_novo_nao_cria_nem_altera_nada(sessao):
    """A suite já correu o arranque; uma segunda passagem não encontra trabalho."""
    criadas, actualizadas = await bootstrap.sync_permissions(sessao)
    resultado = await bootstrap.sync_roles(sessao, criadas)

    assert (criadas, actualizadas) == ([], 0)
    assert resultado == (0, len(ROLE_PERMISSIONS), 0)


async def test_uma_permissao_nova_chega_aos_perfis_que_a_devem_ter(sessao):
    """Regressão: numa instalação actualizada, ninguém recebia a permissão nova."""
    codigo = P.RECOMMENDATIONS_DECIDE
    # Simula uma instalação feita antes de esta permissão existir.
    antiga = (
        await sessao.execute(select(Permission).where(Permission.code == codigo.value))
    ).scalar_one()
    for perfil in (await sessao.execute(select(Role))).scalars().all():
        if antiga in perfil.permissions:
            perfil.permissions.remove(antiga)
    await sessao.flush()
    await sessao.delete(antiga)
    await sessao.flush()
    assert await _perfis_com(sessao, codigo) == set()

    criadas, _ = await bootstrap.sync_permissions(sessao)
    _, _, atribuidas = await bootstrap.sync_roles(sessao, criadas)

    assert criadas == [codigo.value]
    esperados = _perfis_que_devem_ter(codigo)
    assert await _perfis_com(sessao, codigo) == esperados
    assert atribuidas == len(esperados)


async def test_permissao_retirada_pelo_administrador_nao_volta(sessao):
    """Correr o arranque não pode desfazer uma decisão de segurança."""
    gestor = await _perfil(sessao, RoleName.GESTOR)
    fechar = next(p for p in gestor.permissions if p.code == P.INCIDENTS_CLOSE.value)
    gestor.permissions.remove(fechar)
    await sessao.flush()

    for _ in range(2):
        criadas, _ = await bootstrap.sync_permissions(sessao)
        await bootstrap.sync_roles(sessao, criadas)

    await sessao.refresh(gestor)
    assert P.INCIDENTS_CLOSE.value not in {p.code for p in gestor.permissions}


async def test_descricao_desactualizada_e_corrigida(sessao):
    permissao = (
        await sessao.execute(select(Permission).where(Permission.code == P.AUDIT_READ.value))
    ).scalar_one()
    permissao.description = "texto antigo"
    await sessao.flush()

    criadas, actualizadas = await bootstrap.sync_permissions(sessao)

    assert (criadas, actualizadas) == ([], 1)
    assert permissao.description != "texto antigo"


# ------------------------------------------------- conta de administração
async def test_administrador_com_palavra_passe_gerada_tem_de_a_mudar(sessao):
    utilizador, gerada = await bootstrap.ensure_admin(sessao, email="  Chefe@SOC.local ")

    assert utilizador.email == "chefe@soc.local"
    assert gerada is not None
    assert validate_password_strength(gerada) == gerada
    assert verify_password(gerada, utilizador.password_hash)
    assert utilizador.must_change_password is True
    await sessao.refresh(utilizador, ["role"])
    assert utilizador.role.name == RoleName.ADMINISTRADOR.value

    auditoria = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "CRIAR_UTILIZADOR", AuditLog.resource_id == utilizador.id
            )
        )
    ).scalar_one()
    assert auditoria.origin == "cli"


async def test_palavra_passe_fornecida_nao_e_devolvida_nem_obriga_a_mudar(sessao):
    utilizador, gerada = await bootstrap.ensure_admin(
        sessao, email="operacoes@soc.local", password="Fornecida2026Segura"
    )

    assert gerada is None
    assert utilizador.must_change_password is False
    assert verify_password("Fornecida2026Segura", utilizador.password_hash)


async def test_administrador_existente_nao_e_recriado_nem_revela_nada(sessao):
    primeiro, _ = await bootstrap.ensure_admin(sessao, email="unico@soc.local")
    segundo, gerada = await bootstrap.ensure_admin(sessao, email="UNICO@soc.local")

    assert segundo.id == primeiro.id
    assert gerada is None
    contas = (
        await sessao.execute(select(User).where(User.email == "unico@soc.local"))
    ).scalars().all()
    assert len(contas) == 1


def test_palavras_passe_geradas_cumprem_a_politica_e_evitam_caracteres_ambiguos():
    for _ in range(200):
        gerada = bootstrap._generate_password()
        assert len(gerada) == 20
        assert validate_password_strength(gerada) == gerada
        assert not set(gerada) & set("0O1lI"), gerada


async def test_a_equipa_por_omissao_existe_uma_so_vez(sessao):
    primeira = await bootstrap.ensure_default_team(sessao)
    segunda = await bootstrap.ensure_default_team(sessao)

    assert segunda.id == primeira.id
    equipas = (await sessao.execute(select(Team).where(Team.name == "SOC"))).scalars().all()
    assert len(equipas) == 1
