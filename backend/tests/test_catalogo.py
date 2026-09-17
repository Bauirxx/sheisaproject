"""Catálogo: activos, indicadores e consulta MITRE (`api/v1/catalog.py`).

É o que o analista consulta para decidir — que sistema foi atingido, o que já se
sabe de um endereço, que técnica está em causa. Estas rotas não tinham nenhum
teste.

Um defeito foi encontrado ao escrevê-los: **um indicador podia ser registado com
um valor impossível para o seu tipo.** `POST /api/iocs` com
`{"ioc_type": "IP", "value": "banana"}` devolvia 201. A normalização devolvia o
texto tal como vinha quando não o conseguia interpretar, e nada o recusava. Um
"IP" assim entra nas observações, no grafo e — pelo passo de playbook que deduz
o alvo das observações — pode chegar a ser proposto como endereço a bloquear.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.enums import Confidence
from app.models.catalog import MitreTactic, MitreTechnique
from app.models.incident import IncidentTechnique
from app.models.system import AuditLog
from tests.conftest import autenticar, cabecalho


@pytest.fixture
async def token_investigador(cliente) -> str:
    return await autenticar(cliente, "investigador")


async def _registar_activo(cliente, token, **campos) -> dict:
    corpo = {"identifier": "srv-app-01", "name": "Servidor aplicacional", **campos}
    resposta = await cliente.post("/api/assets", json=corpo, headers=cabecalho(token))
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _registar_indicador(cliente, token, tipo, valor):
    return await cliente.post(
        "/api/iocs", json={"ioc_type": tipo, "value": valor}, headers=cabecalho(token)
    )


async def _auditoria(sessao, accao, recurso_id) -> AuditLog:
    return (
        await sessao.execute(
            select(AuditLog).where(AuditLog.action == accao, AuditLog.resource_id == recurso_id)
        )
    ).scalar_one()


# ------------------------------------------------------------------ activos
async def test_registar_activo_fica_auditado_e_consultavel(
    cliente, sessao, token_investigador
):
    activo = await _registar_activo(
        cliente, token_investigador, criticality="CRITICA", wazuh_agent_id="007"
    )

    detalhe = await cliente.get(
        f"/api/assets/{activo['id']}", headers=cabecalho(token_investigador)
    )
    assert detalhe.status_code == 200, detalhe.text
    corpo = detalhe.json()
    assert (corpo["identifier"], corpo["criticality"]) == ("srv-app-01", "CRITICA")
    assert (corpo["incidentes_totais"], corpo["incidentes_activos"]) == (0, 0)

    import uuid

    entrada = await _auditoria(sessao, "CRIAR_ACTIVO", uuid.UUID(activo["id"]))
    assert "CRITICA" in entrada.description


async def test_identificador_de_activo_repetido_da_409(cliente, token_investigador):
    await _registar_activo(cliente, token_investigador)
    repetido = await cliente.post(
        "/api/assets",
        json={"identifier": "srv-app-01", "name": "Outro nome"},
        headers=cabecalho(token_investigador),
    )
    assert repetido.status_code == 409


async def test_o_analista_consulta_mas_nao_regista_activos(cliente, token_analista):
    """`assets:manage` é do investigador e do administrador, não da primeira linha."""
    assert (await cliente.get("/api/assets", headers=cabecalho(token_analista))).status_code == 200
    resposta = await cliente.post(
        "/api/assets",
        json={"identifier": "srv-nao-autorizado", "name": "x"},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 403


async def test_listagem_de_activos_filtra_e_esconde_os_inactivos(cliente, token_investigador):
    await _registar_activo(cliente, token_investigador, identifier="srv-bd-09",
                           criticality="CRITICA", ip_address="10.10.5.99")
    await _registar_activo(cliente, token_investigador, identifier="est-rh-03",
                           criticality="BAIXA")
    await _registar_activo(cliente, token_investigador, identifier="srv-antigo",
                           criticality="CRITICA", is_active=False)

    async def identificadores(consulta: str) -> set[str]:
        resposta = await cliente.get(
            f"/api/assets?{consulta}", headers=cabecalho(token_investigador)
        )
        assert resposta.status_code == 200, resposta.text
        return {a["identifier"] for a in resposta.json()["itens"]}

    assert await identificadores("criticidade=CRITICA") == {"srv-bd-09"}
    assert await identificadores("criticidade=CRITICA&apenas_activos=false") == {
        "srv-bd-09", "srv-antigo",
    }
    assert await identificadores("q=10.10.5.99") == {"srv-bd-09"}


async def test_editar_activo_regista_o_valor_anterior_e_o_novo(
    cliente, sessao, token_investigador
):
    import uuid

    activo = await _registar_activo(cliente, token_investigador, criticality="MEDIA")

    resposta = await cliente.patch(
        f"/api/assets/{activo['id']}", json={"criticality": "ALTA"},
        headers=cabecalho(token_investigador),
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["criticality"] == "ALTA"
    entrada = await _auditoria(sessao, "EDITAR_ACTIVO", uuid.UUID(activo["id"]))
    assert entrada.old_value["criticality"] == "MEDIA"
    assert entrada.new_value["criticality"] == "ALTA"


async def test_activo_inexistente_da_404(cliente, token_analista):
    import uuid

    resposta = await cliente.get(f"/api/assets/{uuid.uuid4()}", headers=cabecalho(token_analista))
    assert resposta.status_code == 404


# --------------------------------------------------------------- indicadores
async def test_o_valor_e_normalizado_e_a_forma_repetida_e_recusada(cliente, token_analista):
    """`EVIL.Example.COM.` e `evil.example.com` são o mesmo indicador."""
    primeiro = await _registar_indicador(cliente, token_analista, "DOMINIO", "EVIL.Example.COM.")
    assert primeiro.status_code == 201, primeiro.text
    assert primeiro.json()["value"] == "evil.example.com"

    repetido = await _registar_indicador(cliente, token_analista, "DOMINIO", "evil.example.com")
    assert repetido.status_code == 409
    assert repetido.json()["erro"]["detalhes"]["ioc_id"] == primeiro.json()["id"]


@pytest.mark.parametrize(
    ("tipo", "valor"),
    [
        ("IP", "banana"),
        ("IP", "999.10.10.10"),
        ("HASH_SHA256", "abc123"),
        ("HASH_MD5", "z" * 32),
        ("HASH_SHA1", "a" * 64),
    ],
    ids=["ip-texto", "ip-fora-da-gama", "sha256-curto", "md5-nao-hexadecimal", "sha1-comprimento"],
)
async def test_valor_impossivel_para_o_tipo_e_recusado(cliente, token_analista, tipo, valor):
    """Regressão: `{"ioc_type": "IP", "value": "banana"}` era aceite com 201."""
    resposta = await _registar_indicador(cliente, token_analista, tipo, valor)

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "VALOR_INVALIDO"


@pytest.mark.parametrize(
    ("tipo", "valor", "guardado"),
    [
        ("IP", " 2001:DB8::1 ", "2001:db8::1"),
        ("HASH_MD5", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
async def test_valores_validos_continuam_aceites(cliente, token_analista, tipo, valor, guardado):
    resposta = await _registar_indicador(cliente, token_analista, tipo, valor)
    assert resposta.status_code == 201, resposta.text
    assert resposta.json()["value"] == guardado


async def test_permitir_um_indicador_exige_motivo_e_tira_o_da_lista(
    cliente, sessao, token_analista
):
    import uuid

    indicador = (await _registar_indicador(cliente, token_analista, "IP", "198.51.100.7")).json()

    sem_motivo = await cliente.post(
        f"/api/iocs/{indicador['id']}/allowlist", json={"is_allowlisted": True},
        headers=cabecalho(token_analista),
    )
    assert sem_motivo.status_code == 422

    permitido = await cliente.post(
        f"/api/iocs/{indicador['id']}/allowlist",
        json={"is_allowlisted": True, "reason": "Scanner de vulnerabilidades autorizado."},
        headers=cabecalho(token_analista),
    )
    assert permitido.status_code == 200, permitido.text
    assert (permitido.json()["is_allowlisted"], permitido.json()["reputation"]) == (True, "BENIGNA")

    async def valores(consulta: str) -> set[str]:
        resposta = await cliente.get(f"/api/iocs?{consulta}", headers=cabecalho(token_analista))
        return {i["value"] for i in resposta.json()["itens"]}

    assert "198.51.100.7" not in await valores("tipo=IP")
    assert "198.51.100.7" in await valores("tipo=IP&incluir_permitidos=true")

    entrada = await _auditoria(sessao, "ALTERAR_LISTA_PERMITIDOS", uuid.UUID(indicador["id"]))
    assert "Scanner de vulnerabilidades autorizado." in entrada.description


async def test_o_detalhe_mostra_onde_o_indicador_foi_observado(cliente, token_analista):
    indicador = (await _registar_indicador(cliente, token_analista, "IP", "203.0.113.150")).json()
    incidente = (
        await cliente.post(
            "/api/incidents",
            json={"title": "Origem hostil observada", "description": "x",
                  "category": "INTRUSAO", "severity": "ALTA"},
            headers=cabecalho(token_analista),
        )
    ).json()
    observacao = await cliente.post(
        f"/api/incidents/{incidente['id']}/observations",
        json={"ioc_id": indicador["id"], "role": "ORIGEM"},
        headers=cabecalho(token_analista),
    )
    assert observacao.status_code == 201, observacao.text

    detalhe = (
        await cliente.get(f"/api/iocs/{indicador['id']}", headers=cabecalho(token_analista))
    ).json()

    assert [i["referencia"] for i in detalhe["incidentes_relacionados"]] == [incidente["reference"]]
    assert detalhe["observacoes_totais"] == 1


# --------------------------------------------------------------------- MITRE
async def test_a_cobertura_separa_o_afirmado_do_que_e_hipotese(
    cliente, sessao, token_analista
):
    """O motor só propõe; o analista afirma. A cobertura não pode misturar os dois."""
    tactica = MitreTactic(tactic_id="TA0006", shortname="credential-access",
                          name="Credential Access", description="", ordering=8)
    sessao.add(tactica)
    await sessao.flush()
    tecnica = MitreTechnique(technique_id="T1110", name="Brute Force", tactic_id=tactica.id,
                             tactic_shortnames=["credential-access"])
    sessao.add(tecnica)
    await sessao.flush()

    async def incidente(titulo) -> dict:
        return (
            await cliente.post(
                "/api/incidents",
                json={"title": titulo, "description": "x", "category": "INTRUSAO",
                      "severity": "ALTA"},
                headers=cabecalho(token_analista),
            )
        ).json()

    afirmado = await incidente("Força bruta confirmada")
    associacao = await cliente.post(
        f"/api/incidents/{afirmado['id']}/techniques",
        json={"technique_id": "t1110", "confidence": "ALTA", "rationale": "Confirmado."},
        headers=cabecalho(token_analista),
    )
    assert associacao.status_code == 201, associacao.text

    import uuid

    hipotese = await incidente("Talvez força bruta")
    sessao.add(IncidentTechnique(
        incident_id=uuid.UUID(hipotese["id"]), technique_id=tecnica.id, is_asserted=False,
        confidence=Confidence.BAIXA, rationale="Inferida pelo motor.", evidence_refs={},
    ))
    await sessao.flush()

    cobertura = await cliente.get("/api/mitre/coverage", headers=cabecalho(token_analista))

    assert cobertura.status_code == 200, cobertura.text
    assert cobertura.json() == [{
        "technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
        "incidentes_afirmados": 1, "incidentes_hipotese": 1,
    }]


async def test_detalhe_de_tecnica_e_tacticas_por_ordem(cliente, sessao, token_analista):
    for identificador, nome_curto, ordem in (
        ("TA0040", "impact", 14), ("TA0001", "initial-access", 2),
    ):
        sessao.add(MitreTactic(tactic_id=identificador, shortname=nome_curto,
                               name=nome_curto, description="", ordering=ordem))
    sessao.add(MitreTechnique(technique_id="T1078", name="Valid Accounts", tactic_shortnames=[]))
    await sessao.flush()

    tacticas = await cliente.get("/api/mitre/tactics", headers=cabecalho(token_analista))
    assert [t["shortname"] for t in tacticas.json()] == ["initial-access", "impact"]

    detalhe = await cliente.get("/api/mitre/techniques/t1078", headers=cabecalho(token_analista))
    assert (detalhe.status_code, detalhe.json()["name"]) == (200, "Valid Accounts")

    em_falta = await cliente.get("/api/mitre/techniques/T9999", headers=cabecalho(token_analista))
    assert em_falta.status_code == 404
