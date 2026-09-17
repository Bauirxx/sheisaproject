"""Importação do catálogo MITRE ATT&CK (§11).

O catálogo vem do bundle STIX da MITRE e nada é escrito à mão. Os testes usam um
bundle mínimo construído aqui, com a estrutura do verdadeiro — conferida contra a
versão 19.2 guardada em `var/mitre/` (858 `attack-pattern`, 149 revogados, uma
`x-mitre-matrix` com 15 tácticas). Nenhum teste vai à rede: a descarga é exercida
com um transporte HTTP falso.

O que importa fixar não é "as linhas são criadas":

* a ordem das tácticas vem da matriz do bundle, não de uma lista fixa — a
  versão 19 renomeou `defense-evasion` para `stealth` e acrescentou
  `defense-impairment`, e uma lista fixa teria desenhado a cadeia pela ordem
  errada sem erro nenhum;
* a táctica primária de uma técnica é a mais cedo na cadeia, não a primeira
  listada no STIX;
* voltar a carregar actualiza em vez de duplicar — **incluindo** o caso em que
  uma versão nova revoga uma técnica que a anterior trazia válida.
"""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.core.errors import SheisaError
from app.models.catalog import MitreTactic, MitreTechnique
from app.services import mitre_service
from app.services.mitre_service import (
    FALLBACK_TACTIC_ORDER,
    find_technique,
    find_techniques,
    load_attack_data,
)
from tests.conftest import cabecalho


# ------------------------------------------------------------ bundle mínimo
def _referencia(identificador: str) -> list[dict]:
    caminho = identificador.replace(".", "/")
    return [{
        "source_name": "mitre-attack",
        "external_id": identificador,
        "url": f"https://attack.mitre.org/{'tactics' if identificador.startswith('TA') else 'techniques'}/{caminho}",
    }]


def _tactica(identificador: str, nome_curto: str, nome: str, **extra) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{identificador}",
        "name": nome,
        "description": f"Descrição de {nome}.",
        "x_mitre_shortname": nome_curto,
        "external_references": _referencia(identificador),
        **extra,
    }


def _tecnica(identificador: str, nome: str, fases: list[str], **extra) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{identificador}",
        "name": nome,
        "description": f"Descrição de {nome}.",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": fase} for fase in fases
        ],
        "x_mitre_is_subtechnique": "." in identificador,
        "x_mitre_platforms": ["Linux", "Windows"],
        "x_mitre_data_sources": ["Logon Session: Logon Session Creation"],
        "external_references": _referencia(identificador),
        **extra,
    }


def _matriz(*identificadores_de_tactica: str) -> dict:
    return {
        "type": "x-mitre-matrix",
        "id": "x-mitre-matrix--enterprise",
        "name": "Enterprise ATT&CK",
        "tactic_refs": [f"x-mitre-tactic--{t}" for t in identificadores_de_tactica],
    }


TACTICAS = (
    _tactica("TA0001", "initial-access", "Initial Access"),
    _tactica("TA0005", "stealth", "Stealth"),
    _tactica("TA0006", "credential-access", "Credential Access"),
)


def _escrever(tmp_path, *objectos, versao="19.2", nome="bundle.json"):
    caminho = tmp_path / nome
    caminho.write_text(
        json.dumps({
            "type": "bundle",
            "objects": [
                {"type": "x-mitre-collection", "id": "x-mitre-collection--1",
                 "x_mitre_version": versao},
                *objectos,
            ],
        }),
        encoding="utf-8",
    )
    return caminho


def _bundle_base(tmp_path, *extra, versao="19.2", nome="bundle.json"):
    return _escrever(
        tmp_path,
        *TACTICAS,
        _matriz("TA0001", "TA0005", "TA0006"),
        _tecnica("T1078", "Valid Accounts", ["stealth", "initial-access"]),
        _tecnica("T1078.004", "Cloud Accounts", ["initial-access"]),
        _tecnica("T1110", "Brute Force", ["credential-access"]),
        *extra,
        versao=versao,
        nome=nome,
    )


async def _tecnica_na_base(sessao, identificador) -> MitreTechnique:
    return (
        await sessao.execute(
            select(MitreTechnique).where(MitreTechnique.technique_id == identificador)
        )
    ).scalar_one()


async def _ordens(sessao) -> dict[str, int]:
    linhas = await sessao.execute(select(MitreTactic.shortname, MitreTactic.ordering))
    return dict(linhas.all())


# ---------------------------------------------------------------- carregar
async def test_carrega_tacticas_tecnicas_e_subtecnicas(sessao, tmp_path):
    resultado = await load_attack_data(sessao, source_file=_bundle_base(tmp_path))

    assert resultado == {
        "version": "19.2", "tactics": 3, "techniques": 2, "subtechniques": 1,
    }

    sub = await _tecnica_na_base(sessao, "T1078.004")
    assert sub.is_subtechnique is True
    assert sub.parent_technique_id == "T1078"
    assert sub.url == "https://attack.mitre.org/techniques/T1078/004"
    assert sub.attack_version == "19.2"

    pai = await _tecnica_na_base(sessao, "T1078")
    assert pai.is_subtechnique is False
    assert pai.parent_technique_id is None
    assert pai.platforms == ["Linux", "Windows"]


async def test_a_ordem_das_tacticas_vem_da_matriz_do_bundle(sessao, tmp_path):
    """A matriz manda, mesmo quando contradiz a lista de recurso."""
    invertida = _escrever(
        tmp_path, *TACTICAS, _matriz("TA0006", "TA0005", "TA0001"),
    )
    await load_attack_data(sessao, source_file=invertida)

    assert await _ordens(sessao) == {
        "credential-access": 0, "stealth": 1, "initial-access": 2,
    }


async def test_sem_matriz_usa_a_ordem_de_recurso(sessao, tmp_path):
    await load_attack_data(sessao, source_file=_escrever(tmp_path, *TACTICAS))

    assert await _ordens(sessao) == {
        nome: FALLBACK_TACTIC_ORDER.index(nome)
        for nome in ("initial-access", "stealth", "credential-access")
    }


async def test_a_tactica_primaria_e_a_mais_cedo_na_cadeia(sessao, tmp_path):
    """T1078 lista `stealth` primeiro; na cadeia, `initial-access` vem antes."""
    await load_attack_data(sessao, source_file=_bundle_base(tmp_path))

    tecnica = await _tecnica_na_base(sessao, "T1078")
    acesso_inicial = (
        await sessao.execute(select(MitreTactic).where(MitreTactic.tactic_id == "TA0001"))
    ).scalar_one()

    assert tecnica.tactic_id == acesso_inicial.id
    assert tecnica.tactic_shortnames == ["stealth", "initial-access"]


async def test_ignora_revogados_e_fases_de_outras_cadeias(sessao, tmp_path):
    caminho = _bundle_base(
        tmp_path,
        _tactica("TA9999", "obsoleta", "Táctica obsoleta", x_mitre_deprecated=True),
        _tecnica("T1086", "PowerShell", ["stealth"], revoked=True),
        _tecnica("T1099", "Timestomp", ["stealth"], x_mitre_deprecated=True),
        {
            **_tecnica("T1200", "Hardware Additions", []),
            "kill_chain_phases": [
                {"kill_chain_name": "outra-cadeia", "phase_name": "initial-access"},
            ],
        },
    )
    resultado = await load_attack_data(sessao, source_file=caminho)

    assert resultado["tactics"] == 3, "a táctica depreciada foi carregada"
    identificadores = set(
        (await sessao.execute(select(MitreTechnique.technique_id))).scalars()
    )
    assert "T1086" not in identificadores, "a técnica revogada foi carregada"

    # Depreciada não é revogada: fica, marcada, para não partir mapeamentos antigos.
    depreciada = await _tecnica_na_base(sessao, "T1099")
    assert depreciada.is_deprecated is True

    fora_da_cadeia = await _tecnica_na_base(sessao, "T1200")
    assert fora_da_cadeia.tactic_shortnames == []
    assert fora_da_cadeia.tactic_id is None


# -------------------------------------------------------------- actualizar
async def test_carregar_de_novo_actualiza_sem_duplicar(sessao, tmp_path):
    await load_attack_data(sessao, source_file=_bundle_base(tmp_path, versao="18.1"))
    antes = (
        await sessao.execute(select(func.count()).select_from(MitreTechnique))
    ).scalar_one()

    # A versão nova renomeia uma táctica mantendo o identificador — foi o que a
    # versão 19 fez a TA0005 — e muda o nome de uma técnica.
    nova = _escrever(
        tmp_path,
        _tactica("TA0001", "initial-access", "Initial Access"),
        _tactica("TA0005", "stealth", "Stealth"),
        _tactica("TA0006", "credential-access", "Credential Access"),
        _matriz("TA0001", "TA0005", "TA0006"),
        _tecnica("T1078", "Valid Accounts", ["stealth", "initial-access"]),
        _tecnica("T1078.004", "Cloud Accounts", ["initial-access"]),
        _tecnica("T1110", "Brute Force (renomeada)", ["credential-access"]),
        versao="19.2",
        nome="nova.json",
    )
    await load_attack_data(sessao, source_file=nova)

    depois = (
        await sessao.execute(select(func.count()).select_from(MitreTechnique))
    ).scalar_one()
    assert depois == antes
    renomeada = await _tecnica_na_base(sessao, "T1110")
    assert renomeada.name == "Brute Force (renomeada)"
    assert renomeada.attack_version == "19.2"
    assert (
        await sessao.execute(select(func.count()).select_from(MitreTactic))
    ).scalar_one() == 3


async def test_tecnica_revogada_numa_versao_nova_deixa_de_ser_oferecida(
    cliente, sessao, tmp_path, token_analista
):
    """Regressão: a técnica revogada era saltada e a linha antiga continuava válida.

    Quando a MITRE revoga uma técnica, o objecto mantém o identificador e ganha
    `revoked: true`. A importação saltava-o — correcto numa base vazia, errado numa
    actualização: a técnica carregada da versão anterior continuava a ser
    oferecida no catálogo como válida.
    """
    await load_attack_data(
        sessao, source_file=_bundle_base(tmp_path, _tecnica("T1086", "PowerShell", ["stealth"]))
    )
    await load_attack_data(
        sessao,
        source_file=_bundle_base(
            tmp_path,
            _tecnica("T1086", "PowerShell", ["stealth"], revoked=True),
            nome="revoga.json",
        ),
    )

    assert (await _tecnica_na_base(sessao, "T1086")).is_deprecated is True

    catalogo = await cliente.get(
        "/api/mitre/techniques?q=T1086", headers=cabecalho(token_analista)
    )
    assert catalogo.status_code == 200, catalogo.text
    assert catalogo.json()["total"] == 0, "o catálogo continua a oferecer a técnica revogada"


# -------------------------------------------------------- origem do bundle
async def test_ficheiro_inexistente_da_erro_claro(sessao, tmp_path):
    em_falta = tmp_path / "nao-existe.json"
    with pytest.raises(SheisaError, match="nao-existe.json"):
        await load_attack_data(sessao, source_file=em_falta)


def _sem_rede(*_args, **_kwargs):
    raise AssertionError("a importação foi à rede havendo cópia local")


async def test_usa_a_copia_local_sem_ir_a_rede(sessao, tmp_path, monkeypatch):
    copia = _bundle_base(tmp_path, nome="cache.json")
    monkeypatch.setattr(settings, "mitre_stix_cache", copia)
    monkeypatch.setattr(mitre_service.httpx, "AsyncClient", _sem_rede)

    resultado = await load_attack_data(sessao)
    assert resultado["techniques"] == 2


def _rede_falsa(monkeypatch, *, estado: int, corpo: bytes) -> list[str]:
    pedidos: list[str] = []
    cliente_real = httpx.AsyncClient

    def responder(pedido: httpx.Request) -> httpx.Response:
        pedidos.append(str(pedido.url))
        return httpx.Response(estado, content=corpo)

    def cliente(*args, **kwargs):
        return cliente_real(*args, transport=httpx.MockTransport(responder), **kwargs)

    monkeypatch.setattr(mitre_service.httpx, "AsyncClient", cliente)
    return pedidos


async def test_forcar_descarga_substitui_a_copia_local(sessao, tmp_path, monkeypatch):
    copia = _bundle_base(tmp_path, versao="18.1", nome="cache.json")
    monkeypatch.setattr(settings, "mitre_stix_cache", copia)
    recente = _bundle_base(tmp_path, versao="19.2", nome="recente.json").read_bytes()
    pedidos = _rede_falsa(monkeypatch, estado=200, corpo=recente)

    resultado = await load_attack_data(sessao, force_download=True)

    assert pedidos == [settings.mitre_stix_url]
    assert resultado["version"] == "19.2"
    assert copia.read_bytes() == recente


async def test_sem_copia_local_descarrega_e_cria_a_pasta(sessao, tmp_path, monkeypatch):
    copia = tmp_path / "var" / "mitre" / "enterprise-attack.json"
    monkeypatch.setattr(settings, "mitre_stix_cache", copia)
    corpo = _bundle_base(tmp_path, nome="remoto.json").read_bytes()
    _rede_falsa(monkeypatch, estado=200, corpo=corpo)

    await load_attack_data(sessao)

    assert copia.read_bytes() == corpo


async def test_descarga_falhada_nao_estraga_a_copia_existente(sessao, tmp_path, monkeypatch):
    copia = _bundle_base(tmp_path, versao="18.1", nome="cache.json")
    original = copia.read_bytes()
    monkeypatch.setattr(settings, "mitre_stix_cache", copia)
    _rede_falsa(monkeypatch, estado=503, corpo=b"Service Unavailable")

    with pytest.raises(httpx.HTTPStatusError):
        await load_attack_data(sessao, force_download=True)

    assert copia.read_bytes() == original


# ---------------------------------------------------------------- procurar
async def test_procura_ignora_maiusculas_e_espacos(sessao, tmp_path):
    await load_attack_data(sessao, source_file=_bundle_base(tmp_path))

    assert (await find_technique(sessao, "t1078.004")).name == "Cloud Accounts"
    assert await find_technique(sessao, "T9999") is None

    encontradas = await find_techniques(sessao, ["t1110", " T1078 ", "", "T9999"])
    assert set(encontradas) == {"T1110", "T1078"}
    assert await find_techniques(sessao, []) == {}
