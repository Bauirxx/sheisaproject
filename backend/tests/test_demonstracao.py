"""Cenário de demonstração (§4.14 da monografia).

O que aqui se protege não é que o comando corra sem erro — é que produza um
incidente **com conteúdo**. Um cenário que terminasse com um incidente sem
observações, sem evidência e sem marcos temporais passaria num teste de
execução e falharia na defesa, porque o grafo viria vazio e o relatório também.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select

from app.core.enums import IncidentStatus, SourceKind
from app.models.incident import Incident
from app.models.investigation import Comment, Evidence, Observation
from app.models.telemetry import Alert
from app.services import demo_service


async def _correr(sessao) -> Incident:
    await demo_service.run_demo_scenario(sessao)
    return (
        await sessao.execute(
            select(Incident).where(Incident.is_demo_data.is_(True))
        )
    ).scalars().one()


async def test_o_cenario_percorre_os_dez_passos(sessao):
    relato = await demo_service.run_demo_scenario(sessao)
    texto = "\n".join(relato)
    for numero in range(1, 11):
        assert f"Passo {numero}" in texto, f"o passo {numero} não foi relatado"


async def test_o_incidente_termina_encerrado(sessao):
    incidente = await _correr(sessao)
    assert incidente.status is IncidentStatus.ENCERRADO
    assert incidente.is_demo_data is True


async def test_a_fonte_e_o_suricata(sessao):
    """§4.14: 'o Suricata detecta uma actividade suspeita na rede'."""
    await _correr(sessao)
    alertas = (
        await sessao.execute(select(Alert).where(Alert.is_demo_data.is_(True)))
    ).scalars().all()
    assert alertas
    assert all(a.source_kind is SourceKind.SURICATA for a in alertas)


async def test_a_deduplicacao_e_demonstrada(sessao):
    """Quatro eventos equivalentes têm de dar um alerta, não quatro."""
    await _correr(sessao)
    brute_force = (
        await sessao.execute(
            select(Alert)
            .where(Alert.is_demo_data.is_(True), Alert.rule_id == "2001219")
        )
    ).scalars().one()
    assert brute_force.event_count == 4


async def test_o_incidente_tem_conteudo_investigavel(sessao):
    """Sem observações e evidências, o grafo e o relatório vêm vazios."""
    incidente = await _correr(sessao)

    observacoes = await sessao.scalar(
        select(func.count())
        .select_from(Observation)
        .where(Observation.incident_id == incidente.id)
    )
    evidencias = await sessao.scalar(
        select(func.count())
        .select_from(Evidence)
        .where(Evidence.incident_id == incidente.id)
    )
    comentarios = await sessao.scalar(
        select(func.count())
        .select_from(Comment)
        .where(Comment.incident_id == incidente.id)
    )

    assert observacoes >= 4, "poucas observações para um grafo demonstrável"
    assert evidencias == 1
    assert comentarios >= 1


async def test_os_marcos_temporais_sao_preenchidos(sessao):
    """São eles que alimentam as métricas de resposta dos relatórios."""
    incidente = await _correr(sessao)
    assert incidente.acknowledged_at is not None
    assert incidente.contained_at is not None
    assert incidente.eradicated_at is not None
    assert incidente.resolved_at is not None
    assert incidente.lessons_learned


async def test_dois_alertas_convergem_num_incidente(sessao):
    """A força bruta e a comunicação com C2 pertencem ao mesmo incidente."""
    incidente = await _correr(sessao)
    alertas = (
        await sessao.execute(select(Alert).where(Alert.is_demo_data.is_(True)))
    ).scalars().all()
    assert len(alertas) == 2
    assert all(a.incident_id == incidente.id for a in alertas)


async def test_o_reset_remove_so_os_dados_de_demonstracao(sessao):
    """Um reset que apagasse dados reais seria pior do que não existir."""
    from app.core.references import ReferenceKind, next_reference

    real = Incident(
        reference=await next_reference(sessao, ReferenceKind.INCIDENT),
        title="Incidente real que não é de demonstração",
        description="",
        detected_at=datetime.now(UTC),
        is_demo_data=False,
    )
    sessao.add(real)
    await sessao.flush()
    id_real = real.id

    await _correr(sessao)
    removidos = await demo_service.reset_demo_data(sessao)

    assert removidos["incidentes"] == 1
    assert removidos["alertas"] == 2

    restantes = await sessao.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.is_demo_data.is_(True))
    )
    assert restantes == 0

    sobreviveu = await sessao.get(Incident, id_real)
    assert sobreviveu is not None, "o reset apagou um incidente real"


async def test_correr_duas_vezes_nao_acumula(sessao):
    """`--reset` seguido de nova execução deixa exactamente um cenário."""
    await demo_service.run_demo_scenario(sessao)
    await demo_service.reset_demo_data(sessao)
    await demo_service.run_demo_scenario(sessao)

    incidentes = await sessao.scalar(
        select(func.count())
        .select_from(Incident)
        .where(Incident.is_demo_data.is_(True))
    )
    assert incidentes == 1


async def test_o_resumo_lista_o_que_existe(sessao):
    await _correr(sessao)
    resumo = await demo_service.demo_summary(sessao)
    assert len(resumo["incidentes"]) == 1
    assert len(resumo["alertas"]) == 2
    assert resumo["total"] == 3
