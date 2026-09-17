"""Estratégias de correlação que `test_correlacao.py` não exercitava.

`SEQUENCIA_TEMPORAL` e `ACTIVO_ALVO` não tinham nenhum teste, nem os filtros de
condições das regras. Dois defeitos:

* **A sequência juntava alertas sem relação nenhuma.** Os candidatos eram todos
  os alertas da janela, fosse qual fosse o activo ou o atacante. Uma falha de
  autenticação num servidor, uma execução noutro e um trojan num terceiro, de
  três origens diferentes, formavam uma "cadeia de ataque em progressão" — e a
  regra semeada que usa esta estratégia tem a prioridade mais alta e dá
  severidade CRITICA. Uma progressão é de *uma* actividade: os alertas têm de
  partilhar o activo ou algum artefacto observado.
* **Um alerta sem regra contava como uma detecção distinta** na convergência
  num activo: `None` entrava no conjunto de regras distintas.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.enums import CorrelationOutcome, CorrelationStrategy, ObservationRole
from app.correlation.engine import correlate_alert
from app.models.catalog import Asset
from tests.test_correlacao import _alerta_com_indicadores, _regra

CADEIA = ["authentication", "execution", "trojan"]


def _origem(ip: str) -> list[dict]:
    return [{"tipo": "IP", "valor": ip, "papel": ObservationRole.ORIGEM.value}]


async def _activo(sessao, identificador: str) -> Asset:
    activo = Asset(identifier=identificador, name=identificador)
    sessao.add(activo)
    await sessao.flush()
    return activo


async def _etapas(sessao, *, indicadores_por_etapa, activos=(None, None, None)):
    """Três alertas pela ordem da cadeia, com cinco minutos entre cada um."""
    inicio = datetime.now(UTC) - timedelta(minutes=30)
    alertas = []
    for numero, (etiqueta, indicadores, activo) in enumerate(
        zip(CADEIA, indicadores_por_etapa, activos, strict=True)
    ):
        alertas.append(
            await _alerta_com_indicadores(
                sessao,
                indicadores=indicadores,
                quando=inicio + timedelta(minutes=5 * numero),
                tags=[f"{etiqueta}_detectada"],
                rule_id=f"regra-{etiqueta}",
                dedup=f"cadeia-{etiqueta}-{numero}-{id(indicadores)}",
                asset_id=activo.id if activo else None,
            )
        )
    return alertas


# ------------------------------------------------------ sequência temporal
async def test_etapas_sem_relacao_entre_si_nao_formam_uma_cadeia(sessao):
    """Regressão: três ataques independentes eram fundidos num incidente CRITICO."""
    await _regra(sessao, CorrelationStrategy.SEQUENCIA_TEMPORAL, sequencia=CADEIA,
                 minimo=3, janela=180)
    servidores = [await _activo(sessao, f"srv-{n}") for n in ("a", "b", "c")]
    *_, ultimo = await _etapas(
        sessao,
        indicadores_por_etapa=[_origem("203.0.113.1"), _origem("198.51.100.2"),
                               _origem("192.0.2.3")],
        activos=servidores,
    )

    decisao = await correlate_alert(sessao, ultimo)

    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO, decisao.rationale


async def test_etapas_no_mesmo_activo_formam_uma_cadeia(sessao):
    await _regra(sessao, CorrelationStrategy.SEQUENCIA_TEMPORAL, sequencia=CADEIA,
                 minimo=3, janela=180)
    servidor = await _activo(sessao, "srv-cadeia")
    primeiro, segundo, ultimo = await _etapas(
        sessao,
        indicadores_por_etapa=[_origem("203.0.113.1"), [], _origem("192.0.2.3")],
        activos=[servidor, servidor, servidor],
    )

    decisao = await correlate_alert(sessao, ultimo)

    assert decisao.outcome is CorrelationOutcome.NOVO_INCIDENTE, decisao.rationale
    assert set(decisao.related_alert_ids) == {primeiro.id, segundo.id}
    assert "authentication -> execution -> trojan" in decisao.rationale


async def test_etapas_do_mesmo_atacante_formam_uma_cadeia(sessao):
    """Sem activo registado, é o artefacto do atacante que liga as etapas."""
    await _regra(sessao, CorrelationStrategy.SEQUENCIA_TEMPORAL, sequencia=CADEIA,
                 minimo=3, janela=180)
    atacante = _origem("203.0.113.66")
    *_, ultimo = await _etapas(sessao, indicadores_por_etapa=[atacante, atacante, atacante])

    decisao = await correlate_alert(sessao, ultimo)

    assert decisao.outcome is CorrelationOutcome.NOVO_INCIDENTE, decisao.rationale


async def test_etapas_fora_de_ordem_nao_formam_uma_cadeia(sessao):
    await _regra(sessao, CorrelationStrategy.SEQUENCIA_TEMPORAL,
                 sequencia=list(reversed(CADEIA)), minimo=3, janela=180)
    servidor = await _activo(sessao, "srv-ordem")
    *_, ultimo = await _etapas(
        sessao, indicadores_por_etapa=[[], [], []], activos=[servidor] * 3
    )

    decisao = await correlate_alert(sessao, ultimo)

    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO


# ------------------------------------------------- convergência num activo
async def test_detecções_distintas_no_mesmo_activo_convergem(sessao):
    await _regra(sessao, CorrelationStrategy.ACTIVO_ALVO, minimo=3, janela=120)
    servidor = await _activo(sessao, "srv-convergencia")
    for regra in ("5710", "31103"):
        await _alerta_com_indicadores(sessao, indicadores=[], rule_id=regra,
                                      dedup=f"conv-{regra}", asset_id=servidor.id)
    terceiro = await _alerta_com_indicadores(sessao, indicadores=[], rule_id="86601",
                                             dedup="conv-86601", asset_id=servidor.id)

    decisao = await correlate_alert(sessao, terceiro)

    assert decisao.outcome is CorrelationOutcome.NOVO_INCIDENTE
    assert "3 detecções distintas" in decisao.rationale


async def test_a_mesma_detecao_repetida_nao_e_convergencia(sessao):
    await _regra(sessao, CorrelationStrategy.ACTIVO_ALVO, minimo=2, janela=120)
    servidor = await _activo(sessao, "srv-repeticao")
    await _alerta_com_indicadores(sessao, indicadores=[], rule_id="5710",
                                  dedup="rep-1", asset_id=servidor.id)
    segundo = await _alerta_com_indicadores(sessao, indicadores=[], rule_id="5710",
                                            dedup="rep-2", asset_id=servidor.id)

    assert (await correlate_alert(sessao, segundo)).outcome is CorrelationOutcome.SEM_CORRELACAO


async def test_alerta_sem_regra_nao_conta_como_detecao_distinta(sessao):
    """Regressão: `None` entrava no conjunto e fazia de segunda detecção."""
    await _regra(sessao, CorrelationStrategy.ACTIVO_ALVO, minimo=2, janela=120)
    servidor = await _activo(sessao, "srv-sem-regra")
    await _alerta_com_indicadores(sessao, indicadores=[], rule_id="5710",
                                  dedup="sr-1", asset_id=servidor.id)
    sem_regra = await _alerta_com_indicadores(sessao, indicadores=[], rule_id=None,
                                              dedup="sr-2", asset_id=servidor.id)

    decisao = await correlate_alert(sessao, sem_regra)

    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO, decisao.rationale


# ------------------------------------------------------------- condições
async def test_as_condicoes_da_regra_filtram_o_alerta(sessao):
    atacante = _origem("203.0.113.88")
    await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="cond-1")
    segundo = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="cond-2")

    for condicoes in (
        {"rule_groups_any": ["web_attack"]},
        {"source_kinds": ["SURICATA"]},
        {"triage_score_min": 90},
        {"severity_min": "CRITICA"},
    ):
        regra = await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA,
                             condicoes=condicoes, nome=f"Regra {condicoes}")
        decisao = await correlate_alert(sessao, segundo)
        assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO, condicoes
        regra.is_enabled = False
        await sessao.flush()


async def test_campos_declarados_substituem_os_indicadores(sessao):
    """Uma regra pode correlacionar por colunas do evento em vez dos indicadores."""
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA,
                 campos=["event_type"], minimo=2)
    await _alerta_com_indicadores(sessao, indicadores=[], dedup="campo-1")
    segundo = await _alerta_com_indicadores(sessao, indicadores=[], dedup="campo-2")

    decisao = await correlate_alert(sessao, segundo)

    assert decisao.outcome is CorrelationOutcome.NOVO_INCIDENTE
    assert "authentication_failed" in decisao.rationale
