"""Cenário de demonstração do protótipo (§4.14 da monografia).

Percorre os **dez passos** do cenário que vai ser apresentado na defesa:

    1.  O alerta é identificado (o Suricata detecta actividade suspeita).
    2.  O analista regista/converte o alerta num incidente.
    3.  O sistema gera automaticamente o identificador.
    4.  O analista classifica o incidente.
    5.  Define a severidade como Alta.
    6.  Atribui o incidente ao responsável.
    7.  Adiciona comentários e evidências.
    8.  O incidente passa a Em Investigação.
    9.  Depois da resposta, passa a Resolvido.
    10. Após validação, passa a Encerrado.

Três decisões que este ficheiro toma e que convém não desfazer:

**Passa pelo fluxo real da aplicação.** Os alertas entram pelo normalizador do
Suricata e pelo serviço de ingestão, a promoção passa por `promote_alert`, as
transições por `incident_service.transition`. Seria muito mais curto inserir
linhas directamente na base de dados — e o resultado seria uma demonstração de
dados, não do sistema. Um incidente inserido à mão não tem observações
materializadas, não tem marcos temporais, não aparece no grafo e produz um
relatório vazio. Na defesa, a diferença nota-se.

**A fonte é o Suricata.** O §4.14 diz "o Suricata detecta uma actividade
suspeita na rede", e a monografia identifica QRadar, NetScout e Suricata como as
ferramentas do INCM. As verificações manuais feitas durante o desenvolvimento
usaram Wazuh, que é a fonte do laboratório; não é a fonte do cenário.

**Tudo fica marcado com `is_demo_data=True`.** A interface assinala visivelmente
qualquer registo com esta marca, e `demo --reset` remove-os. Dados de
demonstração misturados com dados reais, sem distinção, seriam exactamente o
tipo de coisa que o princípio de não simular existe para evitar.

O actor é a conta de analista, quando existe. Não é cosmética: o módulo de
histórico/auditoria (§4.5.7) é um dos que a defesa mostra, e uma linha temporal
inteira assinada por "sistema" não demonstra nada sobre rastreabilidade.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta

from fastapi import UploadFile
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditContext
from app.core.enums import (
    EvidenceType,
    IncidentCategory,
    IncidentStatus,
    Severity,
    SourceKind,
)
from app.models.identity import Role, User
from app.models.incident import Incident
from app.models.investigation import Comment, Evidence, Observation
from app.models.telemetry import Alert, Event
from app.services import evidence_service, incident_service, ingestion_service

#: Nome da fonte tal como aparece na plataforma. O §4.14 é explícito quanto a
#: ser o Suricata a detectar.
FONTE = "suricata-demo"

#: Rede interna usada no cenário. A monografia usa `192.168.X.X` nos exemplos;
#: aqui usam-se endereços concretos dessa gama para o alvo, e a gama de
#: documentação RFC 5737 para o atacante — que `is_external_ip` reconhece
#: correctamente como externa.
ALVO_IP = "192.168.10.25"
ATACANTE_IP = "203.0.113.45"

#: Infra-estrutura do segundo sinal. O domínio usa `.invalid`, reservado pela
#: RFC 2606 precisamente para exemplos: não resolve e nunca poderá pertencer a
#: ninguém, o que evita pôr um domínio real num cenário de demonstração.
C2_DOMINIO = "atualizacao-sistema.invalid"
C2_IP = "198.51.100.62"


def _eventos_suricata(agora: datetime) -> list[dict]:
    """Eventos EVE JSON do Suricata, no formato que o `eve.json` produz.

    São quatro sinais da mesma actividade, com minutos de intervalo: é o que
    permite demonstrar a deduplicação (quatro eventos, um alerta com
    `event_count=4`) em vez de encher a fila com quatro entradas iguais.
    """
    base = {
        "event_type": "alert",
        "src_ip": ATACANTE_IP,
        "dest_ip": ALVO_IP,
        "src_port": 51443,
        "dest_port": 22,
        "proto": "TCP",
        "in_iface": "eth0",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2001219,
            "rev": 20,
            "signature": "ET SCAN Potential SSH Scan / Brute Force",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
    }
    eventos = []
    for i in range(4):
        instante = agora - timedelta(minutes=18 - i * 4)
        eventos.append(
            {
                **base,
                "timestamp": instante.isoformat(),
                "flow_id": 1700000000000000 + i,
            }
        )
    return eventos


def _evento_c2(agora: datetime) -> dict:
    """Segundo sinal: o servidor visado a contactar infra-estrutura externa.

    Não é decoração. Um incidente com um único indicador dá um grafo de três
    nós, que não demonstra nada sobre investigação. Com este sinal o grafo
    passa a ligar o servidor ao domínio e ao endereço de comando e controlo —
    que é a pergunta a que o grafo investigativo existe para responder: "o que
    mais está relacionado com isto?".

    A categoria contém "trojan", pelo que o normalizador eleva a severidade um
    grau acima da que a assinatura declara. É comportamento real do motor, e
    vale a pena mostrá-lo.
    """
    instante = agora - timedelta(minutes=6)
    return {
        "event_type": "alert",
        "timestamp": instante.isoformat(),
        "flow_id": 1700000000000900,
        "src_ip": ALVO_IP,
        "dest_ip": C2_IP,
        "src_port": 44120,
        "dest_port": 80,
        "proto": "TCP",
        "in_iface": "eth0",
        "app_proto": "http",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2028371,
            "rev": 3,
            "signature": "ET MALWARE Observed Suspicious HTTP Beacon",
            "category": "A Network Trojan was detected",
            "severity": 2,
        },
        "http": {
            "hostname": C2_DOMINIO,
            "url": "/api/v2/checkin",
            "http_user_agent": "Mozilla/5.0 (compatible; updater/1.0)",
            "http_method": "POST",
            "status": 200,
        },
    }


#: Conteúdo da evidência anexada no passo 7. É um extracto de `auth.log`
#: coerente com o alerta: mesma origem, mesmo serviço, mesma janela temporal.
#: Uma evidência que não case com o alerta faz a demonstração perder o ponto.
def _extracto_de_log(agora: datetime) -> bytes:
    linhas = []
    for i in range(12):
        instante = agora - timedelta(minutes=18 - i)
        linhas.append(
            f"{instante.strftime('%b %d %H:%M:%S')} srv-app-01 sshd[{2400 + i}]: "
            f"Failed password for invalid user admin from {ATACANTE_IP} "
            f"port {51443 + i} ssh2"
        )
    linhas.append(
        f"{agora.strftime('%b %d %H:%M:%S')} srv-app-01 sshd[2412]: "
        f"Disconnecting invalid user admin {ATACANTE_IP}: "
        f"Too many authentication failures"
    )
    return ("\n".join(linhas) + "\n").encode("utf-8")


async def _contexto(session: AsyncSession) -> AuditContext:
    """Contexto de auditoria em nome do analista, se existir algum."""
    resultado = await session.execute(
        select(User)
        .join(Role, Role.id == User.role_id)
        .where(Role.name == "ANALISTA_SOC", User.is_active.is_(True))
        .order_by(User.created_at)
        .limit(1)
    )
    analista = resultado.scalar_one_or_none()
    if analista is None:
        return AuditContext(
            actor_email="sistema", is_system=True, origin="cli",
        )
    return AuditContext(
        actor_id=analista.id,
        actor_email=analista.email,
        actor_role="ANALISTA_SOC",
        is_system=False,
        origin="cli",
    )


async def _responsavel(session: AsyncSession) -> User | None:
    """Quem recebe o incidente no passo 6."""
    resultado = await session.execute(
        select(User)
        .join(Role, Role.id == User.role_id)
        .where(Role.name.in_(["ANALISTA_SOC", "INVESTIGADOR"]), User.is_active.is_(True))
        .order_by(User.created_at)
        .limit(1)
    )
    return resultado.scalar_one_or_none()


async def reset_demo_data(session: AsyncSession) -> dict[str, int]:
    """Remove os dados de demonstração, e só esses.

    A ordem importa: as dependências são apagadas antes dos incidentes e dos
    alertas. Os registos de auditoria **não** são removidos — a tabela é
    append-only por construção, e é assim que deve ser. Ficam lá como registo
    de que houve uma demonstração, o que é preferível a uma auditoria com
    buracos.
    """
    incidentes = [
        i
        for (i,) in (
            await session.execute(
                select(Incident.id).where(Incident.is_demo_data.is_(True))
            )
        ).all()
    ]
    alertas = [
        a
        for (a,) in (
            await session.execute(select(Alert.id).where(Alert.is_demo_data.is_(True)))
        ).all()
    ]

    removidos = {"incidentes": len(incidentes), "alertas": len(alertas)}

    if incidentes:
        # As evidências têm ficheiros em disco; apagá-los antes das linhas.
        ficheiros = (
            await session.execute(
                select(Evidence).where(Evidence.incident_id.in_(incidentes))
            )
        ).scalars().all()
        for evidencia in ficheiros:
            caminho = evidence_service.absolute_path_for(evidencia)
            if caminho.exists():
                caminho.unlink()
        removidos["evidencias"] = len(ficheiros)

        for modelo in (Evidence, Comment, Observation):
            await session.execute(
                delete(modelo).where(modelo.incident_id.in_(incidentes))
            )

    if alertas:
        await session.execute(delete(Event).where(Event.alert_id.in_(alertas)))
        # Solta os alertas dos incidentes antes de apagar uns e outros.
        await session.execute(
            Alert.__table__.update()
            .where(Alert.id.in_(alertas))
            .values(incident_id=None)
        )
        await session.execute(delete(Alert).where(Alert.id.in_(alertas)))

    if incidentes:
        await session.execute(delete(Incident).where(Incident.id.in_(incidentes)))

    await session.flush()
    return removidos


async def run_demo_scenario(
    session: AsyncSession, *, reset: bool = False
) -> list[str]:
    """Executa os dez passos do §4.14 e devolve o relato de cada um."""
    relato: list[str] = []
    agora = datetime.now(UTC)

    if reset:
        removidos = await reset_demo_data(session)
        relato.append(
            "Dados de demonstração anteriores removidos: "
            + ", ".join(f"{n} {k}" for k, n in removidos.items() if n)
            if any(removidos.values())
            else "Não havia dados de demonstração anteriores."
        )

    ctx = await _contexto(session)
    actor = ctx.actor_email or "sistema"

    # ---------------------------------------------- 1. o alerta é identificado
    resultados = await ingestion_service.ingest_batch(
        session,
        ctx,
        _eventos_suricata(agora),
        source_name=FONTE,
        source_kind=SourceKind.SURICATA,
        is_demo=True,
    )
    aceites = [r for r in resultados if getattr(r, "alert_id", None)]
    if not aceites:
        raise RuntimeError(
            "A ingestão não produziu nenhum alerta. O cenário não pode "
            "continuar sobre dados que não existem."
        )

    alerta = await session.get(Alert, aceites[0].alert_id)
    relato.append(
        f"Passo 1 — O Suricata detectou actividade suspeita: {len(resultados)} "
        f"eventos deduplicados em {alerta.reference} "
        f"(severidade {alerta.severity.value}, pontuação de triagem "
        f"{alerta.triage_score}/100, {alerta.event_count} eventos)."
    )

    # ------------------------------ 2 e 3. conversão em incidente e referência
    incidente = await incident_service.promote_alert(
        session,
        ctx,
        alert=alerta,
        title="Possível tentativa de intrusão por SSH",
        rationale=(
            "Varrimento e tentativas de autenticação com origem externa contra "
            "o serviço SSH de um servidor interno."
        ),
        is_demo=True,
    )
    relato.append(
        f"Passo 2 — {actor} converteu {alerta.reference} num incidente."
    )
    relato.append(
        f"Passo 3 — O sistema gerou o identificador {incidente.reference}."
    )

    # Segundo sinal, ligado ao mesmo incidente. O §4.14 resume a detecção a um
    # passo, mas a plataforma sabe associar alertas a um incidente existente
    # (§4.5, "gestão de alertas") e é isso que dá conteúdo ao grafo e à
    # investigação. Fica registado como passo 3a para não desalinhar a
    # numeração do guião.
    resultado_c2 = await ingestion_service.ingest_batch(
        session, ctx, [_evento_c2(agora)],
        source_name=FONTE, source_kind=SourceKind.SURICATA, is_demo=True,
    )
    alerta_c2_id = next(
        (r.alert_id for r in resultado_c2 if getattr(r, "alert_id", None)), None
    )
    if alerta_c2_id is not None:
        alerta_c2 = await session.get(Alert, alerta_c2_id)
        if alerta_c2.incident_id != incidente.id:
            observacoes = await incident_service.link_alert(
                session, ctx,
                alert=alerta_c2, incident=incidente,
                rationale=(
                    f"Mesmo activo ({ALVO_IP}) a contactar infra-estrutura externa "
                    f"pouco depois das tentativas de autenticação."
                ),
            )
        else:
            observacoes = 0
        relato.append(
            f"Passo 3a — Segundo sinal do Suricata ({alerta_c2.reference}, "
            f"severidade {alerta_c2.severity.value}) ligado a "
            f"{incidente.reference}: comunicação de {ALVO_IP} para "
            f"{C2_DOMINIO}. {observacoes} observação(ões) materializada(s)."
        )

    # --------------------------------------------------- 4 e 5. classificação
    #
    # A promoção já propõe categoria e severidade a partir dos grupos de regra
    # e da severidade da fonte. O relato distingue **confirmar** de **corrigir**
    # em vez de anunciar uma alteração que pode não ter acontecido: "classificado
    # como X (era X)" daria a impressão de trabalho onde não houve nenhum, e
    # esconderia o facto — que é favorável — de a plataforma já ter acertado.
    categoria_anterior = incidente.category
    severidade_anterior = incidente.severity
    incidente.category = IncidentCategory.TENTATIVA_INTRUSAO
    incidente.severity = Severity.ALTA
    await session.flush()

    relato.append(
        f"Passo 4 — Classificação confirmada como {incidente.category.value}: "
        f"foi o que a promoção já tinha inferido dos grupos de regra."
        if categoria_anterior == incidente.category
        else f"Passo 4 — Reclassificado de {categoria_anterior.value} para "
             f"{incidente.category.value}."
    )
    relato.append(
        f"Passo 5 — Severidade confirmada como {incidente.severity.value}: "
        f"coincide com a que o Suricata reportou."
        if severidade_anterior == incidente.severity
        else f"Passo 5 — Severidade alterada de {severidade_anterior.value} para "
             f"{incidente.severity.value}."
    )

    # ------------------------------------------------------- 6. atribuição
    responsavel = await _responsavel(session)
    if responsavel is not None:
        await incident_service.assign(
            session, ctx, incident=incidente, assignee_id=responsavel.id
        )
        relato.append(f"Passo 6 — Atribuído a {responsavel.email}.")
    else:
        relato.append(
            "Passo 6 — Não existe nenhuma conta de analista para receber o "
            "incidente; a atribuição foi omitida em vez de simulada."
        )

    # -------------------------------------------- 7. comentários e evidências
    await incident_service.add_comment(
        session,
        ctx,
        incident=incidente,
        body=(
            f"Confirmada a origem externa {ATACANTE_IP}. O padrão é compatível "
            f"com varrimento seguido de tentativas de autenticação contra "
            f"{ALVO_IP}:22. Recolhido o extracto de auth.log do servidor."
        ),
    )
    conteudo = _extracto_de_log(agora)
    evidencia = await evidence_service.store_evidence(
        session,
        ctx,
        incident=incidente,
        upload=UploadFile(
            file=io.BytesIO(conteudo),
            filename="auth.log",
            size=len(conteudo),
        ),
        name="Extracto de auth.log do servidor afectado",
        description=(
            "Tentativas de autenticação falhadas registadas pelo sshd na janela "
            "do alerta."
        ),
        evidence_type=EvidenceType.LOG,
        source=f"srv-app-01 ({ALVO_IP})",
        collected_at=agora,
    )
    relato.append(
        f"Passo 7 — Comentário registado e evidência anexada "
        f"({evidencia.name}, SHA-256 {evidencia.sha256[:16]}…)."
    )

    # --------------------------------------------------- 8, 9 e 10. ciclo de vida
    #
    # O ciclo de vida da plataforma é mais detalhado do que o resumo de dez
    # passos do §4.14, e segue o §4.9 da própria monografia:
    #
    #     NOVO → ABERTO → EM INVESTIGAÇÃO → EM RESPOSTA → RESOLVIDO → ENCERRADO
    #
    # Duas diferenças, ambas a favor do detalhe:
    #
    # * ABERTO é um estado intermédio real ("incidente validado, necessita de
    #   tratamento", §4.9) e o grafo de transições não deixa saltá-lo;
    # * "EM RESPOSTA" está decomposto em contenção, erradicação e recuperação,
    #   porque cada uma marca um instante distinto e é desses instantes que
    #   saem as métricas de resposta dos relatórios.
    #
    # Percorrê-los todos não afasta a demonstração do guião: enriquece o passo
    # 9, que o guião resume como "depois da resposta".
    await incident_service.transition(
        session, ctx, incident=incidente, new_status=IncidentStatus.ABERTO,
        note="Incidente validado; necessita de tratamento.",
    )
    await incident_service.transition(
        session, ctx, incident=incidente, new_status=IncidentStatus.INVESTIGACAO,
        note="Início da investigação da actividade detectada.",
    )
    relato.append(
        f"Passo 8 — {incidente.reference} passou por {IncidentStatus.ABERTO.value} "
        f"e está em {IncidentStatus.INVESTIGACAO.value}."
    )

    for estado, nota in (
        (IncidentStatus.CONTENCAO, f"Origem {ATACANTE_IP} bloqueada no perímetro."),
        (IncidentStatus.ERRADICACAO, "Credenciais da conta visada rodadas."),
        (IncidentStatus.RECUPERACAO, "Serviço SSH reposto com acesso restringido."),
    ):
        await incident_service.transition(
            session, ctx, incident=incidente, new_status=estado, note=nota
        )
    relato.append(
        "Passo 9a — Resposta executada: contenção, erradicação e recuperação "
        "(cada uma com o seu instante registado, que é o que alimenta as "
        "métricas de resposta)."
    )

    await incident_service.transition(
        session,
        ctx,
        incident=incidente,
        new_status=IncidentStatus.RESOLVIDO,
        resolution_summary=(
            f"Origem {ATACANTE_IP} bloqueada no perímetro e credenciais da conta "
            f"visada rodadas. Não se confirmou acesso bem sucedido: todas as "
            f"tentativas registadas falharam a autenticação."
        ),
    )
    relato.append(
        f"Passo 9b — Após a resposta, passou a {IncidentStatus.RESOLVIDO.value}."
    )

    incidente.lessons_learned = (
        "O serviço SSH do servidor estava acessível a partir do exterior sem "
        "restrição de origem. Recomenda-se limitar o acesso à rede de gestão e "
        "activar bloqueio automático por tentativas falhadas."
    )
    await incident_service.transition(
        session, ctx, incident=incidente, new_status=IncidentStatus.ENCERRADO,
        note="Validado e documentado.",
    )
    relato.append(
        f"Passo 10 — Após validação, passou a {IncidentStatus.ENCERRADO.value}."
    )

    relato.append("")
    relato.append(
        f"Cenário concluído. {incidente.reference} percorreu os dez passos do "
        f"§4.14 pelo fluxo real da aplicação; todos os registos ficam marcados "
        f"como dados de demonstração e podem ser removidos com "
        f"`manage demo --reset`."
    )
    relato.append(
        "Nota para a apresentação: os tempos de reconhecimento, contenção e "
        "resolução aparecem quase iguais porque o cenário inteiro corre em "
        "segundos. Os marcos são reais — foram gravados no instante de cada "
        "transição —, mas o intervalo entre eles não representa o de um "
        "incidente conduzido por pessoas. Preferiu-se dizê-lo a antedatar os "
        "marcos para produzir métricas mais apresentáveis."
    )
    return relato


async def demo_summary(session: AsyncSession) -> dict[str, int | list[str]]:
    """Que dados de demonstração existem neste momento."""
    incidentes = (
        await session.execute(
            select(Incident.reference).where(Incident.is_demo_data.is_(True))
        )
    ).scalars().all()
    alertas = (
        await session.execute(
            select(Alert.reference).where(Alert.is_demo_data.is_(True))
        )
    ).scalars().all()
    return {
        "incidentes": list(incidentes),
        "alertas": list(alertas),
        "total": len(incidentes) + len(alertas),
    }
