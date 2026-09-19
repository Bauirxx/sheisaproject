"""Vocabulário de domínio.

Os valores persistidos são strings estáveis em maiúsculas (independentes de
idioma) — a tradução para português acontece na interface. Isto evita que uma
mudança de redacção na UI obrigue a uma migração de dados.
"""

from __future__ import annotations

from enum import StrEnum


# ---------------------------------------------------------------- severidade
class Severity(StrEnum):
    INFO = "INFO"
    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"
    CRITICA = "CRITICA"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.BAIXA: 1,
    Severity.MEDIA: 2,
    Severity.ALTA: 3,
    Severity.CRITICA: 4,
}


class Priority(StrEnum):
    P4 = "P4"  # planeada
    P3 = "P3"  # normal
    P2 = "P2"  # elevada
    P1 = "P1"  # urgente

    @property
    def rank(self) -> int:
        return {Priority.P4: 0, Priority.P3: 1, Priority.P2: 2, Priority.P1: 3}[self]


class Confidence(StrEnum):
    """Confiança numa asserção (classificação, IOC, técnica MITRE inferida)."""

    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"
    CONFIRMADA = "CONFIRMADA"


# --------------------------------------------------------------- ciclo de vida
class IncidentStatus(StrEnum):
    NOVO = "NOVO"
    ABERTO = "ABERTO"
    TRIAGEM = "TRIAGEM"
    INVESTIGACAO = "INVESTIGACAO"
    CONTENCAO = "CONTENCAO"
    ERRADICACAO = "ERRADICACAO"
    RECUPERACAO = "RECUPERACAO"
    RESOLVIDO = "RESOLVIDO"
    ENCERRADO = "ENCERRADO"
    SUSPENSO = "SUSPENSO"
    DUPLICADO = "DUPLICADO"
    FALSO_POSITIVO = "FALSO_POSITIVO"
    ESCALADO = "ESCALADO"


#: Grafo de transições permitidas (§7 - "o ciclo de vida deverá ser configurável").
#: Editar este mapa é a forma suportada de adaptar o ciclo de vida à organização;
#: o serviço de incidentes valida contra ele, pelo que nenhuma transição não
#: declarada é possível - nem pela UI, nem por chamada directa à API.
INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NOVO: frozenset({
        IncidentStatus.ABERTO, IncidentStatus.TRIAGEM,
        IncidentStatus.FALSO_POSITIVO, IncidentStatus.DUPLICADO,
    }),
    IncidentStatus.ABERTO: frozenset({
        IncidentStatus.TRIAGEM, IncidentStatus.INVESTIGACAO, IncidentStatus.SUSPENSO,
        IncidentStatus.ESCALADO, IncidentStatus.FALSO_POSITIVO, IncidentStatus.DUPLICADO,
    }),
    IncidentStatus.TRIAGEM: frozenset({
        IncidentStatus.INVESTIGACAO, IncidentStatus.ABERTO, IncidentStatus.SUSPENSO,
        IncidentStatus.ESCALADO, IncidentStatus.FALSO_POSITIVO, IncidentStatus.DUPLICADO,
    }),
    IncidentStatus.INVESTIGACAO: frozenset({
        IncidentStatus.CONTENCAO, IncidentStatus.RESOLVIDO, IncidentStatus.SUSPENSO,
        IncidentStatus.ESCALADO, IncidentStatus.FALSO_POSITIVO, IncidentStatus.DUPLICADO,
    }),
    IncidentStatus.CONTENCAO: frozenset({
        IncidentStatus.ERRADICACAO, IncidentStatus.INVESTIGACAO,
        IncidentStatus.SUSPENSO, IncidentStatus.ESCALADO,
    }),
    IncidentStatus.ERRADICACAO: frozenset({
        IncidentStatus.RECUPERACAO, IncidentStatus.CONTENCAO,
        IncidentStatus.SUSPENSO, IncidentStatus.ESCALADO,
    }),
    IncidentStatus.RECUPERACAO: frozenset({
        IncidentStatus.RESOLVIDO, IncidentStatus.ERRADICACAO, IncidentStatus.SUSPENSO,
    }),
    IncidentStatus.RESOLVIDO: frozenset({
        IncidentStatus.ENCERRADO, IncidentStatus.INVESTIGACAO,  # reabertura
    }),
    # Estado terminal. Reabrir exige criar um incidente relacionado - preserva a
    # integridade do registo histórico, ao contrário do merge destrutivo do RTIR.
    IncidentStatus.ENCERRADO: frozenset(),
    IncidentStatus.SUSPENSO: frozenset({
        IncidentStatus.ABERTO, IncidentStatus.TRIAGEM, IncidentStatus.INVESTIGACAO,
        IncidentStatus.CONTENCAO, IncidentStatus.ERRADICACAO, IncidentStatus.RECUPERACAO,
    }),
    IncidentStatus.DUPLICADO: frozenset({IncidentStatus.ENCERRADO}),
    IncidentStatus.FALSO_POSITIVO: frozenset({
        IncidentStatus.ENCERRADO, IncidentStatus.ABERTO,  # reclassificação
    }),
    IncidentStatus.ESCALADO: frozenset({
        IncidentStatus.INVESTIGACAO, IncidentStatus.CONTENCAO,
        IncidentStatus.RESOLVIDO, IncidentStatus.SUSPENSO,
    }),
}

#: Estados em que o incidente já não consome atenção operacional.
INCIDENT_TERMINAL_STATUSES = frozenset({
    IncidentStatus.ENCERRADO, IncidentStatus.FALSO_POSITIVO, IncidentStatus.DUPLICADO,
})

#: Estados considerados "activos" para efeitos de painel e carga por analista.
INCIDENT_ACTIVE_STATUSES = frozenset(
    s for s in IncidentStatus
    if s not in INCIDENT_TERMINAL_STATUSES and s != IncidentStatus.RESOLVIDO
)


class AlertStatus(StrEnum):
    """Ciclo de vida de triagem do alerta.

    Deliberadamente distinto do ciclo do incidente: o alerta é uma asserção de
    detecção, não uma ocorrência confirmada. Esta separação é o que impede que
    cada alerta se torne automaticamente um incidente (§6).
    """

    NOVO = "NOVO"
    EM_TRIAGEM = "EM_TRIAGEM"
    CORRELACIONADO = "CORRELACIONADO"   # ligado a um incidente existente
    PROMOVIDO = "PROMOVIDO"             # originou um incidente novo
    DESCARTADO = "DESCARTADO"           # sem relevância operacional
    FALSO_POSITIVO = "FALSO_POSITIVO"
    DUPLICADO = "DUPLICADO"


ALERT_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NOVO: frozenset({
        AlertStatus.EM_TRIAGEM, AlertStatus.CORRELACIONADO, AlertStatus.PROMOVIDO,
        AlertStatus.DESCARTADO, AlertStatus.FALSO_POSITIVO, AlertStatus.DUPLICADO,
    }),
    AlertStatus.EM_TRIAGEM: frozenset({
        AlertStatus.CORRELACIONADO, AlertStatus.PROMOVIDO, AlertStatus.DESCARTADO,
        AlertStatus.FALSO_POSITIVO, AlertStatus.DUPLICADO,
    }),
    # Um alerta já ligado a um incidente pode ser promovido a incidente próprio
    # se a investigação concluir que é actividade distinta.
    AlertStatus.CORRELACIONADO: frozenset({
        AlertStatus.PROMOVIDO, AlertStatus.FALSO_POSITIVO,
    }),
    AlertStatus.PROMOVIDO: frozenset({AlertStatus.FALSO_POSITIVO}),
    AlertStatus.DESCARTADO: frozenset({AlertStatus.EM_TRIAGEM}),
    AlertStatus.FALSO_POSITIVO: frozenset({AlertStatus.EM_TRIAGEM}),
    AlertStatus.DUPLICADO: frozenset({AlertStatus.EM_TRIAGEM}),
}

ALERT_OPEN_STATUSES = frozenset({AlertStatus.NOVO, AlertStatus.EM_TRIAGEM})

#: Estados que um alerta só pode atingir **ligando-o a um incidente**.
#:
#: `ALERT_TRANSITIONS` diz que a passagem é legítima; isto diz que não é
#: legítima por si só. Um alerta PROMOVIDO sem `incident_id` mente duas vezes:
#: sai da fila de triagem como se tivesse sido tratado e não aparece em
#: incidente nenhum, pelo que o trabalho desaparece sem deixar rasto.
#:
#: Vive aqui, e não na rota que primeiro a verificou, porque uma regra guardada
#: numa porta é uma regra que as outras portas esquecem — foi assim que a
#: aplicação de recomendações a perdeu depois de a triagem manual a ganhar.
#: Quem atingir estes estados tem de passar por `promote_alert` ou `link_alert`.
ALERT_STATES_REQUIRING_INCIDENT = frozenset({
    AlertStatus.PROMOVIDO, AlertStatus.CORRELACIONADO,
})


# ------------------------------------------------- comunicações de incidente
class ReportChannel(StrEnum):
    """Por onde a comunicação entrou.

    Registado de propósito e nunca inferido: uma comunicação que chegou por
    email não tem a mesma confiança de origem que uma submetida no portal com
    referência e código, e quem tria precisa de o saber. `EMAIL` só é usado
    quando a caixa de correio está de facto configurada e verificada.
    """

    PORTAL = "PORTAL"          # formulário público, sem conta na plataforma
    EMAIL = "EMAIL"            # caixa de segurança (abuse@/cert@)
    API = "API"                # sistema de terceiros, com chave
    MANUAL = "MANUAL"          # registada por um analista a partir de outro meio


class ReportStatus(StrEnum):
    """Ciclo de vida de uma comunicação de incidente (§5 · RTIR).

    A distinção que o RTIR acerta e que se conserva aqui: **a comunicação não é
    o incidente.** É matéria-prima. Várias comunicações podem descrever o mesmo
    incidente, e uma comunicação pode não descrever incidente nenhum.

    `ACEITE` significa que foi ligada a pelo menos um incidente — nunca se marca
    aceite sem essa ligação existir, senão o estado afirmaria um trabalho que
    não foi feito.
    """

    RECEBIDA = "RECEBIDA"      # entrou, ninguém olhou ainda
    EM_TRIAGEM = "EM_TRIAGEM"  # um analista está a avaliá-la
    ACEITE = "ACEITE"          # ligada a um ou mais incidentes
    RECUSADA = "RECUSADA"      # sem relevância operacional, com justificação
    DUPLICADA = "DUPLICADA"    # já descrita por outra comunicação


#: Transições permitidas para uma comunicação.
#:
#: `RECUSADA` e `DUPLICADA` voltam a `EM_TRIAGEM` porque uma decisão de triagem
#: pode ser revista — ao contrário de `ACEITE`, que só se desfaz desligando o
#: incidente, operação que tem o seu próprio registo.
REPORT_TRANSITIONS: dict[ReportStatus, frozenset[ReportStatus]] = {
    ReportStatus.RECEBIDA: frozenset({
        ReportStatus.EM_TRIAGEM, ReportStatus.ACEITE,
        ReportStatus.RECUSADA, ReportStatus.DUPLICADA,
    }),
    ReportStatus.EM_TRIAGEM: frozenset({
        ReportStatus.ACEITE, ReportStatus.RECUSADA, ReportStatus.DUPLICADA,
    }),
    ReportStatus.ACEITE: frozenset({ReportStatus.EM_TRIAGEM}),
    ReportStatus.RECUSADA: frozenset({ReportStatus.EM_TRIAGEM}),
    ReportStatus.DUPLICADA: frozenset({ReportStatus.EM_TRIAGEM}),
}

#: Estados em que a comunicação ainda espera decisão.
REPORT_OPEN_STATUSES = frozenset({
    ReportStatus.RECEBIDA, ReportStatus.EM_TRIAGEM,
})

#: Estado que só se atinge com pelo menos um incidente ligado.
#:
#: Mesma razão de `ALERT_STATES_REQUIRING_INCIDENT`: marcar aceite sem ligação
#: deixaria a comunicação fora da fila e fora de qualquer incidente, e o
#: trabalho desaparecia sem deixar rasto.
REPORT_STATES_REQUIRING_INCIDENT = frozenset({ReportStatus.ACEITE})


class TaskStatus(StrEnum):
    PENDENTE = "PENDENTE"
    EM_CURSO = "EM_CURSO"
    BLOQUEADA = "BLOQUEADA"
    CONCLUIDA = "CONCLUIDA"
    CANCELADA = "CANCELADA"


# ------------------------------------------------------------- classificação
class IncidentCategory(StrEnum):
    """Taxonomia alinhada com a classificação de referência eCSIRT.net/ENISA."""

    CONTEUDO_ABUSIVO = "CONTEUDO_ABUSIVO"
    CODIGO_MALICIOSO = "CODIGO_MALICIOSO"
    RECOLHA_INFORMACAO = "RECOLHA_INFORMACAO"
    TENTATIVA_INTRUSAO = "TENTATIVA_INTRUSAO"
    INTRUSAO = "INTRUSAO"
    DISPONIBILIDADE = "DISPONIBILIDADE"
    SEGURANCA_INFORMACAO = "SEGURANCA_INFORMACAO"
    FRAUDE = "FRAUDE"
    VULNERABILIDADE = "VULNERABILIDADE"
    OUTRO = "OUTRO"


class IocType(StrEnum):
    IP = "IP"
    DOMINIO = "DOMINIO"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"
    HOSTNAME = "HOSTNAME"
    UTILIZADOR = "UTILIZADOR"
    PROCESSO = "PROCESSO"
    FICHEIRO = "FICHEIRO"
    CHAVE_REGISTO = "CHAVE_REGISTO"
    USER_AGENT = "USER_AGENT"
    CERTIFICADO = "CERTIFICADO"


class IocReputation(StrEnum):
    DESCONHECIDA = "DESCONHECIDA"
    BENIGNA = "BENIGNA"
    SUSPEITA = "SUSPEITA"
    MALICIOSA = "MALICIOSA"


class ObservationRole(StrEnum):
    """Papel do artefacto no evento observado - dá direcção às arestas do grafo."""

    ORIGEM = "ORIGEM"
    DESTINO = "DESTINO"
    ALVO = "ALVO"
    PAYLOAD = "PAYLOAD"
    ACTOR = "ACTOR"
    ARTEFACTO = "ARTEFACTO"
    RELACIONADO = "RELACIONADO"


class AssetCriticality(StrEnum):
    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"
    CRITICA = "CRITICA"


class AssetType(StrEnum):
    SERVIDOR = "SERVIDOR"
    ESTACAO = "ESTACAO"
    EQUIPAMENTO_REDE = "EQUIPAMENTO_REDE"
    APLICACAO = "APLICACAO"
    BASE_DADOS = "BASE_DADOS"
    SERVICO_CLOUD = "SERVICO_CLOUD"
    DISPOSITIVO_MOVEL = "DISPOSITIVO_MOVEL"
    OUTRO = "OUTRO"


class RelationType(StrEnum):
    """Arestas tipadas entre incidentes (§20)."""

    DUPLICADO_DE = "DUPLICADO_DE"
    RELACIONADO_COM = "RELACIONADO_COM"
    CAUSADO_POR = "CAUSADO_POR"
    ORIGINOU = "ORIGINOU"
    PARTE_DE_CAMPANHA = "PARTE_DE_CAMPANHA"
    ESCALADO_DE = "ESCALADO_DE"


# ------------------------------------------------------------------- acções
class ActionRiskLevel(StrEnum):
    """Determina o regime de aprovação exigido (§13)."""

    BAIXO = "BAIXO"        # automático, pré-autorizado
    MODERADO = "MODERADO"  # requer aprovação de um analista
    CRITICO = "CRITICO"    # requer aprovação humana obrigatória e explícita


class ActionStatus(StrEnum):
    PROPOSTA = "PROPOSTA"
    AGUARDA_APROVACAO = "AGUARDA_APROVACAO"
    APROVADA = "APROVADA"
    REJEITADA = "REJEITADA"
    EM_EXECUCAO = "EM_EXECUCAO"
    EXECUTADA = "EXECUTADA"
    FALHADA = "FALHADA"
    REVERTIDA = "REVERTIDA"
    CANCELADA = "CANCELADA"


class ApprovalDecision(StrEnum):
    APROVADA = "APROVADA"
    REJEITADA = "REJEITADA"
    PENDENTE = "PENDENTE"
    #: Ninguém decidiu dentro do prazo. Não é uma rejeição: ninguém rejeitou.
    CADUCADA = "CADUCADA"


class PlaybookExecutionStatus(StrEnum):
    PENDENTE = "PENDENTE"
    EM_EXECUCAO = "EM_EXECUCAO"
    AGUARDA_APROVACAO = "AGUARDA_APROVACAO"
    CONCLUIDA = "CONCLUIDA"
    FALHADA = "FALHADA"
    CANCELADA = "CANCELADA"


class PlaybookStepType(StrEnum):
    ENRIQUECER_IOC = "ENRIQUECER_IOC"
    CONSULTAR_REPUTACAO = "CONSULTAR_REPUTACAO"
    IDENTIFICAR_ACTIVOS = "IDENTIFICAR_ACTIVOS"
    CRIAR_TAREFA = "CRIAR_TAREFA"
    SOLICITAR_APROVACAO = "SOLICITAR_APROVACAO"
    EXECUTAR_ACCAO = "EXECUTAR_ACCAO"
    ALTERAR_ESTADO = "ALTERAR_ESTADO"
    ATRIBUIR_RESPONSAVEL = "ATRIBUIR_RESPONSAVEL"
    REGISTAR_NOTA = "REGISTAR_NOTA"
    NOTIFICAR = "NOTIFICAR"


# ------------------------------------------------------- fontes e integrações
class SourceKind(StrEnum):
    WAZUH = "WAZUH"
    SURICATA = "SURICATA"
    QRADAR = "QRADAR"
    NETSCOUT = "NETSCOUT"
    MANUAL = "MANUAL"
    API_GENERICA = "API_GENERICA"


class IntegrationStatus(StrEnum):
    """Nunca apresentar uma integração como activa sem verificação real (§4)."""

    NAO_CONFIGURADA = "NAO_CONFIGURADA"
    CONFIGURADA = "CONFIGURADA"       # credenciais presentes, ainda não verificada
    ACTIVA = "ACTIVA"                 # teste de ligação bem-sucedido
    ERRO = "ERRO"
    DESACTIVADA = "DESACTIVADA"


class IntegrationDirection(StrEnum):
    ENTRADA = "ENTRADA"      # recebe alertas
    SAIDA = "SAIDA"          # executa acções
    BIDIRECIONAL = "BIDIRECIONAL"


# ------------------------------------------------------------- inteligência
class RecommendationKind(StrEnum):
    TRIAGEM = "TRIAGEM"
    CLASSIFICACAO = "CLASSIFICACAO"
    PRIORIZACAO = "PRIORIZACAO"
    CORRELACAO = "CORRELACAO"
    TECNICA_MITRE = "TECNICA_MITRE"
    PLAYBOOK = "PLAYBOOK"
    FALSO_POSITIVO = "FALSO_POSITIVO"
    PROXIMO_PASSO = "PROXIMO_PASSO"


class RecommendationStatus(StrEnum):
    PENDENTE = "PENDENTE"
    ACEITE = "ACEITE"
    REJEITADA = "REJEITADA"
    EXPIRADA = "EXPIRADA"


class EvidenceType(StrEnum):
    LOG = "LOG"
    CAPTURA_ECRA = "CAPTURA_ECRA"
    CAPTURA_REDE = "CAPTURA_REDE"
    FICHEIRO = "FICHEIRO"
    RELATORIO = "RELATORIO"
    ARTEFACTO = "ARTEFACTO"
    EVENTO = "EVENTO"
    OUTRO = "OUTRO"


class AuditOutcome(StrEnum):
    SUCESSO = "SUCESSO"
    NEGADO = "NEGADO"
    FALHA = "FALHA"


class ReportKind(StrEnum):
    INCIDENTE = "INCIDENTE"
    INVESTIGACAO = "INVESTIGACAO"
    ACTIVIDADE = "ACTIVIDADE"
    PERIODO = "PERIODO"
    SEVERIDADE = "SEVERIDADE"
    DESEMPENHO = "DESEMPENHO"
    RESPOSTA = "RESPOSTA"


# ------------------------------------------------------------- correlação
class CorrelationStrategy(StrEnum):
    """Estratégias do motor de correlação (§9).

    Cada uma responde a uma pergunta diferente sobre "isto é a mesma
    actividade?" - e é por serem várias que o motor deixa de ser um simples
    "procurar semelhantes".
    """

    #: Alertas distintos que partilham um artefacto (IP, utilizador, host).
    ENTIDADE_PARTILHADA = "ENTIDADE_PARTILHADA"
    #: Sequência ordenada de categorias de detecção compatível com uma cadeia
    #: de ataque (ex.: recolha -> acesso inicial -> execução).
    SEQUENCIA_TEMPORAL = "SEQUENCIA_TEMPORAL"
    #: N ocorrências do mesmo tipo de detecção dentro de uma janela.
    LIMIAR = "LIMIAR"
    #: Detecções heterogéneas convergindo no mesmo activo.
    ACTIVO_ALVO = "ACTIVO_ALVO"


class CorrelationOutcome(StrEnum):
    """O que o motor fez com o alerta."""

    SEM_CORRELACAO = "SEM_CORRELACAO"
    LIGADO_A_INCIDENTE = "LIGADO_A_INCIDENTE"
    NOVO_INCIDENTE = "NOVO_INCIDENTE"
    CAMPANHA_PROPOSTA = "CAMPANHA_PROPOSTA"
    DUPLICADO_SUPRIMIDO = "DUPLICADO_SUPRIMIDO"


class NotificationKind(StrEnum):
    INCIDENTE_ATRIBUIDO = "INCIDENTE_ATRIBUIDO"
    APROVACAO_PENDENTE = "APROVACAO_PENDENTE"
    ACCAO_EXECUTADA = "ACCAO_EXECUTADA"
    ACCAO_FALHADA = "ACCAO_FALHADA"
    TAREFA_ATRIBUIDA = "TAREFA_ATRIBUIDA"
    INCIDENTE_ESCALADO = "INCIDENTE_ESCALADO"
    CORRELACAO_DETECTADA = "CORRELACAO_DETECTADA"
    RECOMENDACAO_NOVA = "RECOMENDACAO_NOVA"


class IncidentOrigin(StrEnum):
    """Como o incidente passou a existir. Distinto de `SourceKind`, que diz
    de que ferramenta veio o sinal: aqui regista-se a *decisao* que o criou."""

    REGISTO_MANUAL = "REGISTO_MANUAL"
    PROMOCAO_ALERTA = "PROMOCAO_ALERTA"
    CORRELACAO = "CORRELACAO"
    PLAYBOOK = "PLAYBOOK"
    ESCALAMENTO = "ESCALAMENTO"
    #: Nasceu de uma comunicação externa aceite em triagem. Distinto de
    #: REGISTO_MANUAL: o que o originou não foi um analista a observar algo, foi
    #: alguém de fora a comunicá-lo, e a origem tem de o dizer.
    COMUNICACAO_EXTERNA = "COMUNICACAO_EXTERNA"


class ActionKind(StrEnum):
    """Tipos de accao de resposta suportados.

    Cada tipo tem um executor real registado em `app/integrations/`. Um tipo sem
    executor configurado nao pode ser executado - a API recusa, em vez de
    reportar sucesso falso (§4).
    """

    BLOQUEAR_IP = "BLOQUEAR_IP"
    DESBLOQUEAR_IP = "DESBLOQUEAR_IP"
    ISOLAR_ACTIVO = "ISOLAR_ACTIVO"
    REMOVER_ISOLAMENTO = "REMOVER_ISOLAMENTO"
    DESACTIVAR_UTILIZADOR = "DESACTIVAR_UTILIZADOR"
    TERMINAR_SESSOES = "TERMINAR_SESSOES"
    EXECUTAR_VARRIMENTO = "EXECUTAR_VARRIMENTO"
    RECOLHER_ARTEFACTOS = "RECOLHER_ARTEFACTOS"
    NOTIFICAR_EQUIPA = "NOTIFICAR_EQUIPA"
    #: Porta de autorizacao de um playbook. Nao actua sobre nenhum sistema:
    #: existe para que a decisao humana tenha uma entidade real, aprovavel e
    #: auditavel. Sem ela, um passo "solicitar aprovacao" suspenderia a
    #: execucao sem nada que pudesse ser aprovado - e o playbook nunca mais
    #: seria retomado.
    AUTORIZAR_PROSSEGUIMENTO = "AUTORIZAR_PROSSEGUIMENTO"
    ENRIQUECER_IOC = "ENRIQUECER_IOC"
    REGISTAR_NOTA = "REGISTAR_NOTA"
