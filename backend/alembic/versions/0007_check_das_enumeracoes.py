"""restricoes CHECK para as colunas de enumeracao

Revision ID: 0007_check_enumeracoes
Revises: 0006_comunicacoes
Create Date: 2026-09-24

Impoe, na base de dados, os valores validos de cada coluna de enumeracao.

Ate aqui a validacao era so do ORM (`validate_strings=True`): um valor invalido
escrito por SQL directo passava. Estas restricoes CHECK fecham essa porta -- a
base recusa qualquer valor fora do dominio da enumeracao.

**Custo assumido, e deliberado.** Os valores ficam fixados aqui, no momento em
que a migracao foi escrita. Acrescentar um estado novo a uma enumeracao (como
`CADUCADA` foi acrescentado as aprovacoes) passa a exigir uma migracao que refaca
a restricao da coluna afectada. E o preco de a base os impor.

`native_enum=False`: as colunas sao VARCHAR e nao tipos ENUM nativos -- por isso
a imposicao e uma restricao CHECK e nao um tipo, e acrescentar um valor nunca
exige `ALTER TYPE`. Colunas anulaveis continuam a aceitar NULL: `NULL IN (...)`
e UNKNOWN, nao FALSE, pelo que a restricao nao as torna obrigatorias.

Os valores foram extraidos dos proprios modelos (o mesmo `.enums` que o
SQLAlchemy expoe), pelo que coincidem com o dominio no momento da escrita.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0007_check_enumeracoes"
down_revision: str | None = "0006_comunicacoes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (tabela, coluna, [valores validos]) -- fixados no momento desta migracao.
RESTRICOES: list[tuple[str, str, list[str]]] = [
    ("assets", "asset_type", ['SERVIDOR', 'ESTACAO', 'EQUIPAMENTO_REDE', 'APLICACAO', 'BASE_DADOS', 'SERVICO_CLOUD', 'DISPOSITIVO_MOVEL', 'OUTRO']),
    ("assets", "criticality", ['BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("integrations", "kind", ['WAZUH', 'SURICATA', 'QRADAR', 'NETSCOUT', 'MANUAL', 'API_GENERICA']),
    ("integrations", "direction", ['ENTRADA', 'SAIDA', 'BIDIRECIONAL']),
    ("integrations", "status", ['NAO_CONFIGURADA', 'CONFIGURADA', 'ACTIVA', 'ERRO', 'DESACTIVADA']),
    ("iocs", "ioc_type", ['IP', 'DOMINIO', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EMAIL', 'HOSTNAME', 'UTILIZADOR', 'PROCESSO', 'FICHEIRO', 'CHAVE_REGISTO', 'USER_AGENT', 'CERTIFICADO']),
    ("iocs", "reputation", ['DESCONHECIDA', 'BENIGNA', 'SUSPEITA', 'MALICIOSA']),
    ("iocs", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("campaigns", "severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("campaigns", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("incident_reports", "channel", ['PORTAL', 'EMAIL', 'API', 'MANUAL']),
    ("incident_reports", "claimed_category", ['CONTEUDO_ABUSIVO', 'CODIGO_MALICIOSO', 'RECOLHA_INFORMACAO', 'TENTATIVA_INTRUSAO', 'INTRUSAO', 'DISPONIBILIDADE', 'SEGURANCA_INFORMACAO', 'FRAUDE', 'VULNERABILIDADE', 'OUTRO']),
    ("incident_reports", "claimed_severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("incident_reports", "status", ['RECEBIDA', 'EM_TRIAGEM', 'ACEITE', 'RECUSADA', 'DUPLICADA']),
    ("notifications", "kind", ['INCIDENTE_ATRIBUIDO', 'APROVACAO_PENDENTE', 'ACCAO_EXECUTADA', 'ACCAO_FALHADA', 'TAREFA_ATRIBUIDA', 'INCIDENTE_ESCALADO', 'CORRELACAO_DETECTADA', 'RECOMENDACAO_NOVA']),
    ("notifications", "severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("playbooks", "trigger_category", ['CONTEUDO_ABUSIVO', 'CODIGO_MALICIOSO', 'RECOLHA_INFORMACAO', 'TENTATIVA_INTRUSAO', 'INTRUSAO', 'DISPONIBILIDADE', 'SEGURANCA_INFORMACAO', 'FRAUDE', 'VULNERABILIDADE', 'OUTRO']),
    ("playbooks", "trigger_min_severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("recommendations", "kind", ['TRIAGEM', 'CLASSIFICACAO', 'PRIORIZACAO', 'CORRELACAO', 'TECNICA_MITRE', 'PLAYBOOK', 'FALSO_POSITIVO', 'PROXIMO_PASSO']),
    ("recommendations", "status", ['PENDENTE', 'ACEITE', 'REJEITADA', 'EXPIRADA']),
    ("audit_logs", "outcome", ['SUCESSO', 'NEGADO', 'FALHA']),
    ("correlation_rules", "strategy", ['ENTIDADE_PARTILHADA', 'SEQUENCIA_TEMPORAL', 'LIMIAR', 'ACTIVO_ALVO']),
    ("correlation_rules", "resulting_severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("incidents", "category", ['CONTEUDO_ABUSIVO', 'CODIGO_MALICIOSO', 'RECOLHA_INFORMACAO', 'TENTATIVA_INTRUSAO', 'INTRUSAO', 'DISPONIBILIDADE', 'SEGURANCA_INFORMACAO', 'FRAUDE', 'VULNERABILIDADE', 'OUTRO']),
    ("incidents", "severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("incidents", "priority", ['P4', 'P3', 'P2', 'P1']),
    ("incidents", "status", ['NOVO', 'ABERTO', 'TRIAGEM', 'INVESTIGACAO', 'CONTENCAO', 'ERRADICACAO', 'RECUPERACAO', 'RESOLVIDO', 'ENCERRADO', 'SUSPENSO', 'DUPLICADO', 'FALSO_POSITIVO', 'ESCALADO']),
    ("incidents", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("incidents", "origin", ['REGISTO_MANUAL', 'PROMOCAO_ALERTA', 'CORRELACAO', 'PLAYBOOK', 'ESCALAMENTO', 'COMUNICACAO_EXTERNA']),
    ("incidents", "source_kind", ['WAZUH', 'SURICATA', 'QRADAR', 'NETSCOUT', 'MANUAL', 'API_GENERICA']),
    ("playbook_steps", "step_type", ['ENRIQUECER_IOC', 'CONSULTAR_REPUTACAO', 'IDENTIFICAR_ACTIVOS', 'CRIAR_TAREFA', 'SOLICITAR_APROVACAO', 'EXECUTAR_ACCAO', 'ALTERAR_ESTADO', 'ATRIBUIR_RESPONSAVEL', 'REGISTAR_NOTA', 'NOTIFICAR']),
    ("playbook_steps", "action_kind", ['BLOQUEAR_IP', 'DESBLOQUEAR_IP', 'ISOLAR_ACTIVO', 'REMOVER_ISOLAMENTO', 'DESACTIVAR_UTILIZADOR', 'TERMINAR_SESSOES', 'EXECUTAR_VARRIMENTO', 'RECOLHER_ARTEFACTOS', 'NOTIFICAR_EQUIPA', 'AUTORIZAR_PROSSEGUIMENTO', 'ENRIQUECER_IOC', 'REGISTAR_NOTA']),
    ("playbook_steps", "risk_level", ['BAIXO', 'MODERADO', 'CRITICO']),
    ("alerts", "source_kind", ['WAZUH', 'SURICATA', 'QRADAR', 'NETSCOUT', 'MANUAL', 'API_GENERICA']),
    ("alerts", "severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("alerts", "status", ['NOVO', 'EM_TRIAGEM', 'CORRELACIONADO', 'PROMOVIDO', 'DESCARTADO', 'FALSO_POSITIVO', 'DUPLICADO']),
    ("alerts", "correlation_outcome", ['SEM_CORRELACAO', 'LIGADO_A_INCIDENTE', 'NOVO_INCIDENTE', 'CAMPANHA_PROPOSTA', 'DUPLICADO_SUPRIMIDO']),
    ("incident_relations", "relation_type", ['DUPLICADO_DE', 'RELACIONADO_COM', 'CAUSADO_POR', 'ORIGINOU', 'PARTE_DE_CAMPANHA', 'ESCALADO_DE']),
    ("incident_relations", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("incident_techniques", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("playbook_executions", "status", ['PENDENTE', 'EM_EXECUCAO', 'AGUARDA_APROVACAO', 'CONCLUIDA', 'FALHADA', 'CANCELADA']),
    ("reports", "kind", ['INCIDENTE', 'INVESTIGACAO', 'ACTIVIDADE', 'PERIODO', 'SEVERIDADE', 'DESEMPENHO', 'RESPOSTA']),
    ("actions", "action_kind", ['BLOQUEAR_IP', 'DESBLOQUEAR_IP', 'ISOLAR_ACTIVO', 'REMOVER_ISOLAMENTO', 'DESACTIVAR_UTILIZADOR', 'TERMINAR_SESSOES', 'EXECUTAR_VARRIMENTO', 'RECOLHER_ARTEFACTOS', 'NOTIFICAR_EQUIPA', 'AUTORIZAR_PROSSEGUIMENTO', 'ENRIQUECER_IOC', 'REGISTAR_NOTA']),
    ("actions", "risk_level", ['BAIXO', 'MODERADO', 'CRITICO']),
    ("actions", "status", ['PROPOSTA', 'AGUARDA_APROVACAO', 'APROVADA', 'REJEITADA', 'EM_EXECUCAO', 'EXECUTADA', 'FALHADA', 'REVERTIDA', 'CANCELADA']),
    ("events", "source_kind", ['WAZUH', 'SURICATA', 'QRADAR', 'NETSCOUT', 'MANUAL', 'API_GENERICA']),
    ("events", "severity", ['INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA']),
    ("observations", "role", ['ORIGEM', 'DESTINO', 'ALVO', 'PAYLOAD', 'ACTOR', 'ARTEFACTO', 'RELACIONADO']),
    ("observations", "confidence", ['BAIXA', 'MEDIA', 'ALTA', 'CONFIRMADA']),
    ("tasks", "status", ['PENDENTE', 'EM_CURSO', 'BLOQUEADA', 'CONCLUIDA', 'CANCELADA']),
    ("tasks", "priority", ['P4', 'P3', 'P2', 'P1']),
    ("action_approvals", "decision", ['APROVADA', 'REJEITADA', 'PENDENTE', 'CADUCADA']),
    ("evidence", "evidence_type", ['LOG', 'CAPTURA_ECRA', 'CAPTURA_REDE', 'FICHEIRO', 'RELATORIO', 'ARTEFACTO', 'EVENTO', 'OUTRO']),
    ("playbook_step_executions", "step_type", ['ENRIQUECER_IOC', 'CONSULTAR_REPUTACAO', 'IDENTIFICAR_ACTIVOS', 'CRIAR_TAREFA', 'SOLICITAR_APROVACAO', 'EXECUTAR_ACCAO', 'ALTERAR_ESTADO', 'ATRIBUIR_RESPONSAVEL', 'REGISTAR_NOTA', 'NOTIFICAR']),
    ("playbook_step_executions", "status", ['PENDENTE', 'EM_CURSO', 'BLOQUEADA', 'CONCLUIDA', 'CANCELADA']),
]


def _nome(tabela: str, coluna: str) -> str:
    return f"ck_{tabela}_{coluna}_enum"


def _condicao(coluna: str, valores: list[str]) -> str:
    lista = ", ".join("'" + v.replace("'", "''") + "'" for v in valores)
    return f'"{coluna}" IN ({lista})'


def upgrade() -> None:
    # SQL cru, de proposito: `op.create_check_constraint` aplicaria a
    # `naming_convention` do metadata (`ck_%(table_name)s_%(constraint_name)s`),
    # duplicando o prefixo e passando alguns nomes do limite de 63 caracteres do
    # PostgreSQL, que os truncava. Aqui o nome fica exactamente como esta em
    # `_nome`, curto e legivel.
    for tabela, coluna, valores in RESTRICOES:
        op.execute(
            f"ALTER TABLE {tabela} ADD CONSTRAINT {_nome(tabela, coluna)} "
            f"CHECK ({_condicao(coluna, valores)})"
        )


def downgrade() -> None:
    for tabela, coluna, _ in RESTRICOES:
        op.execute(
            f"ALTER TABLE {tabela} DROP CONSTRAINT {_nome(tabela, coluna)}"
        )
