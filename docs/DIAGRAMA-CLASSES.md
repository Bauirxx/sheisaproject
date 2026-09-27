# SHEISA — Diagrama de classes (modelo de domínio)

Diagrama das 33 entidades do domínio do SHEISA e das suas relações, extraído
directamente dos modelos SQLAlchemy em [`backend/app/models/`](../backend/app/models/).
Nada aqui é inventado: classes, atributos e relações correspondem ao código.

> **Para a monografia:** as imagens prontas e a fonte UML estão em
> [`docs/diagramas/`](diagramas/) — `classes.png` (inserir), `classes.svg`
> (escalável, melhor para impressão) e `classes.puml` (fonte PlantUML, editável e
> importável no draw.io). Ver as instruções no fim deste documento.

Para poupar espaço, cada classe mostra os atributos identificadores e alguns de
domínio, não todos. As chaves estrangeiras aparecem como relações (associações),
não como atributos. Quase todas as entidades registam ainda um `created_by_id`
para o `User` que as criou; essas ligações foram omitidas do desenho para não o
sobrecarregar.

## Notação

| Símbolo | Significado |
|---|---|
| `*--` | **Composição** — o filho não existe sem o pai; apagar o pai apaga o filho (`ON DELETE CASCADE`). |
| `o--` | **Agregação** — referência forte, mas o filho sobrevive ao pai (`ON DELETE SET NULL`/`RESTRICT`). |
| `-->` | **Associação** — uma entidade referencia outra. |
| `--` | **Ligação muitos-para-muitos**, através de uma tabela de associação. |
| `"1"`, `"*"`, `"0..1"` | Cardinalidades nas pontas da relação. |

As quatro tabelas de associação são `role_permissions`, `incident_assets`,
`task_dependencies` e `report_incidents`.

## Módulos

- **Identidade e acesso** — `User`, `Role`, `Permission`, `Team`, `UserSession`, `ApiKey`
- **Deteção** — `Event`, `Alert`, `CorrelationRule`
- **Incidente** — `Incident`, `IncidentRelation`, `IncidentTechnique`
- **Catálogo e intelligence** — `Asset`, `Ioc`, `Campaign`, `MitreTactic`, `MitreTechnique`
- **Investigação** — `Observation`, `Comment`, `Task`, `Evidence`
- **Resposta** — `Playbook`, `PlaybookStep`, `PlaybookExecution`, `PlaybookStepExecution`, `Action`, `ActionApproval`
- **Recomendações** — `Recommendation`
- **Comunicação externa** — `IncidentReport`
- **Sistema** — `Integration`, `Notification`, `Report`, `AuditLog`

## Diagrama

```mermaid
classDiagram
  class User {
    +UUID id
    +str email
    +str full_name
    +bool is_active
    +int failed_login_count
    +datetime last_login_at
  }
  class Role {
    +UUID id
    +str name
    +bool is_system
  }
  class Permission {
    +UUID id
    +str code
    +str description
  }
  class Team {
    +UUID id
    +str name
    +bool is_active
  }
  class UserSession {
    +UUID id
    +datetime expires_at
    +datetime revoked_at
    +str ip_address
  }
  class ApiKey {
    +UUID id
    +str name
    +str key_prefix
    +bool is_active
    +int use_count
  }

  class Event {
    +UUID id
    +SourceKind source_kind
    +str source_event_id
    +str event_type
    +Severity severity
    +datetime occurred_at
    +str source_ip
    +str host
    +dict raw_payload
  }
  class Alert {
    +UUID id
    +str reference
    +str title
    +Severity severity
    +AlertStatus status
    +str dedup_key
    +int event_count
    +int triage_score
    +CorrelationOutcome correlation_outcome
  }
  class CorrelationRule {
    +UUID id
    +str name
    +CorrelationStrategy strategy
    +int window_minutes
    +int min_alerts
    +bool is_enabled
  }

  class Incident {
    +UUID id
    +str reference
    +str title
    +IncidentCategory category
    +Severity severity
    +Priority priority
    +IncidentStatus status
    +IncidentOrigin origin
    +datetime detected_at
    +int risk_score
  }
  class IncidentRelation {
    +UUID id
    +RelationType relation_type
    +str rationale
    +Confidence confidence
  }
  class IncidentTechnique {
    +UUID id
    +bool is_asserted
    +Confidence confidence
    +str rationale
  }

  class Asset {
    +UUID id
    +str identifier
    +str name
    +AssetType asset_type
    +AssetCriticality criticality
    +str ip_address
    +str wazuh_agent_id
  }
  class Ioc {
    +UUID id
    +IocType ioc_type
    +str value
    +IocReputation reputation
    +Confidence confidence
    +int risk_score
    +bool is_allowlisted
  }
  class Campaign {
    +UUID id
    +str reference
    +str name
    +Severity severity
    +str suspected_actor
    +bool is_active
  }
  class MitreTactic {
    +UUID id
    +str tactic_id
    +str shortname
    +str name
    +int ordering
  }
  class MitreTechnique {
    +UUID id
    +str technique_id
    +str name
    +bool is_subtechnique
    +list platforms
  }

  class Observation {
    +UUID id
    +ObservationRole role
    +datetime observed_at
    +Confidence confidence
    +bool is_automatic
  }
  class Comment {
    +UUID id
    +str body
    +bool is_internal
    +bool is_system
  }
  class Task {
    +UUID id
    +str title
    +TaskStatus status
    +Priority priority
    +int ordering
    +datetime due_at
  }
  class Evidence {
    +UUID id
    +str name
    +EvidenceType evidence_type
    +str sha256
    +int size_bytes
    +bool integrity_ok
  }

  class Playbook {
    +UUID id
    +str name
    +int version
    +bool is_enabled
    +Severity trigger_min_severity
    +bool auto_execute
    +str closing_status
  }
  class PlaybookStep {
    +UUID id
    +int ordering
    +str name
    +PlaybookStepType step_type
    +ActionKind action_kind
    +ActionRiskLevel risk_level
    +bool requires_approval
  }
  class PlaybookExecution {
    +UUID id
    +str reference
    +PlaybookExecutionStatus status
    +int playbook_version
    +bool triggered_automatically
    +str result_summary
  }
  class PlaybookStepExecution {
    +UUID id
    +int ordering
    +str step_name
    +PlaybookStepType step_type
    +TaskStatus status
  }
  class Action {
    +UUID id
    +str reference
    +ActionKind action_kind
    +ActionRiskLevel risk_level
    +ActionStatus status
    +str title
    +bool is_reversible
  }
  class ActionApproval {
    +UUID id
    +ApprovalDecision decision
    +str required_permission
    +str justification
    +datetime expires_at
  }

  class Recommendation {
    +UUID id
    +RecommendationKind kind
    +RecommendationStatus status
    +str target_type
    +UUID target_id
    +int confidence
    +bool applied
  }

  class IncidentReport {
    +UUID id
    +str reference
    +str reporter_name
    +str reporter_email
    +ReportChannel channel
    +str subject
    +ReportStatus status
    +int tracking_views
  }

  class Integration {
    +UUID id
    +str name
    +SourceKind kind
    +IntegrationDirection direction
    +IntegrationStatus status
    +bool is_enabled
    +int events_received
  }
  class Notification {
    +UUID id
    +NotificationKind kind
    +Severity severity
    +str title
    +datetime read_at
  }
  class Report {
    +UUID id
    +str reference
    +ReportKind kind
    +str title
    +datetime period_start
    +datetime period_end
  }
  class AuditLog {
    +UUID id
    +str action
    +str resource_type
    +str actor_email
    +AuditOutcome outcome
    +datetime created_at
  }

  Role "1" o-- "*" User : role
  Team "1" o-- "*" User : membros
  Role "*" -- "*" Permission : role_permissions
  User "1" *-- "*" UserSession : sessoes
  Integration "1" o-- "*" ApiKey : chaves

  Alert "1" *-- "*" Event : eventos
  Event "*" --> "0..1" Integration : origem
  Event "*" --> "0..1" Asset
  Alert "*" --> "0..1" CorrelationRule : regra
  Alert "*" --> "0..1" Asset
  CorrelationRule "*" --> "0..1" Playbook : sugere

  Incident "*" --> "0..1" User : responsavel
  Incident "*" --> "0..1" User : reportado_por
  Incident "*" --> "0..1" Team
  Campaign "1" o-- "*" Incident : incidentes
  Incident "*" -- "*" Asset : incident_assets
  Incident "1" o-- "*" Alert : alertas
  Incident "1" *-- "*" Comment
  Incident "1" *-- "*" Task
  Incident "1" *-- "*" Evidence
  Incident "1" *-- "*" Observation
  Incident "1" *-- "*" IncidentTechnique
  Incident "1" *-- "*" Action
  Incident "1" *-- "*" PlaybookExecution
  IncidentRelation "*" --> "1" Incident : origem
  IncidentRelation "*" --> "1" Incident : destino
  IncidentTechnique "*" --> "1" MitreTechnique

  MitreTactic "1" o-- "*" MitreTechnique : tecnicas
  MitreTechnique "*" --> "0..1" MitreTactic : tactica

  Observation "*" --> "1" Ioc
  Observation "*" --> "0..1" Asset
  Observation "*" --> "0..1" Alert
  Task "*" -- "*" Task : depende_de
  Task "*" --> "0..1" PlaybookExecution
  Evidence "*" --> "0..1" Task
  Comment "*" --> "0..1" User : autor
  Task "*" --> "0..1" User : responsavel

  Playbook "1" *-- "*" PlaybookStep : passos
  PlaybookExecution "*" --> "1" Playbook
  PlaybookExecution "1" *-- "*" PlaybookStepExecution
  PlaybookStepExecution "*" --> "0..1" PlaybookStep
  PlaybookStepExecution "*" --> "0..1" Action
  Action "1" *-- "*" ActionApproval : aprovacoes
  Action "*" --> "0..1" Integration
  Action "*" --> "0..1" Recommendation
  Action "*" --> "0..1" User : proposto_por
  ActionApproval "*" --> "0..1" User : decidido_por

  Recommendation "*" --> "0..1" User : decidido_por
  IncidentReport "*" --> "0..1" User : triado_por
  IncidentReport "*" -- "*" Incident : report_incidents
  IncidentReport "*" --> "0..1" IncidentReport : duplicado_de
  Notification "*" --> "1" User
  Report "*" --> "0..1" Incident
  Report "*" --> "0..1" User : gerado_por
  AuditLog "*" --> "0..1" User : actor
```

## Guião de explicação (para defender o diagrama)

O modelo foi desenhado à volta de cinco decisões. Quem apresentar deve conseguir
explicar cada uma — são elas que distinguem o SHEISA de uma cópia do RTIR ou do
TheHive.

### 1. Event ≠ Alert ≠ Incident — três classes, não uma

- **Event** é um facto bruto de uma fonte (uma linha do Wazuh ou do Suricata).
- **Alert** agrupa eventos pela `dedup_key` e já traz a pontuação da triagem; um
  alerta reúne muitos eventos (`Alert "1" *-- "*" Event`).
- **Incident** é o caso que **uma pessoa decide tratar**. Nasce de um alerta
  promovido, de correlação, de um playbook, de escalamento ou de uma comunicação
  externa — é o que o campo `origin` regista.

> Em uma frase: a granularidade cresce de Event para Alert para Incident, e cada
> nível é uma classe com o seu próprio ciclo de vida. Juntá-los numa só tabela
> perderia a distinção entre "o que a máquina viu" e "o que decidimos investigar".

### 2. IOC global vs Observação contextual

- **Ioc** é o indicador em si — um IP, um hash — único e global, com reputação e
  risco próprios.
- **Observation** liga um `Ioc` a um `Incident` **num papel** (origem, alvo,
  artefacto…). O mesmo IP pode ser o atacante num incidente e o alvo noutro.

> Em uma frase: separámos *o que o indicador é* (global, na base de conhecimento)
> de *o que ele significou aqui* (contextual, no caso). É a `Observation` que
> carrega o papel, não o `Ioc`.

### 3. Modelo de resposta separado da sua execução

- **Playbook** e **PlaybookStep** são o procedimento — o que *se deve* fazer.
- **PlaybookExecution** e **PlaybookStepExecution** são uma corrida concreta — o
  que *se fez*, passo a passo, com o resultado de cada um.
- **Action** é uma medida (bloquear IP, isolar host); se for disruptiva, exige
  uma **ActionApproval** antes de executar.

> Em uma frase: o registo do que aconteceu (`PlaybookExecution`) não muda quando
> alguém edita o procedimento (`Playbook`) — por isso são classes separadas, e a
> execução guarda a `playbook_version` que correu.

### 4. Auditoria imutável (append-only)

- **AuditLog** regista quem (`actor`/`api_key`), o quê (`action`), sobre o quê
  (`resource`), e o antes/depois (`old_value`/`new_value`). Repare que só tem
  **associações** para fora, nunca composições: nada o apaga em cascata, porque
  um registo de auditoria não se apaga.

### 5. O que as pontas das setas afirmam

| Relação | Exemplo no diagrama | O que significa |
|---|---|---|
| Composição `*--` | `Incident *-- Comment` | Apagar o incidente apaga os comentários. |
| Agregação `o--` | `Role o-- User` | Apagar um perfil **não** apaga os utilizadores (é restrito). |
| Muitos-para-muitos `--` | `Incident -- Asset` | Um incidente afecta vários activos; um activo aparece em vários incidentes. |

### Números para citar

33 entidades · 4 tabelas de associação · 9 módulos. Desde a migração
`0007_check_enumeracoes`, os valores das enumerações são impostos por restrição
CHECK na própria base de dados, não apenas pela aplicação.

## Como usar os ficheiros (para a monografia)

Em [`docs/diagramas/`](diagramas/) estão os dois diagramas (classes e casos de
uso) em três formatos:

| Ficheiro | Para quê |
|---|---|
| `classes.png` / `casos-de-uso.png` | Inserir directamente num documento Word. |
| `classes.svg` / `casos-de-uso.svg` | **Escalável** — não fica pixelizado ao ampliar nem ao imprimir. Preferir em LaTeX/PDF. |
| `classes.puml` / `casos-de-uso.puml` | Fonte **PlantUML** (UML a sério). Para editar e voltar a exportar. |

**Editar e re-exportar** (se precisar de mudar algo):

1. **Online, sem instalar nada:** abrir <https://www.plantuml.com/plantuml>,
   colar o conteúdo do `.puml`, e descarregar em PNG ou SVG.
2. **No draw.io / diagrams.net:** *Arrange → Insert → Advanced → PlantUML…*,
   colar o `.puml`. Fica editável como formas do draw.io.
3. **No VS Code:** instalar a extensão *PlantUML* e pré-visualizar com `Alt+D`.

As imagens são geradas a partir do `.puml`; se o modelo mudar, reexportar.


