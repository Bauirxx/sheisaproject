# Briefing técnico — evolução da plataforma

> Versionado em 2026-09-15. É a especificação alargada que orienta a construção
> da plataforma para além do que o capítulo da monografia descreve.
>
> **Nota sobre numeração.** Os comentários no código citam secções como `§4`,
> `§12`, `§16`, `§32` — essa numeração vem de um briefing anterior, com outra
> estrutura, que não chegou a ser versionado. **Não corresponde à numeração
> deste documento.** Quando o código diz "§12 — motor determinístico explicável",
> a ideia correspondente aqui é a das secções 49–52 (AI assistida, com
> explicabilidade e aprovação humana). Ao tocar em código antigo, leia a frase
> que acompanha a citação: é ela que diz o que a regra exige, e é sempre
> autossuficiente.
>
> Equivalências úteis entre a numeração antiga (no código) e este documento:
>
> | No código | Ideia | Aqui |
> |---|---|---|
> | §4, §34 | nada é simulado; não fingir sucesso | 50 (explainability), 31 (aprovação) |
> | §7 | ciclo de vida configurável | 5 (RTIR), 29 (workflow engine) |
> | §8, §9 | ingestão, normalização, correlação | 6, 7, 8 |
> | §11 | MITRE nunca assumido | 15, 50 |
> | §12 | camada de inteligência explicável | 49, 50, 52 |
> | §13, §32 | aprovações, human-in-the-loop | 31, 32 |
> | §16 | auditoria | 42, 43 |
> | §21 | grafo investigativo | 19 |
> | §22, §23 | RBAC, autenticação, segredos | 39, 45, 48 |
> | §27 | paginação | 94 |
> | §28–§30 | interface | 77–82 |
> | §32 (testes) | testes | 87, 88, 89 |
> | §36 | lições aprendidas | 54, 55 |

---

# MISSÃO

Plataforma de *Cybersecurity Incident Response / Incident Management* já em
desenvolvimento e **já em produção**. O backend está praticamente concluído e
existe arquitectura, base de dados, APIs, frontend e funcionalidades a
funcionar.

**Não reconstruir o projecto de raiz.** Fazer uma evolução profunda da
plataforma existente, preservando o que já funciona e acrescentando
funcionalidades inspiradas em: RTIR, TheHive, Cortex, MISP, Wazuh e MITRE
ATT&CK.

---

## 1. Regra mais importante: não quebrar o que já existe

Antes de alterar código: analisar arquitectura, backend, frontend, base de
dados, APIs, autenticação, autorização, integrações e componentes existentes;
identificar funcionalidades implementadas e incompletas, bugs, dívida técnica,
duplicação, riscos de segurança e pontos de extensão.

Não remover funcionalidades sem justificação técnica. Não substituir componentes
funcionais só porque existe tecnologia diferente. Não alterar contratos de APIs
sem necessidade. Preservar compatibilidade ou criar estratégia de migração.

## 2. Primeira fase: auditoria

**2.1 Arquitectura actual** — documentar frontend, backend, banco, storage,
autenticação, autorização, filas, workers, integrações, APIs, serviços externos,
deployment e observabilidade.

**2.2 Funcionalidades existentes** — matriz por funcionalidade (Login,
Incidentes, Alerts, Cases, Tasks, IOC, Evidence, Threat Intelligence, Playbooks,
Audit) com: existe? estado? precisa melhoria?

Não assumir que algo não existe só porque não foi encontrado rapidamente.

## 3. Princípio de produto

Não é um "ticketing system". Trabalha com entidades de segurança:

```
REPORT → ALERT → INCIDENT → CASE/INVESTIGATION → TASKS → OBSERVABLES →
EVIDENCE → THREAT INTELLIGENCE → RESPONSE → RECOVERY → LESSONS LEARNED
```

## 4. Modelo unificado de incidente

Um incidente pode conter: reports, alerts, cases, investigations, tasks,
observables, IOCs, assets, users, evidence, TTPs, threat actors, malware,
campaigns, communications, response actions, timeline, lessons learned.

Não transformar tudo numa única entidade genérica.

## 5. Melhorias inspiradas no RTIR

**Incident Reports** — criação manual, via API, email, webhook, automática;
classificação, prioridade, severidade, atribuição, histórico, anexos,
relacionamento.

**Incidents** — ID único, severidade, prioridade, categoria, subcategoria,
owner, team, SLA, status, TLP, PAP, business impact, technical impact,
confidence, classification.

**Relationships** — incident↔incident, report→incident, alert→incident,
incident→investigation, incident→countermeasure, incident→evidence. Permitir
merge, split, duplicate, related, parent/child.

**Investigations** e **Countermeasures** associadas ao incidente.

## 6. Melhorias inspiradas no TheHive

Alert, Case, Task, Observable, TTP, Evidence, Timeline, Collaboration,
Reporting, Automation — integrados com o modelo de Incident Management.

**Alert Management** — ingestão, normalização, triagem, classificação, severity,
priority, deduplicação, correlação, agrupamento, fecho, conversão para
incidente, associação a incidente existente.

## 7. Alert correlation engine

```
100 alerts → Correlation Engine → 7 related groups → 3 incidents
```

Correlacionar por: IP, domínio, hash, URL, utilizador, hostname, asset, source,
TTP, malware, threat actor, campaign, janela temporal, similaridade. Evitar
criação excessiva de incidentes duplicados.

## 8. Deduplicação

Detectar automaticamente quando alerts representam o mesmo evento. Permitir
merge automático e manual, regras configuráveis e **explicação da correlação**.

## 9. Case management

Cada investigação tem um Case: incident, alerts, tasks, observables, evidence,
assets, TTPs, timeline, comments, notes, response, reports.

## 10. Task management

Criação, atribuição, prioridade, prazo, status, dependências, checklist,
comentários, evidências, escalonamento, recorrência, conclusão, reabertura.
Criação automática por playbooks.

## 11. Observable / IOC management

Tipos: IPv4, IPv6, domínio, URL, email, MD5, SHA1, SHA256, hostname, filename,
MAC, username, CVE, certificate, process, registry key, cloud resource,
container, custom.

Cada observable: Type, Value, Confidence, Severity, First Seen, Last Seen,
Source, Tags, TLP, PAP, Status, Expiration, Related Incidents, Related Cases.

## 12. IOC lifecycle

`Unknown → Suspicious → Malicious → Confirmed → Benign → Expired`. Manter
histórico.

## 13. Threat intelligence

Módulo próprio. Integrar futuramente com MISP, STIX, TAXII, VirusTotal,
AlienVault OTX, AbuseIPDB, feeds internos e externos. **Não acoplar ao core** —
criar um *Connector Framework*.

## 14. MISP

Integração bidireccional: importar/exportar eventos e IOCs, sincronização,
enrichment, relacionamento, criação de eventos, consulta, tags, TLP, galaxy,
threat actor, malware, campaign.

## 15. MITRE ATT&CK

Suporte nativo a tactics, techniques, sub-techniques, procedures, groups,
software, campaigns. Associar a incident, case, observable, malware, threat
actor, task, detection, evidence. **Linguagem comum para descrever comportamento
adversário.**

## 16. Threat actor management

Name, aliases, groups, campaigns, malware, infrastructure, TTPs, IOCs,
incidents.

## 17. Malware management

Family, hashes, files, domains, IPs, TTPs, campaigns, incidents.

## 18. Campaign management

Threat actor, malware, infrastructure, TTPs, incidents.

## 19. Cyber investigation graph

Camada gráfica para visualizar relações:

```
Threat Actor → Campaign → Malware → Hash → IP → Domain → Asset → Incident
```

Permitir pivot: "mostrar tudo relacionado a este hash", "todos os incidentes
relacionados a este IP", "outros casos envolvendo este utilizador", "TTPs
relacionados".

## 20. Similarity engine

Ao abrir um novo incidente, propor incidentes possivelmente relacionados **com a
razão**: shared IP, shared hash, same asset, same user, same TTP, same domain,
temporal proximity. Não apenas devolver um score sem explicação.

## 21. Evidence management

Suportar ficheiros, screenshots, logs, PCAP, emails, documentos, imagens,
vídeos, memória, dumps, hashes.

Cada evidência: Evidence ID, SHA256, MD5 opcional, Filename, MIME, Size, Source,
Collected By, Collected At, Case, Incident, Classification, TLP.

## 22. Chain of custody

Registar: Collected, Stored, Accessed, Downloaded, Analyzed, Exported, Shared.
Cada acção com User, Timestamp, Action, Source, Destination, Hash. **A evidência
original não deve ser sobrescrita.**

## 23. Object storage

Preservar o storage existente. Preparar suporte para S3, MinIO, cloud object
storage, com encryption, versioning, checksum, access control e retention.

## 24. Timeline

Timeline unificada, com eventos automáticos, manuais, de integrações e acções do
analista.

## 25. Asset management

Servers, endpoints, laptops, mobile, network devices, cloud workloads,
applications, databases, websites, APIs, user accounts, containers.

Campos: Asset ID, Hostname, IP, MAC, OS, Owner, Department, Location,
Criticality, Tags, Vulnerabilities, Incidents, Alerts.

## 26. User / identity context

Relacionar incidentes com utilizador, conta, departamento, role, dispositivo,
autenticações, localização e eventos de identidade.

## 27. SLA engine

Response SLA, triage SLA, containment SLA, resolution SLA, escalation, breach
detection. Tudo configurável. Exemplo: `Critical: Response = 15 min, Triage = 30
min, Containment = 1 hour`.

## 28. Escalation engine

`Critical → 15 min → Senior Analyst → 30 min → SOC Manager → 60 min → CISO`.

## 29. Workflow engine

Workflows configuráveis **sem editar código**:

```
WHEN Incident Severity = Critical
IF   Asset Criticality = High
THEN Assign L2; Start SLA; Enrich IOC; Notify Manager; Create Task
```

## 30. Playbook engine

Playbooks para phishing, malware, ransomware, DDoS, brute force, account
compromise, data breach, suspicious login, web attack, insider threat,
vulnerability exploitation.

Cada playbook: Trigger, Steps, Conditions, Actions, Approvals, Tasks,
Notifications, Evidence, Closure criteria.

## 31. Automation engine

Block IP, block domain, block hash, disable account, isolate endpoint, send
email, notify Teams/Slack, create MISP event, update firewall, create ticket,
executar script controlado. **Acções destrutivas exigem aprovação humana.**

## 32. Human-in-the-loop

```
Low Risk      → automático
Medium Risk   → aprovação do analista
High Risk     → aprovação do gestor
Critical      → dupla aprovação
```

## 33. Cortex-like analyzer/responder engine

```
Observable → Analyzer → Result        (IP→reputation, Hash→VirusTotal, …)
Observable → Responder → Action       (IP→firewall block, Account→disable, …)
```

## 34. Wazuh integration

`Wazuh Alert → Platform → Correlation → Incident`. Suportar API, webhook quando
aplicável, alert ingestion, agent information, vulnerability context, endpoint
context, rule information.

## 35. SIEM / EDR / IDS connector framework

Preparar para Wazuh, Splunk, Elastic, Microsoft Sentinel, QRadar, Suricata,
Snort, Zeek, Microsoft Defender, CrowdStrike, SentinelOne e outros. **Não
implementar todos imediatamente** — criar arquitectura extensível.

## 36. Email ingestion

Mailbox de segurança (`security@company`) para phishing reports, abuse reports,
notificações externas e alertas automáticos. Extrair sender, recipient, subject,
URL, domínio, IP, anexos e hashes.

## 37. Portal externo

Portal para clientes/constituency: reportar incidente, carregar evidência,
acompanhar report, responder ao SOC, receber actualizações, descarregar
relatório. **O utilizador externo nunca deve aceder a dados internos.**

## 38. Multi-tenancy

`Platform → Tenant A/B/C`, cada um com users, teams, incidents, alerts,
evidence, integrations, workflows, playbooks e policies. Isolamento rigoroso.

## 39. RBAC + ABAC

**RBAC** — Super Admin, Platform Admin, SOC Manager, Incident Manager, Senior
Analyst, Analyst, Threat Intelligence Analyst, Forensic Analyst, Auditor,
External User.

**ABAC** (opcional) — permissões por tenant, organization, team, classification,
resource, severity, case, geographic scope.

## 40. Restricted cases

`Public, Internal, Confidential, Restricted, Highly Restricted`. Apenas
utilizadores autorizados acedem.

## 41. Break-glass access

`Request emergency access → Reason → Approval → Temporary access → Automatic
expiration → Full audit`.

## 42. Audit log

Registar WHO, WHAT, WHEN, WHERE, BEFORE, AFTER, RESULT. Eventos: login, logout,
create, update, delete, export, download, assignment, escalation, evidence
access, playbook execution, approval, rejection, integration action.

## 43. Audit tamper resistance

Append-only, hash chaining, WORM, external immutable storage, digital
signatures.

## 44. Security

Rever contra SQL injection, XSS, CSRF, SSRF, command injection, path traversal,
XXE, insecure deserialization, broken access control, IDOR, privilege
escalation, file upload attacks, rate-limit bypass, API abuse, secret leakage.

## 45. Authentication

Password, MFA, TOTP, WebAuthn/passkeys futuramente, OIDC, OAuth2, SAML, LDAP,
Active Directory, Keycloak. **Não remover o sistema actual se estiver a
funcionar.**

## 46. API security

API keys, scopes, expiration, rotation, revocation, rate limiting, request
validation, schema validation, audit.

## 47. Webhook security

HMAC, signatures, timestamp, replay protection, IP allowlist, TLS.

## 48. Secrets

Nunca em source code, frontend, logs, git, ou base de dados sem encryption.
Considerar secret manager/Vault.

## 49. AI assistant

Camada de IA segura, que pode: resumir incidentes e timeline, extrair IOC,
sugerir severity, classificação, técnicas ATT&CK, encontrar incidentes
semelhantes, sugerir próximos passos, gerar relatório, pesquisar Knowledge Base,
explicar relações no graph. **A IA nunca é autoridade absoluta.**

## 50. AI explainability

Toda a recomendação deve informar: Recommendation, Confidence, Reason, Evidence,
Sources. **Não apresentar inferências como factos.**

## 51. AI security

Tenant isolation, data classification, PII masking, prompt injection protection,
output validation, model access control, audit, provider policy, LLM local
opcional. Nunca enviar dados confidenciais a terceiros sem política explícita.

## 52. AI human approval

A IA pode recomendar "Isolate HOST-01", mas acções de impacto exigem aprovação
conforme a política.

## 53. Knowledge base

Procedures, runbooks, playbooks, investigation guides, lessons learned,
policies, analyst notes, resolved case knowledge.

## 54. Lessons learned

Após o fecho: o que aconteceu? causa raiz? o que funcionou? o que falhou? que
controlos falharam? o que deve mudar? acções recomendadas? **Gerar tasks para
corrigir gaps.**

## 55. Continuous improvement

```
Incident → Root Cause → Control Gap → Recommendation → Task →
Implementation → Verification → Detection Improvement
```

## 56. Detection engineering

Registar/relacionar Sigma, YARA, Suricata, Snort, KQL, SPL, EQL:
`Detection Rule → Technique → Incident → Evidence`.

## 57. ATT&CK coverage

Dashboard de cobertura por táctica, para identificar gaps.

## 58. Dashboards

Por perfil: **Analyst** (my alerts/incidents/tasks, critical alerts, SLA, IOC);
**SOC Manager** (backlog, workload, MTTA, MTTR, SLA, incidents by severity);
**CISO** (risk, business impact, trends, critical incidents, compliance);
**Administrator** (users, integrations, health, audit, storage, workers).

## 59. KPIs

MTTD, MTTA, MTTR, MTTC, false-positive rate, SLA compliance, incident volume,
alert volume, analyst workload, backlog, escalation count.

## 60. Business impact

Financial, Operational, Reputation, Legal, Confidentiality, Integrity,
Availability.

## 61. Risk engine

Calcular risco com factores configuráveis: severity, asset criticality, threat
intelligence, confidence, exposure, business impact. **O administrador deve
poder configurar a fórmula.**

## 62. Search

Pesquisa global por incident ID, case ID, alert, IP, domínio, URL, hash, user,
hostname, asset, CVE, threat actor, malware, campaign. Com filters, saved
searches, advanced query, date range, fuzzy search.

## 63. Custom views

"My Critical Incidents", "Unassigned Alerts", "Overdue Tasks", "Phishing",
"Ransomware", "High Risk". Cada utilizador guarda as suas.

## 64. Bulk operations

Seleccionar múltiplos alerts/incidents/observables/tasks e executar assign, tag,
close, merge, escalate, export.

## 65. Command palette

`Ctrl + K` — search incident, search IOC, create incident, create task, run
playbook, open case.

## 66. Notification engine

Email, push, Teams, Slack, webhook, SMS futuramente. Configurar por severity,
event, user, team, tenant.

## 67. Report generation

Incident, Executive, Technical, Forensic, Threat Intelligence, Monthly SOC, SLA
e Compliance reports. Exportar PDF, DOCX, CSV, JSON, STIX.

## 68. Data retention

Configurável por tenant, evidence, incident, audit, alert, logs. **Nunca apagar
evidências críticas automaticamente sem política explícita.**

## 69. Backup

Full, incremental, retention, encryption, restore, restore testing.

## 70. Disaster recovery

Documentar RPO, RTO, recovery, backup, failover.

## 71. Observability

Structured logging, metrics, traces, health checks, integration health, worker
health. Considerar OpenTelemetry.

## 72. Integration health

Dashboard com estado de cada integração (Wazuh, MISP, Cortex, Email, Storage,
Database, Workers), last sync, errors, latency, events received, rate limits.

## 73. Connector framework

Cada integração: name, version, authentication, permissions, inputs, outputs,
health check, rate limit, logs, configuration. **Não acoplar ao domínio
principal.**

## 74. Plugin architecture

Connector, Analyzer, Responder, Workflow e UI plugins.

## 75. Migration

Permitir futuramente importar do **RTIR** (users, tickets, incidents,
investigations, countermeasures, attachments, history) e do **TheHive** (alerts,
cases, tasks, observables, attachments, TTPs).

## 76. Interoperability

REST API, webhooks, STIX, TAXII, MISP format, JSON, CSV. Evitar vendor lock-in.

## 77. UX / UI

Profissional, inspirada na experiência visual de ferramentas SOC (TheHive, RTIR,
Wazuh), mas **sem copiar identidade visual, logos, assets ou layouts
proprietários**. Criar identidade própria.

## 78. Paleta de cores

**Dark mode (principal)**

```
Background        #0B1120      Text              #F8FAFC
Surface           #111827      Text Secondary    #94A3B8
Surface Elevated  #172033      Success           #22C55E
Border            #263247      Warning           #F59E0B
Primary           #4F8CFF      Danger            #EF4444
Primary Hover     #6EA3FF      Critical          #DC2626
                               Info              #38BDF8
```

**Light mode**

```
Background        #F8FAFC      Text              #0F172A
Surface           #FFFFFF      Text Secondary    #64748B
Surface Elevated  #F1F5F9      Success           #16A34A
Border            #E2E8F0      Warning           #D97706
Primary           #2563EB      Danger            #DC2626
                               Info              #0284C7
```

A cor deve indicar estado, não decorar a interface.

## 79. Severity colors

```
Informational → #38BDF8      High     → #F97316
Low           → #22C55E      Critical → #DC2626
Medium        → #F59E0B
```

**Nunca depender apenas da cor** — usar também ícone, texto e badge.

## 80. Layout SOC

Sidebar, top navigation, global search, notifications, workspace, context panel.
O analista deve aceder a Alerts, Incidents, Cases, Investigations, Tasks,
Observables, Evidence, Threat Intel, Assets, Playbooks e Reports sem navegar por
muitas telas.

## 81. Incident page

```
Header: ID │ Severity │ Status │ Owner │ SLA

Tabs: Overview │ Timeline │ Alerts │ Cases │ Tasks │ Observables │
      Evidence │ Assets │ TTPs │ Threat Intelligence │ Communications │
      Response │ Audit │ Report
```

## 82. Single pane of glass

O analista não deve precisar de abrir cinco sistemas para compreender um
incidente. Agregar alert + threat intelligence + asset + user + IOC + timeline +
evidence numa única investigação.

## 83. Não duplicar ferramentas desnecessariamente

A plataforma é uma camada de **orquestração e investigação**; não substitui
SIEM, EDR, IDS, Threat Intelligence, firewall ou sandbox — integra-os.

## 84. Princípio de arquitectura

Separar Detection, Intelligence, Incident Management, Investigation, Automation,
Response e Reporting, permitindo integração entre todos.

## 85. Modelo de dados

Antes de modificar tabelas: analisar schema actual, identificar tabelas
existentes, reutilizar entidades compatíveis, criar migrations, evitar
destructive migrations, preservar dados de produção, criar índices, verificar
integridade referencial.

## 86. API compatibility

Antes de modificar um endpoint, verificar consumidores, frontend, integrações,
mobile e automações. Se necessário, versionar (`/api/v1`, `/api/v2`).

## 87. Testes

Para cada funcionalidade nova: unit tests, integration tests, API tests,
authorization tests, security tests, regression tests. **Não considerar uma
funcionalidade concluída apenas porque a tela aparece.**

## 88. Security testing

Broken access control, IDOR, tenant isolation, privilege escalation, upload
vulnerabilities, API abuse, authentication bypass, CSRF, XSS, SSRF, SQL
injection.

## 89. Regression test

`Existing functionality + New functionality = Regression suite`. A plataforma já
está em produção; **estabilidade é requisito funcional e operacional crítico**.

## 90. Migration safety

Reversível quando possível, com backup, sem apagar dados silenciosamente, com
rollback e teste em staging.

## 91. Feature flags

Libertar funcionalidades gradualmente (`AI_ASSISTANT=false`, `GRAPH_ENGINE=true`,
`MISP_INTEGRATION=false`).

## 92. Staging

`Development → Testing → Staging → Migration validation → Production`. Não
implementar directamente em produção.

## 93. Performance

Não introduzir funcionalidades que façam a página de incidente correr 50
consultas. Usar indexing, caching, pagination, lazy loading, async jobs e
background workers.

## 94. Pagination

Nunca carregar milhares de alerts, incidents, evidence ou observables.

## 95. Async processing

Operações pesadas em workers: `Upload → Queue → Scanner → Result`,
`IOC → Queue → Enrichment → Result`.

## 96. Product differentiation

Superar as referências sobretudo em: UX, correlação, investigação gráfica,
automação, integração, AI assistida, multi-tenancy, evidence management,
explainability, deployment, API-first architecture, migration, collaboration e
continuous improvement. **Não copiar funcionalidades cegamente.**

## 97. O que não deve ser alterado sem necessidade

Preservar funcionalidades, dados, APIs, autenticação, deployment, integrações e
componentes estáveis. Qualquer refactor grande apresenta:
`Current → Problem → Proposed → Migration → Risk → Rollback`.

## 98. Roadmap

- **P0 — não pode faltar:** Incidents, Alerts, Cases, Tasks, Observables,
  Evidence, Timeline, RBAC, Audit, API, Search, Dashboard, SLA.
- **P1 — SOC:** Wazuh, MISP, ATT&CK, correlation, enrichment, playbooks,
  notifications, workflow engine.
- **P2 — Advanced:** investigation graph, analyzer/responder engine, asset
  management, threat actors, malware, campaigns, external portal, migration
  tools.
- **P3 — Intelligence:** AI assistant, similarity engine, recommendation engine,
  AI IOC extraction, knowledge base, continuous improvement.
- **P4 — Enterprise:** multi-region, HA, advanced compliance, marketplace,
  federation, enterprise migration, advanced DR.

## 99. Requisito final de implementação

Antes de programar: verificar se já existe (total ou parcialmente), verificar
dependências e impacto no banco, na API, no frontend e na segurança;
implementar, testar, documentar, executar regression tests.

## 100. Resultado esperado

```
                    DATA SOURCES
       SIEM   EDR   IDS   EMAIL   USER REPORT
        └──────┴─────┴──────┴──────────┘
                       ▼
                INGESTION ENGINE
                       ▼
              NORMALIZATION ENGINE
                       ▼
              CORRELATION ENGINE
                 ┌─────┴─────┐
              ALERT       REPORT
                 └─────┬─────┘
                       ▼
                    INCIDENT
                       ▼
                 INVESTIGATION
       ┌───────────────┼────────────────┐
   OBSERVABLES      EVIDENCE          ASSETS
       ▼               ▼                ▼
 THREAT INTEL       FORENSICS       CONTEXT
       ▼
    ATT&CK → GRAPH → DECISION → PLAYBOOK →
    AUTOMATION / APPROVAL → RESPONSE → RECOVERY →
    LESSONS LEARNED → DETECTION IMPROVEMENT
```

## 101. Referências oficiais (benchmark)

Usar apenas como referência funcional e arquitectural — **não copiar código,
marca, identidade visual ou interface proprietária**.

- **RTIR** — <https://docs.bestpractical.com/release-notes/rtir/index.html> —
  incident reports, incidents, investigations, countermeasures, ticket
  relationships, workflows, queues, permissions. Série estável: RTIR 6.0.3.
- **TheHive** — <https://strangebee.com/thehive/> ·
  <https://docs.strangebee.com/> — alerts, cases, tasks, observables, TTPs,
  collaboration, investigation, reporting, custom views, automation.
- **Cortex** — <https://strangebee.com/cortex/> ·
  <https://docs.strangebee.com/cortex/> — analyzers, responders, enrichment,
  active response, API, integração com observables.
- **MISP** — <https://www.misp-project.org/> — threat intelligence, IOC,
  sharing, feeds, taxonomies, galaxies, correlation, STIX, APIs.
- **Wazuh** — <https://wazuh.com/> · <https://documentation.wazuh.com/> — SIEM,
  XDR, endpoints, cloud, vulnerability detection, security monitoring, alerts.
- **MITRE ATT&CK** — <https://attack.mitre.org/> — tactics, techniques,
  sub-techniques, procedures, threat groups, software, attack mapping.

---

## Instrução final

**Não começar por criar código.** Primeiro uma auditoria completa da aplicação
existente. Depois: Current Architecture, Current Features, Feature Gap Analysis,
Database Gap Analysis, API Gap Analysis, Security Gap Analysis, UX Gap Analysis,
Integration Gap Analysis, Recommended Architecture Changes, Migration Plan,
Implementation Roadmap.

Para cada alteração:

```
Existing capability → Gap → Improvement → Technical design → Migration →
Implementation → Tests → Security validation → Documentation
```

**A plataforma já está em produção. Estabilidade, segurança e compatibilidade
têm prioridade sobre novas funcionalidades.** Não apagar nem substituir
funcionalidades existentes apenas para seguir este documento. O objectivo é
evoluir a plataforma existente para uma solução de Cyber Incident Response de
nível profissional.
