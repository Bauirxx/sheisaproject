# SHEISA — Estado do projecto e continuação

> Documento de passagem de testemunho. Descreve o que está **feito e
> verificado**, o que **falta**, e como retomar o trabalho sem repetir análise.
>
> Última actualização: 2026-09-15

---

## 1. O que é

Plataforma de gestão e resposta a incidentes cibernéticos (SOC/CSIRT), para
uma monografia sobre o INCM, inspirada em RTIR, TheHive e Wazuh mas com
arquitectura própria.

**Regra que atravessa tudo (§4 e §34 do briefing):** nada é simulado. Se uma
funcionalidade aparece, tem implementação real; se uma integração não está
verificada, a plataforma diz que não está em vez de fingir.

## 2. Decisões já tomadas (não reabrir sem motivo)

Escolhidas pelo utilizador no arranque:

| Decisão | Escolha |
|---|---|
| Frontend | **React + TypeScript + Vite** |
| Camada de IA (§12) | **Só motor determinístico/estatístico** — sem LLM |
| Wazuh (§26) | **Montar laboratório em Docker** (não há Wazuh existente) |
| Âmbito de fontes | Wazuh + Suricata implementados **e** conectores QRadar + NetScout |

Decisões arquitecturais tomadas durante a construção:

- **`IOC` (entidade global) vs `Observation` (avistamento contextual).** O IOC é
  único por `(tipo, valor)` e carrega reputação; a Observação é "este indicador,
  neste incidente, neste papel, neste instante". É o que permite calcular
  `first_seen`/`last_seen` a partir de avistamentos reais e o que dá arestas ao
  grafo (§21).
- **`Incidente` e `Caso` colapsam numa entidade.** `Campaign` agrupa incidentes
  (§20); "Investigação" é uma *vista* sobre o incidente, não uma tabela.
- **`Event` vs `Alert`.** Event = sinal bruto normalizado (alto volume);
  Alert = asserção de detecção após deduplicação. 4000 tentativas de força
  bruta = 1 alerta com `event_count=4000`.
- **Auditoria append-only ao nível da base de dados** (gatilhos PostgreSQL
  recusam UPDATE, DELETE e TRUNCATE).
- **Ciclo de vida como grafo de transições configurável** em
  `app/core/enums.py` (`INCIDENT_TRANSITIONS`, `ALERT_TRANSITIONS`).

## 3. Ambiente

```
Python 3.11.9 · Node 22.10 · Docker 29 · PostgreSQL 16
backend/.venv          ambiente virtual (ja criado)
docker compose up -d   sheisa-db :15433 · sheisa-db-test :15434
```

Arranque de raiz:

```bash
cd sheisa_project
cp .env.example .env          # e gerar segredos reais
docker compose up -d db db-test
cd backend
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe -m scripts.manage init
./.venv/Scripts/python.exe -m scripts.manage mitre-load
./.venv/Scripts/python.exe -m scripts.manage seed-correlation
./.venv/Scripts/python.exe -m scripts.manage seed-playbooks
./.venv/Scripts/python.exe -m scripts.manage seed-assets
./.venv/Scripts/python.exe -m scripts.manage seed-integrations
./scripts/api.sh start        # http://127.0.0.1:8099/api/docs
```

`scripts/api.sh` mata o servidor **por porta** (em Windows o processo aparece
como `python3.11` e um `pkill` por padrão não lhe acerta — já custou um
diagnóstico errado uma vez).

## 4. Feito e verificado a correr

### Fundação
- 35 tabelas, mapeadores SQLAlchemy a configurar sem erros.
- 3 migrações Alembic aplicadas (esquema, sequências + auditoria imutável,
  bloqueio de TRUNCATE).
- Auditoria imutável **testada**: UPDATE, DELETE e TRUNCATE recusados pelo
  PostgreSQL, linha original intacta.
- RBAC: 49 permissões, 6 perfis. Verificação **sempre** contra a base de dados.
- Autenticação: Argon2id, JWT curto + refresh persistido com rotação e detecção
  de reutilização, bloqueio por tentativas, sem enumeração de contas
  (mensagens e tempos idênticos para utilizador inexistente vs palavra-passe
  errada — **testado**).

### Ingestão e inteligência
- Normalizadores Wazuh (níveis 0–15), Suricata (escala invertida 1=alta) e
  genérico. Payload original sempre preservado.
- Idempotência por `(fonte, id da fonte)` e deduplicação por janela.
- Motor de triagem determinístico 0–100 com **decomposição por factor e razão
  textual**. Taxa de falsos positivos aprendida de decisões reais.
- Motor de correlação com 4 estratégias configuráveis em base de dados.
- MITRE ATT&CK **v19.2 real** carregado: 15 tácticas, 233 técnicas,
  476 subtécnicas. Ordem das tácticas lida da matriz do próprio bundle.

### API (86 rotas, 20 domínios do §30)
Autenticação, ingestão, alertas, eventos, incidentes, evidências, tarefas,
activos, IOCs, MITRE, acções, aprovações, playbooks, painel, centro de
operações, grafo, relatórios, utilizadores, perfis, auditoria, integrações,
notificações.

### Verificado ponta-a-ponta em execução real
- Ingestão Wazuh → alerta → correlação → incidente automático (5 alertas
  agregados em INC-000001, 15 observações, T1110 importada como **afirmada**).
- Playbook suspende em aprovação e **retoma** após decisão.
- Separação de funções: quem propõe **não** aprova (403 + auditoria NEGADO).
- Acção crítica exige justificação escrita (422 sem ela).
- RBAC: analista recebe 403 em `users:manage` e em aprovação crítica.
- Painel, centro de operações e grafo (15 nós / 21 arestas) a devolver dados
  reais.

### Erros reais encontrados e corrigidos (não reintroduzir)
1. **`autoflush=False`** fazia o motor pontuar sobre dados ainda não escritos →
   pontuações silenciosamente erradas. Agora `autoflush=True`, com justificação
   no código.
2. **`ipaddress.is_private`** classifica as gamas RFC 5737 (TEST-NET) como
   privadas → o IP do atacante era descartado como IOC. Substituído por
   `is_external_ip` com lista explícita de gamas internas.
3. **Correlação por entidade partilhada** casava pela **vítima** (hostname) e
   concluía "mesmo actor". Agora só considera papéis do lado do atacante
   (`ATTACKER_SIDE_ROLES`).
4. **`srcuser`/`dstuser` confundidos** — a conta visada era marcada como ACTOR.
   Agora `srcuser`→ACTOR, `dstuser`→ALVO.
5. **Contexto de auditoria vazio.** O FastAPI resolve dependências pela ordem da
   assinatura e `AuditDep` vinha antes da autenticação → **tudo era registado
   como `anonimo`/sistema** e a separação de funções ficava desactivada.
   Resolvido tornando `AuditContext` de resolução **tardia** (lê
   `request.state` no momento da escrita).
6. **403 a virar 500.** `resource_type` recebia o caminho do URL numa coluna de
   40 caracteres. Corrigido e acrescentada truncagem defensiva (`_fit`) para
   que a auditoria nunca faça falhar aquilo que regista.
7. **Porta de aprovação sem nada aprovável.** O passo `SOLICITAR_APROVACAO`
   suspendia a execução sem criar entidade nenhuma → o playbook nunca poderia
   ser retomado. Criado `ActionKind.AUTORIZAR_PROSSEGUIMENTO`.

`ruff check app scripts` passa sem avisos.

## 5. O que FALTA (por ordem sugerida)

### 5.1 Motor de recomendações (§12) — **não começado**
Falta `app/intelligence/recommendations.py`. O modelo `Recommendation` já
existe (com `explanation`, `confidence`, `factors`, `evidence_refs`,
`proposed_change`) e o esquema `RecommendationRead`/`RecommendationDecide` já
está escrito em `app/schemas/response.py`. Falta:
- gerar recomendações (triagem, classificação, próximo passo, playbook,
  inferência MITRE por grupos de regra → técnica, detecção de falso positivo);
- rotas `/api/recommendations` (listar, aceitar/rejeitar, aplicar alteração);
- a permissão `RECOMMENDATIONS_DECIDE` já existe.

**Importante:** cada recomendação tem de trazer explicação, confiança calculada
e os dados que a sustentam. O padrão já usado em `app/intelligence/triage.py`
(dataclass `Factor` com `nome`/`pontos`/`razao`) deve ser reaproveitado.

### 5.2 Cenário de demonstração (§33) — **não começado**
`app/services/demo_service.py` é referido por `scripts/manage.py demo` mas
**não existe** (o comando falha). Deve percorrer os 19 passos do §33 usando o
**fluxo real** da aplicação (ingestão pela API, não inserções directas) e
marcar tudo com `is_demo_data=True`.

### 5.3 Testes (§32) — **não começado, obrigatório**
`backend/tests/` está vazio. `pytest`, `pytest-asyncio` e a base de dados de
teste (`sheisa-db-test` :15434, tmpfs) já estão prontos.
Cobrir: autenticação, autorização, CRUD, filtros, transições de estado,
auditoria, normalizadores, deduplicação, correlação, pontuação, aprovações,
uploads, endpoints protegidos, e um teste ponta-a-ponta
alerta→incidente→acção→resolução→relatório.

### 5.4 Frontend (§28–§30) — **não começado**
`frontend/` está vazio. React + TypeScript + Vite, **interface toda em
português**, 20 páginas do §30, densidade de SOC, grafo investigativo
interactivo. A API já expõe tudo o que é preciso, incluindo
`transicoes_permitidas` em cada incidente (para o frontend não duplicar as
regras do ciclo de vida) e `executavel`/`motivo_nao_executavel` nas acções.

### 5.5 Laboratório Wazuh (§26) — **não começado**
`lab/` tem as pastas mas está vazio. Falta `lab/docker-compose.lab.yml` com
Wazuh manager + agente, e o script `custom-sheisa` para o daemon *integrator*.
Contrato real já estudado e documentado em `app/ingestion/wazuh.py`:
`argv[1]`=ficheiro do alerta, `argv[2]`=api_key, `argv[3]`=hook_url.

### 5.6 Exportação PDF — opcional, degrada bem
`app/reporting/pdf.py` não existe; a rota `/api/reports/{id}/pdf` devolve 503
com explicação. `reportlab` está em `requirements-reports.txt` (falhou a
instalar por causa do Pillow e da rede).

### 5.7 Documentação
Falta `docs/ARQUITECTURA.md` (a análise de FASE 1/2 está só no histórico da
conversa) e um `README.md`.

## 6. Contas e credenciais do ambiente local

Criadas na base de dados de desenvolvimento (**não** são segredos de produção):

| Conta | Perfil | Palavra-passe |
|---|---|---|
| `admin@sheisa.local` | ADMINISTRADOR | `gfvAXtXTHnSBgSKpTYM8` (gerada no `init`) |
| `gestor@sheisa.local` | GESTOR | `GestorSeguro2026` |
| `analista@sheisa.local` | ANALISTA_SOC | `AnalistaSeguro2026` |

Chave de ingestão Wazuh criada localmente com o prefixo `r3i691-N`. Para criar
outra: `python -m scripts.manage create-api-key --name "..." --kind WAZUH`.

> São credenciais de laboratório. Numa instalação real, `manage init` gera uma
> palavra-passe aleatória mostrada uma única vez.

## 7. Mapa do código

```
backend/app/
  core/        config, database, security, permissions, enums (ciclos de vida),
               errors, audit (contexto de resolução tardia), deps, middleware,
               pagination, references
  models/      35 entidades: identity, catalog, telemetry, incident,
               investigation, response, intelligence, system
  ingestion/   base (formato comum), wazuh, suricata, generic, registry
  correlation/ engine (4 estratégias)
  intelligence/triage (motor determinístico explicável)
  playbooks/   engine (suspende/retoma em aprovação)
  integrations/base, wazuh_connector, siem_connectors (QRadar/NetScout), registry
  services/    auth, bootstrap, ingestion, incident, evidence, action,
               integration, mitre, seed, analytics, report, timeline
  api/v1/      auth, ingest, alerts, incidents, investigation, catalog,
               response, analytics, reports, admin
  schemas/     common, auth, alert, incident, catalog, response
```

## 8. Como retomar

1. `docker compose up -d db db-test` e `./scripts/api.sh start`.
2. Confirmar: `curl http://127.0.0.1:8099/api/health/ready`.
3. Ler este ficheiro e a secção 5.
4. Trabalhar pela ordem 5.1 → 5.5 (recomendações, demo, testes, frontend, lab).
5. Antes de cada commit: `./.venv/Scripts/python.exe -m ruff check app scripts`.
