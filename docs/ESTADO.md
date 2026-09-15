# SHEISA — Estado do projecto e continuação

> Documento de passagem de testemunho. Descreve o que está **feito e
> verificado**, o que **falta**, e como retomar o trabalho sem repetir análise.
>
> Última actualização: 2026-09-15 (motor de recomendações e suite de testes concluídos)

---

## ONDE ESTAMOS

| | |
|---|---|
| **Feito** | Fundação · ingestão · triagem · correlação · incidentes · evidências · acções · playbooks · painel · grafo · relatórios · administração · **motor de recomendações (5.1)** · **suite de testes (5.3)** |
| **A seguir** | **5.2 cenário de demonstração** → 5.4 frontend → 5.5 laboratório Wazuh → 5.7 documentação |
| **Backend** | 106 rotas, 21 domínios, ~19k linhas |
| **Testes** | 211 a passar, 74% de cobertura |
| **Ambiente** | Python 3.13.7 · PostgreSQL 16 em Docker · API em :8099 |
| **Git** | tudo em `main`, sincronizado com `github.com/Bauirxx/sheisaproject` |

**Documentos de referência, agora versionados:**

- [`MONOGRAFIA-CAP4.md`](MONOGRAFIA-CAP4.md) — capítulo IV da monografia. É o que
  vai ser defendido. **§4.14 é o cenário de demonstração.**
- [`BRIEFING.md`](BRIEFING.md) — especificação técnica de 101 secções.
- Este ficheiro — estado do código e como retomar.

> **Numeração das secções no código.** Os comentários citam `§4`, `§12`, `§16`,
> `§32`… Essa numeração vem de um briefing anterior que nunca foi versionado e
> **não corresponde** a nenhum dos dois documentos acima. `BRIEFING.md` traz uma
> tabela de equivalências. Na prática não é um problema: cada citação no código
> vem acompanhada da frase que explica a regra, e essa frase é autossuficiente.

> **Correcção ao que este documento dizia.** Até 2026-09-15 lia-se aqui "os 19
> passos do §33". O cenário de demonstração tem **10 passos** e está em
> [`MONOGRAFIA-CAP4.md` §4.14](MONOGRAFIA-CAP4.md#414-exemplo-de-cenário-para-demonstrar-o-protótipo).
> O "§33" era uma citação do briefing antigo; os 19 passos não existem em
> documento nenhum e eram provavelmente uma contagem errada.

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
Python 3.13.7 · Node 22.20 · Docker 27.5.1 · PostgreSQL 16
backend/.venv          ambiente virtual (recriado em 2026-09-15)
docker compose up -d   sheisa-db :15433 · sheisa-db-test :15434
```

> **Nota de portabilidade.** O projecto foi construído em Python 3.11.9. Numa
> máquina nova (clone de raiz) foi reposto em **Python 3.13.7** — todas as
> dependências de `requirements-dev.txt` instalam sem alteração de versões e
> `app.main` importa sem avisos. `ruff.toml` mantém `target-version = "py311"`
> de propósito: garante que o código não usa sintaxe que quebre em 3.11.
>
> Depois de um clone **não existe** `.env`, `backend/.venv`, `var/` (onde vive
> a cópia local do bundle STIX do ATT&CK) nem as contas do §6 — tudo isso é
> ignorado pelo git. As pastas `frontend/` e `lab/` também não vêm no clone
> porque estavam vazias e o git não versiona pastas vazias.

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

### Motor de recomendações (§12)
- `app/intelligence/recommendations.py`: 8 geradores determinísticos —
  promoção, severidade e falso positivo sobre alertas; classificação,
  priorização, técnicas ATT&CK, playbook e próximo passo sobre incidentes.
- Mesma decomposição por `Factor` da triagem: **a soma dos factores confere
  sempre com a confiança apresentada** (verificado em execução).
- Quatro invariantes com efeito observável:
  - **não inventa** — a técnica proposta é validada contra o catálogo ATT&CK
    carregado antes de sair;
  - **não insiste** — uma recomendação rejeitada com a mesma proposta não volta
    a ser levantada (garantido pelo histórico, verificado a correr);
  - **não ultrapassa** — a confiança de uma inferência está limitada a 75; a
    associação MITRE criada é `is_asserted=False`;
  - **não dá poderes** — aplicar exige a permissão que a operação exigiria à
    mão. Sem ela a recomendação fica ACEITE, `applied=false`, e a auditoria
    regista NEGADO.
- Migração `0004_reco_unica`: índice único **parcial** que impede duas
  recomendações pendentes do mesmo tipo sobre o mesmo alvo, deixando o
  histórico de decididas acumular (é dele que vem a regra "não insiste").
- Aplicação passa sempre pelos serviços reais (`incident_service.transition`,
  `promote_alert`, `playbook_engine.start_execution`) — uma recomendação aceite
  tem exactamente o mesmo efeito que a acção feita à mão.

### Suite de testes (§32) — 211 testes, 74% de cobertura
`backend/tests/`, 17 ficheiros. Corre com `./.venv/Scripts/python.exe -m pytest`
(a configuração está em `pytest.ini` e `.coveragerc`).

Cobre tudo o que o §32 enumera: autenticação, autorização, CRUD, filtros,
transições de estado, auditoria, normalizadores, deduplicação, correlação,
pontuação, aprovações, uploads, endpoints protegidos e um teste ponta-a-ponta
(evento → alerta → incidente → acção → resolução → relatório). Acrescenta
recomendações, playbooks, painel e grafo.

Quatro decisões da infra-estrutura de teste, explicadas em `tests/conftest.py`:

1. **O esquema vem das migrações**, não de `Base.metadata.create_all`. A
   imutabilidade da auditoria vive em gatilhos criados por `0002`/`0003`; um
   esquema gerado dos metadados teria as tabelas e nenhuma das garantias, e o
   teste que verifica que um UPDATE é recusado passaria a testar nada.
   Obrigou a `alembic/env.py` a aceitar uma ligação injectada
   (`config.attributes["connection"]`), o padrão documentado do Alembic; o
   comportamento na linha de comandos não muda.
2. **Cada teste corre numa transacção revertida no fim.** Limpar tabelas entre
   testes é impossível por construção: os gatilhos recusam DELETE e TRUNCATE
   sobre `audit_logs`. A sessão usa `join_transaction_mode="create_savepoint"`,
   pelo que os `commit()` reais da aplicação libertam savepoints.
3. **Cada pedido HTTP recebe uma sessão nova**, como em produção, ligada à mesma
   ligação. Partilhar um `Session` entre pedidos era mais simples e produzia
   avarias que só existiam no teste.
4. **A preparação de sessão é síncrona** (`asyncio.run`), porque o
   pytest-asyncio 0.25 corre fixtures de sessão e testes em ciclos de eventos
   distintos e uma ligação asyncpg não atravessa ciclos.

> **`.coveragerc` tem `concurrency = greenlet` e isso não é opcional.** Sem essa
> linha, o rastreador perde tudo o que se executa depois do primeiro `await`
> sobre a base de dados: `auth_service` aparecia com 26% de cobertura estando
> exaustivamente testado (com a linha, 70%). Um número assim levaria a
> reescrever testes que já existem.

### API (106 rotas, 21 domínios)
Autenticação, ingestão, alertas, eventos, incidentes, evidências, tarefas,
activos, IOCs, MITRE, acções, aprovações, playbooks, **recomendações**, painel,
centro de operações, grafo, relatórios, utilizadores, perfis, auditoria,
integrações, notificações.

### Verificado ponta-a-ponta em execução real
- Ingestão Wazuh → alerta → correlação → incidente automático (5 alertas
  agregados em INC-000001, 15 observações, T1110 importada como **afirmada**).
- Playbook suspende em aprovação e **retoma** após decisão.
- Separação de funções: quem propõe **não** aprova (403 + auditoria NEGADO).
- Acção crítica exige justificação escrita (422 sem ela).
- RBAC: analista recebe 403 em `users:manage` e em aprovação crítica.
- Painel, centro de operações e grafo (15 nós / 21 arestas) a devolver dados
  reais.
- Motor de recomendações (2026-09-15, base de dados de raiz):
  - 6 decisões reais de falso positivo sobre a regra 550 → recomendação de
    descarte com confiança 60 (taxa 100% penalizada em -40 pela amostra de 6);
  - aceitar a recomendação de próximo passo moveu INC-000001 de NOVO a TRIAGEM
    **e preencheu `acknowledged_at`** — sinal de que passou por
    `incident_service.transition` e não por uma escrita directa;
  - rejeitar uma recomendação e voltar a gerar: não reapareceu;
  - analista sem `playbooks:execute` a aceitar um playbook → ACEITE,
    `applied=false`, auditoria NEGADO com o motivo;
  - inferência MITRE: grupos `syscheck`/`file_integrity` → T1565 (Data
    Manipulation), associada a INC-000002 como **inferida**, confiança BAIXA,
    com justificação e evidência anexadas.

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

8. **`applied` a mentir.** Na primeira versão do serviço de recomendações,
   `rec.applied = True` era escrito a seguir ao despacho, mesmo quando o
   aplicador tinha desistido sem alterar nada (falta de permissão para o campo
   concreto, proposta já satisfeita). Os aplicadores passaram a devolver
   `(aplicou, efeito)`.
9. **Alteração parcial em `ALTERAR_CAMPOS`.** Uma proposta que muda severidade
   *e* prioridade escrevia campo a campo e desistia a meio se o segundo fosse
   recusado — deixando o alvo meio alterado e a auditoria a registar só parte.
   Agora valida tudo numa primeira passagem e só escreve na segunda.

### Defeitos encontrados pela suite de testes (2026-09-15)
Três defeitos reais do produto, nenhum deles hipotético — o terceiro foi
reproduzido no servidor de desenvolvimento antes de ser corrigido:

10. **`incidents:close` não era verificada em lado nenhum.** A permissão estava
    definida e atribuída só ao INVESTIGADOR e ao GESTOR, mas a rota de transição
    só exigia `incidents:transition` — um analista encerrava incidentes. A
    verificação tem de ser feita no corpo do handler, porque o estado de destino
    vem no pedido e não na rota.
11. **`POST /incidents/{id}/assign` devolvia `assignee: null`.** A relação é
    `lazy="selectin"`, carregada com a consulta; alterar a chave estrangeira não
    actualizava o objecto em memória. A interface mostraria "sem responsável" ao
    utilizador que acabara de o escolher.
12. **HTTP 500 ao marcar um incidente como falso positivo** (confirmado a
    correr, não só em teste). `updated_at` tem `onupdate` do lado do servidor,
    pelo que um flush o deixa *expirado*; a releitura acontecia já durante a
    serialização da resposta, fora do contexto assíncrono — `MissingGreenlet`.
    Só se manifestava quando algo forçava um flush entre a alteração e a
    resposta, e marcar como falso positivo consulta os alertas associados.
    Corrigido com `eager_defaults=True` no `Base` declarativo: o PostgreSQL
    devolve os valores gerados na própria instrução (RETURNING), nada fica
    expirado e não há viagem adicional. **Vale para todos os modelos** — era um
    500 à espera de acontecer em qualquer rota que flush antes de responder.

`ruff check app tests scripts` passa sem avisos; `pytest` passa 211 testes.

## 5. O que FALTA (por ordem sugerida)

### 5.1 Motor de recomendações (§12) — **feito** (ver §4)
Fica por fazer, se houver tempo: recomendações de **correlação** entre
incidentes que partilham indicadores do lado do atacante. Não foi feito de
propósito — o motor de correlação já cria essas ligações automaticamente, e uma
recomendação por cima duplicaria a mesma conclusão em dois sítios. Só vale a
pena se se decidir tornar a correlação uma proposta em vez de um automatismo.

O mapa `GROUP_TO_TECHNIQUE` (15 entradas) é o sítio a alargar se se quiser
cobrir mais grupos de regra: acrescentar uma linha chega, porque o
identificador é sempre validado contra o catálogo antes de ser proposto.

### 5.2 Cenário de demonstração — **por fazer, já desbloqueado**
`app/services/demo_service.py` é referido por `scripts/manage.py demo` mas
**não existe** (o comando falha). Deve percorrer os **10 passos do §4.14 da
monografia** usando o **fluxo real** da aplicação (ingestão pela API, não
inserções directas) e marcar tudo com `is_demo_data=True`.

Os 10 passos, do documento:

| Passo | Acção |
|---|---|
| 1 | O alerta é identificado (Suricata detecta actividade suspeita). |
| 2 | O analista regista/converte o alerta num incidente. |
| 3 | O sistema gera automaticamente o identificador. |
| 4 | O analista classifica o incidente. |
| 5 | Define a severidade como Alta. |
| 6 | Atribui o incidente ao responsável. |
| 7 | Adiciona comentários e evidências. |
| 8 | O incidente passa a Em Investigação. |
| 9 | Depois da resposta, passa a Resolvido. |
| 10 | Após validação, passa a Encerrado. |

O cenário deve usar **Suricata** como fonte, porque é essa a fonte do §4.14 —
e não Wazuh, que foi a fonte usada nas verificações manuais até agora.

### 5.3 Testes (§32) — **feito** (ver §4)
211 testes, 74% de cobertura. O que a lista do §32 pede está coberto.

Onde a cobertura continua baixa, e porquê:
- `analytics_service` 14% — as consultas de agregação têm muitos ramos por
  combinação de filtros; os endpoints estão testados, as combinações não;
- `mitre_service` 19%, `integration_service` 21% — ambos falam com o exterior
  (descarga do bundle STIX, conectores); testá-los a sério exige duplos de
  teste, que ainda não existem;
- `timeline_service` e `seed_service` a 0% — só são exercitados pela CLI e pela
  rota de linha temporal, que não têm teste;
- `playbooks/engine` — os caminhos de suspensão e retoma estão testados; os
  tipos de passo menos usados não.

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
| `admin@sheisa.local` | ADMINISTRADOR | `LaJdxJVBcQobCy42tSya` (gerada no `init` de 2026-09-15) |
| `gestor@sheisa.local` | GESTOR | `GestorSeguro2026` |
| `analista@sheisa.local` | ANALISTA_SOC | `AnalistaSeguro2026` |

As contas de gestor e analista **não** sobrevivem a um clone: são criadas pela
API (`POST /api/users`) com o token de administração, não por `manage.py`.

Chave de ingestão Wazuh: criar com
`python -m scripts.manage create-api-key --name "..." --kind WAZUH`
(a chave só é apresentada uma vez).

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
  intelligence/triage (motor determinístico explicável),
               recommendations (8 geradores; mesma decomposição por Factor)
  playbooks/   engine (suspende/retoma em aprovação)
  integrations/base, wazuh_connector, siem_connectors (QRadar/NetScout), registry
  services/    auth, bootstrap, ingestion, incident, evidence, action,
               integration, mitre, seed, analytics, report, timeline,
               recommendation (sincronizar / decidir / aplicar)
  api/v1/      auth, ingest, alerts, incidents, investigation, catalog,
               response, recommendations, analytics, reports, admin

backend/tests/  conftest (migração, transacção por teste, contas), e por tema:
                infraestrutura, autenticacao, autorizacao, auditoria, ingestao,
                triagem, correlacao, incidentes, resposta, playbooks,
                recomendacoes, evidencias, filtros, painel, ponta_a_ponta
  schemas/     common, auth, alert, incident, catalog, response
```

## 8. Como retomar

1. `docker compose up -d db db-test` e `./scripts/api.sh start`.
2. Confirmar: `curl http://127.0.0.1:8099/api/health/ready`.
3. Ler este ficheiro e a secção 5.
4. Trabalhar pela ordem 5.2 → 5.5 (demo, frontend, lab); 5.1 e 5.3 estão feitos.
5. Antes de cada commit: `./.venv/Scripts/python.exe -m ruff check app tests scripts`
   e `./.venv/Scripts/python.exe -m pytest`.
