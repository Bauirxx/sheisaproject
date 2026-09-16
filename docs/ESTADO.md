# SHEISA — Estado do projecto e continuação

> Documento de passagem de testemunho. Descreve o que está **feito e
> verificado**, o que **falta**, e como retomar o trabalho sem repetir análise.
>
> Última actualização: 2026-09-15 (recomendações, testes, demonstração e frontend)

---

## ONDE ESTAMOS

| | |
|---|---|
| **Feito** | Fundação · ingestão · triagem · correlação · incidentes · evidências · acções · playbooks · painel · grafo · relatórios · administração · **motor de recomendações (5.1)** · **cenário de demonstração (5.2)** · **suite de testes (5.3)** |
| **A seguir** | abrir a interface num navegador · exportação PDF (opcional) |
| **Backend** | 106 rotas, 21 domínios, ~19k linhas |
| **Testes** | 231 a passar · `verificar_contrato.py` para o frontend |
| **Verificado em 2026-09-15** | suite a passar · frontend compila (103 módulos) e serve com o proxy a funcionar · 33/35 endpoints GET a responder 200 (os 2 restantes exigem `incident_id`, comportamento correcto) · cenário de demonstração a percorrer os 10 passos |
| **Ambiente** | Python 3.13.7 · Node 22.20 · PostgreSQL 16 em Docker · API em :8099 · interface em :5500 |
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
> ignorado pelo git. `frontend/node_modules` também não: correr
> `cd frontend && npm install` depois do clone.

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

### Frontend (§4.13, §28–§30, §77–§82) — 12 páginas
`frontend/`, React 18 + TypeScript + Vite, tudo em português.
`npm install && npm run dev` → <http://localhost:5173>. O proxy de `/api` para
`127.0.0.1:8099` mantém os caminhos iguais aos de produção e dispensa CORS.

As seis telas do §4.13 estão todas: entrada, painel, lista de incidentes,
registo, detalhe e relatórios. Mais: alertas, recomendações, aprovações,
indicadores, activos, MITRE, auditoria, administração e playbooks.

Decisões que convém não desfazer:

- **O token de acesso vive em memória**, nunca em `localStorage` — que é
  legível por qualquer XSS. A sessão recupera-se pelo token de renovação.
- **A renovação é partilhada** entre pedidos concorrentes: cinco renovações ao
  mesmo tempo disparariam a detecção de reutilização do servidor, que revoga a
  sessão inteira por suspeitar de roubo.
- **`pode()` esconde, não protege.** Quem chegar pelo URL leva 403 do servidor.
- **O ciclo de vida vem do servidor** (`transicoes_permitidas`); o cliente não
  reimplementa `INCIDENT_TRANSITIONS`.
- **A cor nunca comunica sozinha** (§79): todos os distintivos de severidade
  trazem o texto do valor.
- **O grafo tem disposição determinística.** Uma simulação física move os nós
  enquanto estabiliza, e um analista que aponta para um nó e o vê fugir perde o
  fio à investigação.

> **`backend/scripts/verificar_contrato.py`** confirma que os campos que o
> frontend lê existem mesmo nas respostas da API. O TypeScript garante
> coerência interna, não correspondência com o servidor — os tipos foram
> escritos à mão. Apanhou quatro divergências reais que teriam aparecido na
> interface como "undefined", entre elas `ActionRead` não expor **quem propôs**
> a acção, o que impedia a interface de explicar a separação de funções.
> **Correr depois de mexer nos esquemas do backend.**

> **Por verificar: o aspecto.** Nada disto foi visto num navegador — não havia
> um disponível. Compila, o servidor serve, o proxy responde, a autenticação
> real funciona e o contrato está confirmado campo a campo. O que falta
> confirmar é espaçamento, contraste e se alguma tabela transborda.

### Cenário de demonstração — os dez passos do §4.14
`app/services/demo_service.py`, invocado por `python -m scripts.manage demo
[--reset]`. Percorre o guião da monografia **pelo fluxo real da aplicação**:
ingestão pelo normalizador do Suricata, promoção por `promote_alert`,
transições por `incident_service.transition`. Inserir linhas directamente seria
muito mais curto e produziria uma demonstração de dados em vez do sistema — um
incidente inserido à mão não tem observações, nem marcos, nem grafo, nem
relatório.

- **Fonte: Suricata**, como o §4.14 diz (as verificações manuais do
  desenvolvimento usaram Wazuh, que é a fonte do laboratório).
- **Dois sinais**: força bruta SSH (4 eventos → 1 alerta, demonstra a
  deduplicação) e uma comunicação com infra-estrutura externa, ligada ao mesmo
  incidente. O segundo existe porque um incidente com um só indicador dá um
  grafo de 3 nós, que não demonstra investigação nenhuma; com ele são **8 nós e
  7 arestas**.
- **Ciclo de vida completo** segundo o §4.9: `NOVO → ABERTO → INVESTIGAÇÃO →
  CONTENÇÃO → ERRADICAÇÃO → RECUPERAÇÃO → RESOLVIDO → ENCERRADO`. O guião de
  dez passos resume "em resposta"; a plataforma decompõe, e é dessa decomposição
  que saem os marcos temporais.
- **Tudo marcado com `is_demo_data=True`** e removível com `--reset`, que apaga
  os dados de demonstração e **só** esses — verificado por teste. A auditoria
  não é apagada: a tabela é append-only por construção.
- Domínio de C2 em `.invalid` (RFC 2606), que nunca poderá pertencer a ninguém.

Duas coisas que o cenário **diz em vez de disfarçar**: quando a classificação
automática já acertou, o relato diz "confirmada" e não finge uma alteração; e as
métricas de resposta aparecem comprimidas porque o cenário corre em segundos —
os marcos são reais, o intervalo entre eles não representa trabalho humano.
Antedatá-los produziria números mais apresentáveis e falsos.

### Suite de testes (§32) — 221 testes, 75% de cobertura
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

### 5.2 Cenário de demonstração — **feito** (ver §4)
`python -m scripts.manage demo --reset`. Os dez passos do §4.14 da monografia,
transcritos em [`MONOGRAFIA-CAP4.md`](MONOGRAFIA-CAP4.md#414-exemplo-de-cenário-para-demonstrar-o-protótipo).

Se quiser alargá-lo: `_eventos_suricata` e `_evento_c2` em
`app/services/demo_service.py` são os dois sinais; acrescentar um terceiro é
acrescentar uma função e uma chamada a `ingest_batch`.

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

### 5.4 Frontend — **funcional; falta vê-lo num navegador**

14 páginas, as seis telas do §4.13 incluídas.
`cd frontend && npm install && npm run dev`.

> **Porta 5500, não 5173.** O Windows reserva intervalos de portas para o
> Hyper-V/WSL e a 5173 cai dentro de um deles nesta máquina, o que fazia o
> Vite rebentar com `EACCES: permission denied ::1:5173`. Confirmar com
> `netsh interface ipv4 show excludedportrange protocol=tcp`.
> Alterar com a variável `SHEISA_PORTA_UI`.

Acrescentado depois da primeira passagem:

- **triagem de alertas** — promover a incidente, ligar a incidente existente,
  descartar/falso positivo, recalcular pontuação (era o passo 2 do §4.14 e não
  tinha botão);
- **gráficos do painel** — o painel usava 1 dos 5 endpoints; passa a usar os
  cinco, com tempos de resposta, série temporal, quatro distribuições e carga
  por analista, em SVG sem dependência nova;
- **tarefas** (§19, que não tinha ecrã nenhum) e **playbooks** no incidente;
- **carregamento de evidências** e descarga autenticada;
- **atribuição de responsável** no detalhe;
- páginas de **integrações** e **notificações**;
- **cobertura MITRE** ao longo da cadeia de ataque, separando técnicas
  afirmadas de hipóteses do motor;
- **edição** de incidente, indicador, activo e utilizador, mais reposição e
  alteração de palavra-passe;
- **relações entre incidentes** (§20) e **reversão de acções** (§14);
- **verificação de integridade** e eliminação de evidências.

Das 106 operações da API, **3 continuam sem ecrã** (sessões próprias, criação
de chaves de API e listagem de equipas) — eram 35 no início desta passagem.

**Por fazer:**

- **abrir num navegador e corrigir o que estiver torto** — continua a ser o
  único passo que não pôde ser dado aqui (não há automação de navegador
  disponível). O que *foi* verificado: compila sem erros de TypeScript, serve,
  o proxy chega à API, e cada caminho e campo usado foi confrontado com o
  OpenAPI e com respostas reais.
- Três operações continuam sem ecrã, todas marginais:
  `GET /auth/sessions` (as próprias sessões do utilizador),
  `POST /integrations/api-keys` (criar chaves; existe na linha de comandos com
  `manage create-api-key`) e `GET /roles/teams`.

### 5.5 Laboratório Wazuh (§26) — **verificado a correr**
Os ficheiros existem: `lab/docker-compose.lab.yml`, `lab/preparar.sh`,
`lab/gerar-alertas.sh`, `lab/agente/Dockerfile`, `lab/integrations/custom-sheisa`
(+ `.py`) e `lab/config/ossec.conf.exemplo`.

Levantado e verificado em 2026-09-15. Gestor saudável, agente `srv-web-lab`
registado (ID 001), `wazuh-integratord` a correr, e a cadeia completa provada:

```
log real → agente → gestor → regra 5710/5712/40112 → integrator
        → custom-sheisa → POST /api/ingest/wazuh → alerta na plataforma
```

O Wazuh chegou a disparar a regra **40112** ("Multiple authentication failures
followed by a success"), que é a assinatura de um comprometimento efectivo — e
a correlação da SHEISA agrupou os alertas em dois incidentes, um por limiar e
outro por origem comum (o IP do atacante, não o host da vítima).

A imagem do Wazuh ronda os 600 MB; conte com uma descarga demorada no primeiro
arranque.

**Dois defeitos corrigidos ao levantá-lo**, ambos silenciosos:

1. `agent-auth -F 1` — a opção `-F` **não existe** no Wazuh 4.12 (existia em
   versões antigas). O comando imprimia o texto de ajuda e saía, e como a saída
   não continha "Valid key" o ciclo repetia-se para sempre com uma mensagem que
   parecia de rede. A substituição de agentes com nome repetido é decidida pelo
   gestor, em `<auth><force><enabled>yes`, que já estava configurado.
2. O gerador datava as linhas com a hora do **anfitrião** (CAT, UTC+2) enquanto
   os contentores correm em UTC. Os registos apareciam no ficheiro, o colector
   dizia analisá-lo, a regra correspondia no `wazuh-logtest` — e não nascia
   alerta nenhum, sem um único erro em lado nenhum. A hora passa a vir do
   contentor.

Contrato do *integrator*, já documentado em `app/ingestion/wazuh.py`:
`argv[1]`=ficheiro do alerta, `argv[2]`=api_key, `argv[3]`=hook_url.

### 5.6 Exportação PDF — opcional, degrada bem
`app/reporting/pdf.py` não existe; a rota `/api/reports/{id}/pdf` devolve 503
com explicação. `reportlab` está em `requirements-reports.txt` (falhou a
instalar por causa do Pillow e da rede).

### 5.7 Documentação — **feita**
- [`README.md`](../README.md) — porta de entrada: o que é, como arrancar, como
  demonstrar, como testar.
- [`ARQUITECTURA.md`](ARQUITECTURA.md) — análise crítica do RTIR, TheHive e
  Wazuh, as decisões de modelação que daí resultaram, e a tabela dos erros
  encontrados em execução.

## 6. Contas e credenciais do ambiente local

Criadas na base de dados de desenvolvimento (**não** são segredos de produção):

| Conta | Perfil | Palavra-passe |
|---|---|---|
| `admin@sheisa.local` | ADMINISTRADOR | `gfvAXtXTHnSBgSKpTYM8` |
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
               recommendation (sincronizar / decidir / aplicar),
               demo (os dez passos do §4.14 pelo fluxo real)
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
4. Trabalhar pela ordem 5.5 → 5.7 (laboratório, PDF, documentação);
   5.1 a 5.4 estão feitos. Antes disso, abrir a interface e corrigir o
   que estiver visualmente errado.
5. Antes de cada commit: `ruff check app tests scripts`, `pytest`, e no
   frontend `npm run verificar`. Depois de mexer nos esquemas da API,
   `python -m scripts.verificar_contrato <senha-de-admin>`.
