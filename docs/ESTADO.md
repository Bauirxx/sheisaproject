# SHEISA — Estado do projecto e continuação

> Documento de passagem de testemunho. Descreve o que está **feito e
> verificado**, o que **falta**, e como retomar o trabalho sem repetir análise.
>
> **Se só vai ler um ficheiro, leia [`CONTINUAR.md`](CONTINUAR.md)**, que é
> curto e accionável. Este é o registo completo, para consultar quando precisar
> do detalhe ou do histórico de uma decisão.
>
> Última actualização: 2026-09-17 (eventos brutos, centro de operações,
> chaves de ingestão, sessões, equipas e limiares do motor)

---

## ONDE ESTAMOS

| | |
|---|---|
| **Feito** | Fundação · ingestão · triagem · correlação · incidentes · evidências · acções · playbooks · painel · grafo · relatórios · administração · **motor de recomendações (5.1)** · **cenário de demonstração (5.2)** · **suite de testes (5.3)** |
| **A seguir** | abrir a interface num navegador |
| **Backend** | 109 rotas, 24 domínios, ~20k linhas em `app/` |
| **Testes** | 460 a passar, 92% de cobertura · ruff limpo em todo o repositório · `verificar_contrato.py` confere 51 vistas do frontend contra a API viva (48 com a fila de aprovação vazia) |
| **Cobertura de UI** | das 109 operações, as 7 sem interface são-no por razão própria: 2 sondas de saúde, 2 de documentação e 3 de ingestão (máquina-a-máquina, por `X-API-Key`) |
| **Verificado em 2026-09-15** | suite a passar · frontend compila (103 módulos) e serve com o proxy a funcionar · 33/35 endpoints GET a responder 200 (os 2 restantes exigem `incident_id`, comportamento correcto) · cenário de demonstração a percorrer os 10 passos |
| **Ambiente** | Python 3.11.9 (venv) · Node 22.10.0 · PostgreSQL 16 em Docker · API em :8099 · interface em :5500 |
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
Python 3.11.9 (backend/.venv) · Node 22.10.0 · Docker 29.3.1 · PostgreSQL 16
backend/.venv          ambiente virtual
docker compose up -d   sheisa-db :15433 · sheisa-db-test :15434
```

> **Nota de portabilidade.** O projecto é construído em Python 3.11.9, que é o
> que esta máquina tem no `backend/.venv`. Foi também reposto num clone de raiz
> em **Python 3.13.7**: todas as dependências de `requirements-dev.txt` instalam
> sem alteração de versões e `app.main` importa sem avisos. Confirme sempre com
> `backend/.venv/Scripts/python.exe --version` em vez de assumir. `ruff.toml` mantém `target-version = "py311"`
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

### Frontend (§4.13, §28–§30, §77–§82) — 19 rotas, 18 autenticadas
`frontend/`, React 18 + TypeScript + Vite, tudo em português.
`npm install && npm run dev` → <http://127.0.0.1:5500>. **A porta é 5500 e não
a 5173 por omissão do Vite:** o Windows reserva 5141–5240 para o Hyper-V/WSL e a
5173 dava `EACCES` sem explicação. `SHEISA_PORTA_UI` sobrepõe-se. O proxy de
`/api` para `127.0.0.1:8099` mantém os caminhos iguais aos de produção e
dispensa CORS.

As seis telas do §4.13 estão todas: entrada, painel, lista de incidentes,
registo, detalhe e relatórios. Mais: centro de operações, alertas, eventos
brutos, recomendações, aprovações, indicadores, activos, MITRE, auditoria,
administração e playbooks.

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

### Cobertura de interface fechada (2026-09-17)
Partiu-se de uma auditoria que compara cada operação da API com o que o
frontend realmente chama. Estavam 12 sem ecrã; ficaram 7, e essas 7 são-no por
razão própria — 2 sondas de saúde, 2 de documentação e as 3 de ingestão, que são
máquina-a-máquina e autenticadas por `X-API-Key` (um browser nunca as chama).
Todas as outras têm agora interface.

**Eventos brutos** (`/eventos`, `GET /events`, `GET /events/{id}`). É a página
com mais valor de defesa de todas as que foram acrescentadas, porque é onde a
distinção evento/alerta/incidente deixa de ser uma afirmação da documentação e
passa a ser observável: quatro mil tentativas de força bruta são quatro mil
eventos e **um** alerta. O detalhe mostra o `raw_payload` tal como a fonte o
enviou, e é a resposta concreta a "como sei que este valor não foi inventado
pela plataforma?" — verificado com um alerta real do laboratório, em que
`severidade ALTA` se lê no `rule.level 12` do payload, `203.0.113.212` no
`data.srcip` e `backup` no `data.dstuser`. O payload traz `tsc`, `gdpr`,
`pci_dss`, `firedtimes`, `predecoder`: campos que ninguém escreveria à mão.
A tabela mostra ainda o **atraso** entre ocorrência e recepção, e assinala-o
quando é negativo — isto é, quando a fonte diz que o evento ocorreu depois de
ter sido recebido, o que denuncia relógios desalinhados. Foi exactamente a falha
que custou horas no laboratório e que não produz erro em lado nenhum.

**Centro de operações** (`/centro`, `GET /soc`). Deliberadamente distinto do
painel: o painel responde a "como estamos" (tempos, tendências, distribuições),
este responde a "o que faço agora" e mostra **itens**, não médias — sete filas
de trabalho numa única resposta, porque sete pedidos separados comporiam o ecrã
aos pedaços e levariam o analista a agir sobre uma imagem parcial. O prazo é
dito por palavras ("fora de prazo há 4 h") e não apenas por cor, que não
sobrevive a uma impressão nem a quem não a distinga.

**Sessões do próprio utilizador** (`GET /auth/sessions`, na Administração).
Mostra endereço, agente e última utilização de cada sessão, porque um acesso a
partir de um endereço estranho é o primeiro sinal de uma credencial
comprometida e é o dono da conta quem está em melhor posição para o notar.

**Chaves de ingestão** (`POST /integrations/api-keys`, nas Integrações). A chave
em claro aparece **uma só vez**, com o aviso de que a base de dados guarda
apenas o hash — afirmação verificada: `SELECT` confirma 64 caracteres de
SHA-256 e zero ocorrências do segredo em qualquer coluna. Verificado também que
a chave **serve**: 401 com uma chave inventada, 202 com a criada pelo
formulário, gerando o alerta ALT-000026. E que revogá-la a inutiliza de imediato.

**Equipa no formulário de utilizador** (`GET /roles/teams`). O comentário de
`EditarUtilizador` já prometia editar "nome, perfil, equipa e estado", e a API
já aceitava `team_id` — só o campo faltava. Verificados os dois caminhos:
atribuir e retirar (`team_id: null`).

**Limiares do motor** (`GET /recommendations/meta/tipos`, nas Recomendações).
Um bloco "Como o motor decide" que mostra as constantes que governam as
propostas — confiança mínima 40, tecto de inferência 75, promoção a partir de
65, validade 7 dias. Vêm do módulo do motor, não reescritas na página, e
confirmou-se que **todas governam decisões a sério**: `MIN_CONFIDENCE_TO_RAISE`
aparece em 7 guardas, e o tecto é aplicado via `_confidence_from(..., tecto=…)`.
Uma constante exposta mas não usada seria exactamente o tipo de número
decorativo que §4 proíbe.

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

### Suite de testes (§32) — 460 testes
`backend/tests/`, 38 ficheiros. Corre com `./.venv/Scripts/python.exe -m pytest`
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

### API (109 rotas, 24 domínios)
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

### Defeitos encontrados ao fechar a cobertura de interface (2026-09-17)
Os dois foram encontrados pelo mesmo método: exercer contra a API viva cada
operação que ainda não tinha ecrã, em vez de assumir que funcionava por estar
escrita.

13. **`POST /integrations/api-keys` devolvia 500 em qualquer pedido válido.**
    O esquema de entrada `ApiKeyCreate` herdava `ApiModel` — a base das
    **respostas**, que traz `use_enum_values=True`. Pydantic substituía o membro
    do enum pela string, e `payload.kind.value` levantava
    `AttributeError: 'str' object has no attribute 'value'`. A rota era uma das
    três que não tinham interface nem teste, e por isso o defeito sobreviveu
    desde que foi escrita: **nunca funcionou nenhuma vez**. Corrigido fazendo-a
    herdar `ApiInput`, como as outras 35 entradas — o que lhe dá também
    `extra="forbid"`, logo um nome de campo trocado passa a falhar em voz alta
    em vez de se perder. `tests/test_chaves_ingestao.py` cobre-o; reverter a
    correcção faz falhar 4 dos 6 testes.

14. **Filtro de severidade em `/events` que parecia filtrar e não filtrava.**
    Ao construir a página de eventos ofereci um filtro de severidade que a rota
    não declarava. Um parâmetro de consulta que o FastAPI não conhece é
    **ignorado em silêncio**: a lista voltava completa e o utilizador concluiria
    que não havia nada a filtrar. Acrescentado `severidade` à rota, a par de
    `fonte`. O teste não se contenta com 200 — exige que a contagem filtrada
    seja menor que a total, senão um filtro ignorado passaria.

Fora do produto, duas arrumações: `alembic/env.py` tinha dois avisos do ruff
(`ruff check .` nunca passava no repositório inteiro, só em `app/` e `tests/`) e
o indicador `srv-web-lab` estava com reputação `MALICIOSA` na base de dados de
desenvolvimento. Este segundo caso merece nota: era **resíduo de um teste manual
da interface**, e foi o próprio registo de auditoria que o provou —
`EDITAR_IOC`, `admin@sheisa.local`, campos `["reputation", "context"]`. A
ingestão está correcta e nunca atribui reputação, deixando-a `DESCONHECIDA`,
que é a resposta honesta quando nada foi verificado. Deixá-lo assim distorceria
a triagem, que dá +20 pontos a indicadores maliciosos, e marcaria o servidor da
própria organização como malicioso. Corrigido **pela API**, para que a correcção
ficasse ela mesma auditada.

### Defeitos encontrados ao subir a cobertura (2026-09-17)
Escrever testes para os módulos com cobertura baixa (`timeline_service`,
`seed_service`, `mitre_service`, `integration_service`, conectores, ingestão
genérica, catálogo, middlewares, arranque e rotas de recomendações e de
alertas, correlação, administração, sessões, acções, grafo, evidências e
incidentes) revelou trinta e nove defeitos. Os testes não verificam que as linhas são criadas: exercem
aquilo para que cada módulo existe — contar a história do incidente pela ordem
certa, e pôr a configuração semeada a funcionar nos motores reais.

15. **A linha temporal contava a história ao contrário.** `created_at` usava
    `now()` do PostgreSQL, que devolve o **início da transacção**. Tudo o que um
    pedido criasse ficava com esse instante, e a auditoria, que regista a hora
    real, passava à frente: no cenário de demonstração, "Estado alterado de
    RESOLVIDO para ENCERRADO" aparecia antes de "Criar incidente". A migração
    `0005_instantes_reais` passa `created_at`/`updated_at` para
    `clock_timestamp()`; o downgrade repõe `now()` e foi exercido. Confirmado na
    API a correr depois de `manage demo --reset`: 15 entradas, alertas antes da
    criação, transições por ordem até ENCERRADO.
16. **Cada mudança de estado e cada comentário apareciam duas vezes** na linha
    temporal — como comentário de sistema e como auditoria. A deduplicação é
    estreita de propósito: os comentários de sistema das decisões sobre acções e
    dos passos de playbook ficam, porque a sua auditoria está ligada à acção ou à
    execução e são o único rasto no incidente.
17. **Aprovar um bloqueio não o executava — e o incidente dizia que sim.** No
    playbook semeado "Resposta a endereço IP malicioso", depois de aprovado o
    bloqueio a execução retomava com a acção parada em APROVADA; o passo 7
    escrevia "Bloqueio aplicado e resultado registado no incidente." e a execução
    terminava CONCLUIDA. É exactamente o que o §4 proíbe. A retoma executa agora a
    acção aprovada; sem integração capaz de bloquear, a acção falha, o passo 6
    (`abort_on_failure`) interrompe o playbook e nada é afirmado. **Decisão
    tomada:** quem executa é o playbook, como já acontecia com as acções de risco
    baixo; o controlo humano é a aprovação. O gestor não tem `actions:execute` e
    não precisa — a permissão verificada é `playbooks:execute`, de quem iniciou.
18. **Rejeitar deixava a execução suspensa para sempre**, em AGUARDA_APROVACAO sem
    nada na fila de quem aprova. Passa a CANCELADA, com o motivo no incidente e na
    auditoria (`INTERROMPER_PLAYBOOK`).
19. **Quem aprovava um passo tornava-se proponente do seguinte.** A retoma corre
    no pedido do aprovador e `propose_action` usava `ctx.actor_id`: o gestor que
    autorizava o passo 5 recebia 403 no bloqueio do passo 6 — "Não pode aprovar
    uma acção que propôs". A proposta de um playbook é agora de quem o iniciou
    (`triggered_by_id`), e a separação de funções continua a valer para essa
    pessoa.
20. **O resumo final perdia os passos anteriores à pausa.** A retoma recomeçava a
    lista, e a execução concluída mostrava só "7. Registar o resultado".
21. **Uma técnica revogada pela MITRE continuava válida depois de actualizar o
    catálogo.** O objecto revogado mantém o identificador e ganha
    `revoked: true`; a importação saltava-o — certo numa base vazia, errado numa
    actualização, em que a linha da versão anterior ficava a ser oferecida no
    catálogo. Passa a depreciada (não apagada, para não partir incidentes que a
    referem). Recarregar o bundle real 19.2 mantém 709 técnicas e 12
    depreciadas.
22. **Uma acção falhada não dizia porquê.** `IntegrationNotAvailableError`
    guardava o motivo só em `details`, e quem regista a falha grava `str(exc)`:
    um `ISOLAR_ACTIVO` sem agente no alvo ficava FALHADO com "A integração
    'Wazuh' não está disponível." e mais nada. O motivo passa a ir na mensagem.

23. **A ingestão genérica descartava eventos diferentes como duplicados.** Sem
    identificador no payload, o de recurso usava só o instante e a descrição:
    duas falhas de autenticação no mesmo segundo, de origens diferentes, davam o
    mesmo identificador, e a segunda era ignorada como "já recebida" — um sinal
    de segurança perdido sem aviso. A descrição entrava ainda por `hash()`, que
    o Python aleatoriza por processo, pelo que o mesmo evento reenviado depois de
    reiniciar a API já não era reconhecido. Passa a SHA-256 do payload canónico
    com o instante.
24. **O defeito 4 continuava vivo na ingestão genérica.** `dstuser` era um
    sinónimo de `username` e recebia o papel ACTOR: a conta visada contava como
    a do atacante. Corrigido no normalizador Wazuh, nunca neste.
25. **Normalização parcial sem aviso.** Um instante ilegível era trocado pela
    hora de recepção, e uma severidade em texto ("12") ou desconhecida era
    interpretada ou assumida em silêncio — o contrário do que o módulo promete.
26. **Instantes syslog datados de 1900.** O formato `Sep 17 08:15:30` não traz
    ano e o `strptime` preenchia 1900; o 29 de Fevereiro nem era lido. Um evento
    de 1900 fica fora de qualquer janela de correlação e no fundo da linha
    temporal. Passa a ter o ano mais recente plausível, tratando a passagem de
    ano e o dia bissexto. Foi um `DeprecationWarning` do Python 3.13 na suite
    que o denunciou.

27. **PATCH com `null` num campo obrigatório dava 500 em cinco rotas** —
    incidentes, activos, indicadores, tarefas e utilizadores. Os esquemas de
    edição aceitam `null` em todos os campos, e o `setattr` deixava o objecto
    inválido: rebentava ao serializar a resposta ou ao gravar. Confirmado na API
    a correr (`PATCH /assets/{id}` com `{"criticality": null}` → 500
    `ERRO_INTERNO`). Um só auxiliar, `core/partial_update.py`, lê a nulabilidade
    do próprio modelo e responde 422 `CAMPO_OBRIGATORIO`; `null` num campo que
    admite vazio continua a limpá-lo.
28. **Indicadores com valor impossível para o tipo.** `POST /iocs` com
    `{"ioc_type": "IP", "value": "banana"}` devolvia 201: a normalização
    devolvia o texto tal como vinha. Um "IP" assim entra nas observações e pode
    ser deduzido como alvo de um bloqueio. IP e hashes passam a ser validados
    (422 `VALOR_INVALIDO`); os tipos sem forma inequívoca não, para não recusar
    valores legítimos. Os 24 indicadores da base de desenvolvimento são válidos.

29. **O limite contra força bruta no login contornava-se com um cabeçalho.**
    A identidade usada pela limitação de taxa era o `X-API-Key`, se viesse, em
    qualquer rota — incluindo `/auth/login`. Mandar um `X-API-Key` diferente em
    cada tentativa abria um balde novo e o limite de 10 por minuto nunca
    chegava. A chave só identifica a fonte na ingestão, onde é validada; no
    resto conta o IP. Confirmado na API reiniciada: com uma chave aleatória por
    tentativa, a 11.ª recebe 429. A limitação de taxa não tinha nenhum teste — a
    fixture `rate_limit_ligado` existia e ninguém a usava.
30. **O 429 saía sem cabeçalhos de segurança.** A limitação de taxa estava por
    fora do middleware dos cabeçalhos, pelo que a resposta que ela devolve não
    passava por ele. A ordem foi trocada.

31. **Uma permissão nova nunca chegava aos perfis que já existiam.** O
    arranque prometia "acrescenta permissões novas sem destruir ajustes", mas só
    cumpria a segunda metade: a permissão era criada e nenhum perfil existente a
    recebia — nem o ADMINISTRADOR, definido como "todas". Como as rotas verificam
    as permissões guardadas na base de dados, numa instalação actualizada a
    funcionalidade nova ficaria recusada a toda a gente. A base de
    desenvolvimento não o mostrava por ter sido inicializada depois de todas as
    permissões actuais existirem. `sync_permissions` devolve agora os códigos
    criados nesta execução e `sync_roles` atribui só esses: uma permissão criada
    agora nunca pode ter sido retirada por ninguém, e a que o administrador
    retirou continua retirada.

32. **O filtro `alvo` da fila de recomendações aceitava qualquer texto.** Os
    valores guardados são `alert` e `incident`; `alvo=incidente` devolvia uma
    fila vazia sem aviso, como se não houvesse nada por decidir — a classe do
    defeito 14. Passa a aceitar só os dois valores e responde 422 aos outros.
    Na API reiniciada: `incident` 200, `alert` 200, `incidente` 422.
33. **Recalcular as recomendações de um só alvo não ficava auditado**, ao
    contrário do recálculo global. Ambos criam e retiram recomendações, e uma
    recomendação retirada desaparece da fila de quem decide.

34. **A triagem marcava um alerta PROMOVIDO ou CORRELACIONADO sem incidente.**
    São estados do ciclo de vida, mas só a promoção e a ligação criam o que lhes
    dá sentido. A interface escondia-os; a API aceitava-os. Agora 422
    `ESTADO_EXIGE_INCIDENTE`.
35. **A confiança indicada ao promover era ignorada.** O esquema aceitava-a, a
    rota não a passava e o serviço fixava MEDIA.
36. **A promoção não consultava o ciclo de vida.** Um alerta DESCARTADO era
    promovido directamente, apagando a decisão de descarte que o motor usa para
    estimar o ruído da regra; o ciclo de vida exige reabri-lo primeiro.
37. **A ligação também não.** Um alerta PROMOVIDO podia ser religado a outro
    incidente, saindo do que ele próprio originou.
38. **Ligava-se um alerta a um incidente ENCERRADO.** O motor de correlação
    recusa-o por reescrever um registo concluído; a ligação manual passou a usar
    o mesmo `LINKABLE_STATUSES`.

39. **Os playbooks mudavam o estado do incidente sem passar pela transição.**
    O passo `ALTERAR_ESTADO` e o estado final declarado faziam
    `incident.status = ...`, verificando só o ciclo de vida, e saltavam o resto:
    os marcos temporais das métricas de resposta (um playbook que levasse o
    incidente a CONTENCAO nunca preenchia `contained_at`), o resumo obrigatório
    para RESOLVIDO, o motivo e a propagação aos alertas para FALSO_POSITIVO, e a
    entrada ALTERAR_ESTADO na auditoria e na linha temporal. Encontrado ao
    aplicar a armadilha 5.15 a todas as atribuições directas de estado.
40. **Um estado final impossível era saltado em silêncio**, e o resumo da
    execução era gravado antes do bloco do estado final — nem a transição
    bem-sucedida lá ficava. Ambos passam a ficar registados.

41. **A sequência temporal juntava alertas sem relação nenhuma.** Os candidatos
    eram todos os alertas da janela: uma falha de autenticação num servidor, uma
    execução noutro e um trojan num terceiro, de três origens diferentes,
    formavam uma "cadeia de ataque em progressão" — e a regra semeada com esta
    estratégia tem a prioridade mais alta e dá severidade CRITICA. Passa a exigir
    que os alertas partilhem o activo ou algum artefacto observado.
42. **Na convergência num activo, um alerta sem regra contava como detecção
    distinta**: `None` entrava no conjunto de regras distintas.
43. **Um administrador podia retirar a si próprio o perfil que gere contas.** A
    rota impedia a auto-desactivação, para não perder o acesso, mas trocar o
    próprio perfil tem o mesmo efeito. Agora 422 `AUTO_DESPROMOCAO`; confirmado
    na API reiniciada, com o perfil do administrador de desenvolvimento intacto.

44. **A palavra-passe actual adivinhava-se sem limite ao mudá-la.** O login
    conta tentativas falhadas e bloqueia a conta; `POST /auth/change-password`
    verificava a palavra-passe actual sem contar nada, e a limitação de taxa
    trata-a como rota comum (300 por minuto). Com um token de acesso roubado
    tentava-se até acertar e depois trocava-se a palavra-passe. Passa a contar
    como no login e, ao bloquear, termina todas as sessões — incluindo a que
    estava a tentar. Não foi confrontado na API a correr, porque bloquearia uma
    conta da base de desenvolvimento.
45. **A hora do bloqueio vinha em UTC sem o dizer.** "Até 08:15" para quem está
    em Maputo significa 10:15 locais.

46. **Propor a reversão de uma acção dava-a por revertida.** A original ficava
    REVERTIDA com a inversa ainda por aprovar — o incidente dizia que o endereço
    fora desbloqueado —, e uma inversa rejeitada deixava a original impossível de
    reverter. Agora só fica REVERTIDA quando a inversa é executada, e não se
    propõem duas reversões em curso. A interface já dizia ao analista o certo:
    "não desfaz nada directamente".
47. **Uma aprovação caducada ficava na fila para sempre.** Decidi-la devolvia 409
    sem mudar nada. A base de desenvolvimento tinha um caso real, ACT-000001,
    caducado na véspera. Há agora a decisão CADUCADA: a acção passa a CANCELADA
    (em nome do sistema, auditado), um playbook suspenso nela termina, e o painel
    e o centro de operações deixam de a contar. Confirmado na API reiniciada.
48. **Uma execução em que o conector lançava excepção contava como falhada mas não
    como executada** — a página de integrações mostrava "0 executadas (1
    falhada)".
49. **`enum_column` afirmava restrições CHECK que não existem.** O esquema não tem
    nenhuma: o SQLAlchemy 2 não as cria por omissão. A docstring foi corrigida; se
    se devem criar é uma decisão — ver [`CONTINUAR.md`](CONTINUAR.md) §4.3.
50. **No grafo com profundidade, uma relação entre incidentes aparecia duas
    vezes**, desenhada a partir de cada lado, e `resumo.arestas` contava-a em
    dobro.
51. **O grafo de um indicador inexistente devolvia 200** com um grafo vazio, ao
    contrário do de um incidente (404). Confirmado na API reiniciada.

Todos verificados por reversão. Desfazer a correcção faz falhar: 15, um teste;
16, dois; 17, dois; 18, 19, 20 e 21, um cada; 22, cinco; 23, dois; 24, um; 25 e
26, quatro cada; 27, nove; 28, cinco; 29 a 38, um cada; 39, dois; 40 a 45, um
cada; 46, três; 47, quatro (decisão, fila, painel e playbook); 48, 50 e 51, um
cada. O 49 é uma correcção de documentação.

52. **A adulteração de uma evidência ficava auditada como sucesso.** A verificação
    dizia-o na resposta, mas o registo de auditoria ficava SUCESSO — enquanto o
    ficheiro em falta ficava FALHA. Quem procurasse as verificações falhadas via
    o ficheiro perdido e não o adulterado, que é o caso grave.
53. **Referências inexistentes davam 500 — ou eram ignoradas.** Um identificador
    de utilizador, equipa ou activo que não existe chegava à base de dados e a
    chave estrangeira recusava-o: 500 ao registar uma observação, ao criar ou
    atribuir um incidente e ao criar ou editar uma tarefa. Nos activos de um
    incidente novo, a consulta por lista ignorava os inexistentes e o incidente
    nascia sem o activo indicado. Um só auxiliar, `core/lookups.py`, responde
    404; confirmado na API reiniciada, sem incidente criado. Ver a armadilha 5.16.

Desfazer a correcção faz falhar: 52, um teste; 53, oito. Os defeitos 27 a 30, 32 e
34 foram também confirmados na API reiniciada, e o 31 com `manage init` na base
de desenvolvimento, que correu sem alterar nada. A base de desenvolvimento não
tinha alertas inconsistentes (0 de 27 PROMOVIDO ou CORRELACIONADO sem incidente). `verificar_contrato.py`
continua a confirmar as 51 vistas.

O conector Wazuh foi confrontado com o gestor 4.12.0 do laboratório antes de se
escreverem os seus testes: com a verificação de certificado ligada falha
(`CERTIFICATE_VERIFY_FAILED`, auto-assinado); com
`permitir_certificado_auto_assinado` responde "Ligação estabelecida com o gestor
Wazuh v4.12.0; 2 agente(s) registado(s)." Os formatos do duplo HTTP dos testes
são os que esse gestor devolveu.

Quatro achados ficaram por corrigir, porque exigem uma decisão e não uma
correcção — estão descritos em [`CONTINUAR.md`](CONTINUAR.md) §4.3: playbooks
semeados com aprovação dupla (e o de bloqueio de IP, que nenhum conector pode
concluir); a importação do QRadar e do NetScout, que nada chama embora o catálogo
diga que importa; os comandos de resposta activa do Wazuh, não verificados e em
parte aparentemente errados; e um playbook que encerra incidentes sem que quem o
corre tenha `incidents:close`.

---

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
460 testes, 92% de cobertura (medido em 2026-09-17). O que a lista do §32
pede está coberto.

Onde a cobertura continua baixa, e porquê (remedido em 2026-09-17 — os valores
anteriores, que este documento afirmava, estavam desactualizados: o
`analytics_service` subiu de 14% para **76%** entretanto):
- `timeline_service` e `seed_service` 100%, `mitre_service` 98%,
  `ingestion/generic.py` 95%, `integration_service` 94%, `core/middleware.py`
  94%, `api/v1/recommendations.py` 95%, `services/bootstrap.py` 92%,
  `api/v1/catalog.py` 91%, `api/v1/alerts.py` 89%, `wazuh_connector` 87% —
  todos subidos em 2026-09-17 (estavam entre 0% e 67%); os testes revelaram os
  defeitos 15 a 53 do §4 (também `evidence_service` e `api/v1/incidents.py` 99%,
  `correlation/engine.py` 91%,
  `api/v1/admin.py` 96%, `services/auth_service.py` 97%, `api/v1/response.py`
  90%, `action_service` 92% e `analytics_service` 95%);
- `siem_connectors` 56% e `integrations/base` 73% — o que falta é código que
  nada na aplicação chama (`fetch_offenses`, `fetch_alerts`, `required_env`);
- os mais baixos agora são `reporting/pdf.py` e `recommendation_service` (77%) e
  `api/v1/reports.py` (80%);
- `playbooks/engine` 74% — suspensão, retoma, rejeição e execução da acção
  aprovada estão testados; os tipos de passo menos usados não.

### 5.4 Frontend — **funcional; falta vê-lo num navegador**

19 rotas (18 autenticadas mais a entrada), as seis telas do §4.13 incluídas.
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

Acrescentado em 2026-09-17, fechando a cobertura: **eventos brutos** com o
payload original, **centro de operações**, **sessões próprias**, **criação de
chaves de ingestão**, **equipa no formulário de utilizador** e os **limiares do
motor** nas recomendações. Ver a secção própria em §4.

Das 109 operações da API, **7 continuam sem ecrã e devem continuar**: as duas
sondas de saúde, as duas de documentação (`openapi.json`, `redoc`) e as três de
ingestão, que são máquina-a-máquina e autenticadas por `X-API-Key`. Eram 35 no
início desta passagem, 12 antes de 2026-09-17.

**Por fazer:**

- **abrir num navegador e corrigir o que estiver torto** — continua a ser o
  único passo que não pôde ser dado aqui (não há automação de navegador
  disponível). O que *foi* verificado: compila sem erros de TypeScript, serve,
  o proxy chega à API, cada caminho e campo usado foi confrontado com respostas
  reais, e cada classe CSS usada foi confrontada com a folha de estilos — este
  último ponto por experiência própria, porque o TypeScript não valida nomes de
  classes e já foram inventadas quatro que não existiam.
- **não há linter no frontend**, só `tsc`. Um `eslint` apanharia dependências
  de `useEffect` em falta e variáveis não usadas, que hoje passam.

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

### 5.6 Exportação PDF — **feita**
`app/reporting/pdf.py`. As dez secções do relatório de incidente e o relatório
de período, com os hashes SHA-256 das evidências por extenso.

Continua opcional: `pip install -r requirements-reports.txt`. Sem o pacote, a
rota responde 503 com explicação e o relatório continua disponível em JSON.

> O `reportlab` importa `PIL.Image` no arranque, pelo que instalar com
> `--no-deps` produz um pacote que não chega a importar. O Pillow e o chardet
> ficaram declarados explicitamente em `requirements-reports.txt`.

Cinco testes, incluindo um que extrai o texto efectivamente desenhado nas
páginas — um PDF válido mas vazio passaria num teste de assinatura.

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

  schemas/     common, auth, alert, incident, catalog, response
  reporting/   pdf (as dez secções do relatório; degrada para 503 sem reportlab)

backend/tests/  conftest (migração, transacção por teste, contas), e por tema:
                infraestrutura, autenticacao, autorizacao, auditoria, ingestao,
                eventos (payload original e filtros), triagem, correlacao,
                incidentes, resposta, playbooks, tarefas, recomendacoes,
                evidencias, chaves_ingestao, relatorios_pdf, filtros, painel,
                demonstracao, ponta_a_ponta

frontend/src/
  api/         cliente (renovação de sessão, multipart, descarga autenticada),
               tipos (contrato partilhado com a API)
  autenticacao/contexto (sessão, permissões efectivas vindas do servidor)
  componentes/ comuns, listagem, Disposicao, graficos (SVG, sem dependência),
               CarregarEvidencias, TriagemDeAlerta, TarefasEPlaybooks,
               CoberturaMitre, RelacoesDeIncidente, Integracoes, MinhasSessoes,
               Editar{Incidente,Catalogo,Utilizador}
  paginas/     Entrada, Painel, CentroDeOperacoes, Alertas, Eventos,
               Incidentes, IncidenteNovo, IncidenteDetalhe, Recomendacoes,
               Aprovacoes, Relatorios, Catalogo (indicadores/activos/MITRE),
               Auditoria, Integracoes (+notificações), Administracao
  estilos/     tokens, base, disposicao
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
