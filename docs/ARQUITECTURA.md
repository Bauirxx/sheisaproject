# Arquitectura

Este documento fixa a análise que precedeu o código e as decisões de modelação
que dela resultaram. Existe porque a alternativa — deixar o raciocínio apenas
no histórico de uma conversa — tornaria impossível, mais tarde, distinguir uma
decisão deliberada de um acidente.

---

## 1. Análise crítica das referências

### RTIR — *Request Tracker for Incident Response*

Organiza a resposta em quatro filas: **Incident Reports**, **Incidents**,
**Investigations** e **Countermeasures**.

**O que faz bem, e que aproveitámos.** O RTIR acerta numa coisa que a maioria
das ferramentas modernas perdeu: **o relato não é o incidente**. Um *Incident
Report* é matéria-prima; vários podem ligar-se a um mesmo *Incident*, numa
relação muitos-para-muitos. As *Countermeasures* têm ciclo de vida próprio
(`pending activation → active → pending removal → removed`), o que reconhece
que uma medida de contenção é uma entidade com estado, e não um campo de texto.

**Onde falha, e que corrigimos.**

| Problema do RTIR | O que fizemos |
|---|---|
| A fusão de bilhetes é **irreversível** e consolida tudo, destruindo o registo original. | Não existe fusão destrutiva. Relacionar cria uma aresta tipada (`DUPLICADO_DE`, `RELACIONADO_COM`, …) e **ambos os incidentes continuam a existir** com o histórico intacto. |
| Rejeitar um *Incident Report* **corta as ligações** aos incidentes, perdendo a relação histórica. | O estado do alerta muda; as ligações e observações permanecem. |
| Quando um relato está ligado a vários incidentes e um é abandonado, o RTIR limita-se a **deixar um comentário** — estado assimétrico. | O ciclo de vida é um grafo de transições explícito e validado no servidor; não há estados implícitos. |
| Interface de 2000s, sem correlação nem inteligência. | Motor de correlação e camada de inteligência determinística. |

### TheHive 5

Contribui o modelo virado para o analista: **Alert → (pré-visualização) →
Case**, com *observables*, tarefas, registos de tarefa, TTPs do ATT&CK e
classificação TLP/PAP.

**O que faz bem.** Proíbe a **criação manual de alertas** — um alerta tem de vir
de uma ferramenta de detecção. É a separação correcta entre sinal e caso, e
adoptámo-la.

**Onde falha.**

- A "correlação" é, na prática, **procurar semelhantes**: uma pesquisa, não um
  motor. Não responde a *"estes cinco alertas são a mesma operação?"*.
- Não há **camada de decisão**: os *responders* do Cortex executam sem porta de
  aprovação, sem separação de funções e sem justificação registada.
- *Observable* mistura duas afirmações diferentes: **"foi visto aqui"** e
  **"é malicioso"**.

### Wazuh

Entra como **camada de detecção**, e é dele que vem o contrato de ingestão real:

- o daemon `integrator` invoca `/var/ossec/integrations/custom-*` com
  `argv[1]` = ficheiro do alerta, `argv[2]` = `api_key`, `argv[3]` = `hook_url`;
- o alerta JSON traz `rule.{id,level,description,groups,mitre}`,
  `agent.{id,name,ip}`, `data.{srcip,dstip,srcport,dstuser}`, `full_log`,
  `decoder`, `location`;
- a severidade é uma escala de **0 a 15**, não de 1 a 5.

Esse último ponto não é um detalhe: traduzir mal os níveis faria um *severe
attack* (15) aparecer como informação. O mapeamento está numa função isolada e
testada (`app/ingestion/wazuh.py::map_wazuh_level`).

### A lacuna que ocupámos

O RTIR tem rigor de ciclo de vida mas nenhuma inteligência. O TheHive tem
experiência de analista mas nenhuma correlação nem governo da decisão. Nenhum
dos dois tem uma **camada de decisão auditável**.

É esse o espaço desta plataforma: o meio da cadeia
(`Evento → Alerta → Observação → Incidente`) e o fim
(`Recomendação → Aprovação → Execução → Resultado`), ambos como entidades reais
e não como campos.

---

## 2. Decisões de modelação

### 2.1 `Event` ≠ `Alert`

- **Event** — sinal bruto normalizado, tal como recebido. Alto volume. Guarda
  sempre o payload original, o que permite corrigir a normalização e
  reprocessar sem perder informação.
- **Alert** — asserção de detecção, resultante de um ou mais eventos após
  deduplicação por janela.

Sem esta separação, 10 000 tentativas de autenticação falhada seriam 10 000
alertas. Com ela, são **um** alerta com `event_count = 10000`.

### 2.2 `Ioc` (global) ≠ `Observation` (contextual)

Esta é a decisão que mais estrutura o resto.

| | |
|---|---|
| **`Ioc`** | Entidade **global**, única por `(tipo, valor)`. Carrega reputação, confiança e contagem de avistamentos. Um IP malicioso é um facto sobre o mundo. |
| **`Observation`** | O **avistamento**: este indicador, neste incidente, neste papel (origem, destino, alvo, payload, actor), neste instante, a partir deste alerta. |

Três consequências práticas:

1. `first_seen` / `last_seen` / `sighting_count` são **calculados a partir de
   avistamentos reais**, em vez de campos que alguém preenche;
2. as arestas do grafo investigativo derivam daqui, com direcção e papel;
3. a correlação pode distinguir o **lado do atacante** do **lado da vítima** —
   ver 2.5.

### 2.3 `Incidente` e `Caso` são a mesma entidade

O briefing distingue-os. Não os separámos: duas tabelas seriam cerimónia sem
função. Em vez disso:

- **`Campaign`** agrupa incidentes que se crê pertencerem à mesma operação;
- **"Investigação"** é uma *vista* sobre o incidente (linha temporal, grafo,
  tarefas), não uma linha numa tabela.

O princípio seguido, do próprio briefing: *não criar tabelas apenas para
parecer completo*.

### 2.4 O ciclo de vida é um grafo, e vive num sítio só

`INCIDENT_TRANSITIONS` e `ALERT_TRANSITIONS`, em `app/core/enums.py`, declaram
que transições são permitidas. O serviço valida contra esse mapa, pelo que
**nenhuma transição não declarada é possível** — nem pela interface, nem por
chamada directa à API.

A interface não reimplementa o grafo: cada incidente traz
`transicoes_permitidas` do servidor. Duplicar a regra no cliente daria duas
versões da mesma verdade, e a do cliente ficaria desactualizada na primeira vez
que alguém editasse o mapa.

`ENCERRADO` é terminal. Reabrir exige criar um incidente relacionado — o que
preserva o registo, ao contrário da fusão destrutiva do RTIR.

### 2.5 Correlação: quatro perguntas, quatro estratégias

| Estratégia | Pergunta a que responde |
|---|---|
| `ENTIDADE_PARTILHADA` | É o mesmo actor? |
| `LIMIAR` | Isto está a repetir-se? |
| `SEQUENCIA_TEMPORAL` | Isto progrediu ao longo de uma cadeia de ataque? |
| `ACTIVO_ALVO` | Este sistema está sob ataque por várias frentes? |

As regras vivem **em base de dados**, não no código: um SOC afina a correlação
continuamente, e exigir um deploy para isso tornaria o motor inútil na prática.

**Uma correcção que só apareceu em teste.** A estratégia
`ENTIDADE_PARTILHADA` considerava todos os artefactos partilhados e, por isso,
correlacionava dois ataques sem relação nenhuma por partilharem o *hostname da
vítima* — concluindo "mesmo actor". Passou a considerar apenas papéis do lado
do atacante (`ATTACKER_SIDE_ROLES`). Partilhar um alvo é uma pergunta
diferente, e tem estratégia própria.

### 2.6 Inteligência determinística, não generativa

A camada de inteligência é **determinística por decisão**, não por limitação.
Cada pontuação traz a sua decomposição: factor, pontos, razão e os dados
consultados.

- é **reprodutível** — a mesma entrada dá sempre a mesma saída, e a soma dos
  factores confere com o total apresentado;
- é **auditável** — cada contributo remete para um registo concreto;
- **não inventa** — sem histórico, o factor vale zero e di-lo, em vez de
  produzir um número plausível.

O componente que "aprende" fá-lo com dados reais: a taxa de falsos positivos de
uma regra vem das decisões que analistas de facto tomaram sobre alertas dessa
regra.

### 2.7 A decisão como entidade

`Action` e `ActionApproval` são entidades com ciclo de vida próprio. Uma acção
proposta e nunca aprovada **continua registada**, com quem a propôs e porque não
avançou. Regras impostas no servidor:

- risco moderado ou crítico **não executa sem aprovação**;
- **quem propõe não aprova** — sem isto, a aprovação seria uma formalidade que
  o próprio autor cumpre;
- acção crítica exige **justificação escrita**;
- o risco pode ser **elevado** por um playbook, nunca baixado — caso contrário
  bastaria declarar `BAIXO` para contornar a aprovação.

### 2.8 Auditoria imutável ao nível da base de dados

O registo de auditoria é **append-only**, garantido por gatilhos do PostgreSQL
que recusam `UPDATE`, `DELETE` e `TRUNCATE`. A aplicação não tem caminho que os
contorne.

A auditoria é escrita **na mesma transacção** que a alteração que descreve: se
o registo falhar, a alteração é revertida. Não existe estado alterado sem
registo correspondente.

> O `TRUNCATE` precisou de um gatilho **de nível statement** à parte: os
> gatilhos de linha não o apanham, e um `TRUNCATE` teria apagado toda a
> auditoria sem encontrar resistência.

---

## 3. Erros encontrados em execução

Registados porque cada um resultou de testar comportamento real em vez de
assumir que funcionava — e porque nenhum deles se manifestava como uma falha
visível.

| Erro | Como se manifestava | Correcção |
|---|---|---|
| `autoflush=False` na sessão | O motor pontuava sobre dados ainda não escritos e produzia **pontuações silenciosamente erradas** | `autoflush=True`, com a justificação no código |
| `ipaddress.is_private` | Classifica as gamas RFC 5737 (TEST-NET) como privadas: o **IP do atacante era descartado** e nunca chegava a ser indicador | `is_external_ip`, com lista explícita de gamas internas |
| Correlação por entidade partilhada | Casava pela **vítima** e concluía "mesmo actor" | Só papéis do lado do atacante |
| `srcuser` / `dstuser` confundidos | A conta **visada** era marcada como actor | `srcuser`→`ACTOR`, `dstuser`→`ALVO` |
| Contexto de auditoria construído cedo demais | O FastAPI resolve dependências pela ordem da assinatura: **todas as acções autenticadas eram registadas como anónimas**, e a separação de funções ficava desactivada | `AuditContext` passou a resolver a identidade **tardiamente**, no momento da escrita |
| `resource_type` recebia o caminho do URL | Coluna de 40 caracteres: um **403 legítimo rebentava e virava 500** | Corrigido e acrescentada truncagem defensiva, para que a auditoria nunca faça falhar o que regista |
| `SOLICITAR_APROVACAO` sem entidade | Suspendia o playbook sem criar nada aprovável: **nunca poderia ser retomado** | `ActionKind.AUTORIZAR_PROSSEGUIMENTO`, uma porta de autorização real |
| Descarga de evidências por `<a href>` | O token vive em memória e a navegação não leva `Authorization`: **todas as descargas dariam 401** | Descarga autenticada com materialização local |

---

## 4. Pilha tecnológica

| Camada | Escolha | Porquê |
|---|---|---|
| API | FastAPI + Pydantic v2 | Validação declarativa e documentação OpenAPI gerada do próprio código |
| Persistência | PostgreSQL 16 + SQLAlchemy 2 + Alembic | JSONB para payloads originais; gatilhos para a imutabilidade da auditoria |
| Palavras-passe | Argon2id | Recomendação actual da OWASP; não trunca aos 72 bytes como o bcrypt |
| Sessões | JWT curto + refresh persistido | Um JWT puro não pode ser revogado antes de expirar; a sessão persistida torna a revogação imediata |
| Interface | React + TypeScript + Vite | Densidade de SOC e grafo investigativo interactivo |
| ATT&CK | Bundle STIX oficial | Dados reais da MITRE; a ordem das tácticas é lida da matriz do próprio bundle, não fixada no código |
