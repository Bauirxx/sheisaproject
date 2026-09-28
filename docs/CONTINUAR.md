# Como continuar o SHEISA

> Documento de arranque para quem retoma o trabalho — outra sessão, outra
> máquina, outro dia. Diz **o que está feito**, **o que fazer a seguir** e,
> sobretudo, **as armadilhas que já custaram horas**, que é a parte que não se
> descobre a ler o código.
>
> Para instalar de raiz, use o [`README.md`](../README.md). Para o registo
> completo de decisões e defeitos, use [`ESTADO.md`](ESTADO.md). Este ficheiro é
> o mais curto dos três de propósito: se crescer demasiado, deixa de ser lido.
>
> Última actualização: 2026-09-20 (detecção Suricata com máquina Kali; recolha de correio por IMAP para servidor real).

---

## 1. Em três minutos

```bash
cd sheisa_project
docker compose up -d db db-test mail     # PostgreSQL e servidor de correio
cd backend && ./scripts/api.sh start     # API em :8099
cd ../frontend && npm run dev            # interface em :5500
```

| | |
|---|---|
| Interface | <http://127.0.0.1:5500> |
| Portal externo (sem sessão) | <http://127.0.0.1:5500/comunicar> |
| API | <http://127.0.0.1:8099> |
| **Caixa de correio do laboratório** | <http://127.0.0.1:8025> |

A última é onde se **vêem** as mensagens que a plataforma envia e as que lhe são
enviadas — é o que torna o canal de email demonstrável em vez de afirmado.

Confirmar que está de pé, por esta ordem — cada passo só faz sentido se o
anterior passou:

```bash
curl http://127.0.0.1:8099/api/health/ready
# {"estado":"pronto","base_dados":"acessivel"}

cd backend
./.venv/Scripts/python.exe -m pytest -q                  # 544 a passar
./.venv/Scripts/python.exe -m ruff check .               # All checks passed!
./.venv/Scripts/python.exe scripts/verificar_contrato.py <palavra-passe>

cd ../frontend
npm run verificar                                        # tsc + eslint + relógio
```

Cópia de segurança (RNF12) — o `criar` verifica o ficheiro restaurando-o de facto:

```bash
cd backend
./scripts/backup.sh criar                    # var/backups/sheisa-<instante>.dump
./scripts/backup.sh listar
./scripts/backup.sh verificar <ficheiro>     # codigo de saida 1 se nao restaurar
./scripts/backup.sh restaurar <ficheiro>     # destrutivo, pede confirmacao
```

**O projecto corre em duas máquinas, com ambientes diferentes** — ambos
verificados, ambos a passar a bateria acima:

| | Máquina A | Máquina B |
|---|---|---|
| Python (`backend/.venv`) | 3.11.9 | 3.13.7 |
| Node | 22.10.0 | 22.20.0 |
| Docker | 29.3.1 | 27.5.1 |

Confirme com `backend/.venv/Scripts/python.exe --version` em vez de assumir. Este
parágrafo já afirmou um só ambiente como "o desta máquina", e estava certo numa e
errado na outra.

> **Na máquina B, o Python 3.14 também está instalado — não o use para o
> `.venv`.** O `reportlab 4.2.5` emite `DeprecationWarning: ast.NameConstant is
> deprecated and will be removed in Python 3.14`: em 3.14 a exportação PDF deixa
> de funcionar.

**Depois de um `git pull`, reinicie a API** (`./scripts/api.sh restart`). O
uvicorn corre sem `--reload`, pelo que continua a servir o código anterior sem
dar sinal disso. O Vite, pelo contrário, recarrega-se sozinho — incluindo quando
muda a porta no `vite.config.ts`. E se o `pull` trouxer alterações a
`requirements*.txt`, instale-as antes de reiniciar.

**Corra também `python -m scripts.manage init`** (é idempotente: não recria a
conta de administração nem toca em palavras-passe). Se o `pull` trouxer
permissões novas, elas não existem na sua base de dados e as rotas que as exigem
respondem 403 a **todos** os perfis, sem que nada no código esteja errado — ver
§5.18. Foi exactamente o que aconteceu em 2026-09-28: as duas permissões da caixa
de comunicações (`reports_inbox:read` e `reports_inbox:triage`) nunca tinham sido
criadas nesta máquina, e a caixa inteira estava inalcançável na API a correr.
`manage init` criou-as e atribuiu 8 permissões aos 6 perfis já existentes.

Desde então **a própria API avisa**: o arranque escreve um `WARNING` que nomeia as
permissões em falta e o comando que as cria (defeito 71). Veja
`backend/var/tmp/api.log` depois de um `restart` — se não houver linha
`sheisa.arranque`, a base está sincronizada.

As contas de laboratório estão em [`ESTADO.md` §6](ESTADO.md#6-contas-e-credenciais-do-ambiente-local),
com uma ressalva: **a palavra-passe de administração é diferente em cada
máquina**, porque é gerada pelo `manage init` de cada base de dados.

---

## 2. A regra que governa tudo

> **Se não está implementado, não apresentar como implementado.**

Não é um slogan; é o critério de aceitação de cada linha. Em concreto:

- **Nada de mocks, dados falsos, respostas fixas ou estatísticas inventadas.**
  Dados de demonstração são permitidos, mas têm de estar marcados *e* passar
  pelos mesmos caminhos reais — o cenário de demonstração chama
  `ingest_batch`, não escreve alertas à mão.
- **Um número apresentado tem de ser verificável.** A pontuação de triagem
  mostra a decomposição factor a factor; os limiares do motor são lidos do
  módulo do motor e não reescritos na interface.
- **Uma integração só aparece como activa depois de o provar** — um teste de
  ligação bem-sucedido ou tráfego efectivamente recebido. Ter credenciais põe-na
  em `CONFIGURADA`, não em `ACTIVA`.
- **Uma constante exposta mas não usada é decorativa**, e portanto proibida. Ao
  expor os limiares do motor confirmei que cada um governa decisões a sério
  (`MIN_CONFIDENCE_TO_RAISE` aparece em sete guardas). Faça o mesmo.

A interface é **inteiramente em português**, incluindo comentários e nomes de
variáveis novas. RTIR, TheHive e Wazuh são para analisar criticamente, não
copiar — o §20 (relações entre incidentes) existe precisamente porque a fusão
irreversível do RTIR é uma má decisão.

---

## 3. Onde estamos

| | |
|---|---|
| Backend | 109 rotas, 24 domínios, ~20k linhas em `app/` |
| Frontend | 19 rotas (18 autenticadas mais a entrada), tudo em português |
| Testes | 573 a passar |
| Qualidade | `ruff check .` limpo em todo o repositório; `eslint` sem erros no frontend (13 avisos de recarregamento a quente, ver §4.2) |
| Contrato | `verificar_contrato.py` sem divergências: 51 confirmações na corrida de 2026-09-28, mais 6 anunciadas como não verificáveis por falta de dados (fila de aprovação vazia, incidente sem técnicas, sem recomendações pendentes). O número varia com o que a base tem — o que não varia é não haver divergências |
| Git | `main`, sincronizado com `github.com/Bauirxx/sheisaproject` |

**Cobertura de interface fechada.** Das 109 operações, 7 não têm ecrã e **não
devem ter**: duas sondas de saúde, duas de documentação (`openapi.json`,
`redoc`) e as três de ingestão, que são máquina-a-máquina autenticadas por
`X-API-Key` — um browser nunca as chama. Todas as outras têm interface.

Está feito e verificado a correr: fundação e auditoria imutável, ingestão
(Wazuh/Suricata/genérica), triagem determinística, correlação com 4 estratégias,
incidentes, evidências com carregamento e descarga autenticada, acções com
separação de funções, playbooks que suspendem em pontos de aprovação, motor de
recomendações, painel, centro de operações, eventos brutos, grafo, relatórios
com exportação PDF, catálogo, MITRE ATT&CK real, administração, e o laboratório
Wazuh ponta a ponta.

---

## 4. O que fazer a seguir

### 4.1 Abrir a interface num navegador — **o único passo que falta e não pôde ser dado**

Nenhuma das sessões de assistente teve automação de navegador. Tudo o que é
verificável sem ela foi verificado: compila sem erros de TypeScript, serve, o
proxy chega à API, cada campo lido foi confrontado com respostas reais e cada
classe CSS foi confrontada com a folha de estilos.

O que **só se vê num navegador**: alinhamento e espaçamento, comportamento dos
formulários longos, o painel lateral em ecrãs estreitos, as tabelas largas a
rolar, e se os gráficos SVG ficam legíveis com poucos dados. Percorra as 19
rotas, comece pelas mais novas (`/eventos`, `/centro`) e corrija o que estiver
torto.

### 4.2 ~~Instalar um linter no frontend~~ — **feito em 2026-09-17**

ESLint 10 com `typescript-eslint` e `eslint-plugin-react-hooks` 7, configurado
em `frontend/eslint.config.js`. `npm run verificar` corre agora `tsc`, `eslint` e
`scripts/verificar-relogio.mjs`, e é o que conta como verificação do frontend.

O que encontrou, em 36 ficheiros: **nenhuma** dependência de `useEffect` em
falta, uma atribuição inútil, e **um defeito real** — ver a armadilha 5.11. Ficam
13 avisos de `react-refresh/only-export-components`, todos em ficheiros que
exportam componentes e utilitários juntos (`comuns.tsx`, `listagem.tsx`,
`graficos.tsx`, `contexto.tsx`). Só afectam o recarregamento a quente em
desenvolvimento; resolvê-los obrigaria a partir esses ficheiros e a mexer nos
imports de ~20 páginas, o que não compensa enquanto não houver outro motivo.

As regras do React Compiler que a versão 7 traz no conjunto recomendado
**não foram desligadas**: correram tal como vêm, e a única que disparou
(`react-hooks/purity`) apontou para um defeito verdadeiro.

### 4.3 Subir a cobertura onde ela é baixa — **a lista original está feita**

**Onde parámos (2026-09-28):** a caça por padrão continua a render mais do que
escolher módulos por percentagem. Aplicar a armadilha 5.15 ao código que entrou
entretanto deu cinco portas abertas num incidente ENCERRADO — `+8` testes em
`tests/test_incidente_encerrado.py`, defeito 69 — e a suite está em **569 a
passar**. O modo de trabalho que as encontra: pegar numa regra recém-criada,
`grep` por quem chama o serviço que ela protege, e contar as portas.

**Onde parámos (2026-09-17):** os quatro módulos que esta secção listava estão
cobertos, e com eles os conectores, a ingestão genérica, o catálogo, os
middlewares, o arranque e as rotas de recomendações e de alertas. Escrever os
testes revelou **trinta e nove defeitos reais**, todos corrigidos e verificados
por reversão — [`ESTADO.md`](ESTADO.md) §4, defeitos 15 a 53. Nenhum dava erro; todos deixavam o sistema num estado
plausível e errado. O mais grave: aprovar um bloqueio num playbook **não o
executava**, e o incidente registava "Bloqueio aplicado".

| Módulo | Antes | Agora |
|---|---|---|
| `timeline_service` | 0% | 100% |
| `seed_service` | 0% | 100% |
| `mitre_service` | 19% | 98% |
| `integration_service` | 55% | 94% |
| `wazuh_connector` | 26% | 87% |
| `siem_connectors` | 30% | 56% — o resto é código que nada chama (abaixo) |
| `ingestion/generic.py` | 18% | 95% |
| `api/v1/catalog.py` | 35% | 91% |
| `core/middleware.py` | 58% | 94% |
| `services/bootstrap.py` | 59% | 92% (o commit `344cdbf` diz 100%: foi escrito antes de medir) |
| `api/v1/recommendations.py` | 63% | 95% |
| `api/v1/alerts.py` | 67% | 89% |
| `correlation/engine.py` | 72% | 91% |
| `api/v1/admin.py` | 73% | 96% |
| `services/auth_service.py` | 74% | 97% |
| `api/v1/response.py` | 76% | 90% |
| `services/action_service.py` | 78% | 92% |
| `services/analytics_service.py` | 76% | 95% |
| `services/evidence_service.py` | 78% | 99% |
| `api/v1/incidents.py` | 77% | 99% |

A lição de método: os testes que encontraram defeitos não verificavam que as
linhas eram criadas, mas que o módulo fazia aquilo para que existe — a linha
temporal conta a história pela ordem certa, a configuração semeada funciona nos
motores reais de ponta a ponta, o conector fala com o gestor Wazuh verdadeiro
(os formatos do duplo HTTP foram capturados do laboratório).

A ingestão genérica confirmou o palpite que a pôs no topo da lista: uma rota
máquina-a-máquina sem ecrã tinha **quatro** defeitos, e o pior perdia eventos —
duas falhas de autenticação no mesmo segundo, de origens diferentes, contavam
como duplicadas e a segunda era descartada.

O catálogo trouxe o defeito de alcance mais largo: um `PATCH` com `null` num
campo obrigatório dava **500 em cinco rotas** — ver a armadilha 5.14. Os
middlewares trouxeram o de segurança: o limite contra força bruta no login
**contornava-se mudando o cabeçalho `X-API-Key`** em cada tentativa.

Os alertas repetiram um padrão que vale a pena procurar noutros sítios: **uma
regra aplicada numa porta e esquecida nas outras**. A triagem cumpria o ciclo de
vida do alerta; a promoção e a ligação não o consultavam. Ver a armadilha 5.15.
Aplicá-la ao resto do código encontrou logo mais um caso: os playbooks mudavam o
estado do incidente sem passar pela transição (defeito 39).

**Os três candidatos que esta secção listava estão feitos** (2026-09-19), e com
eles mais quatro defeitos — ver [`ESTADO.md`](ESTADO.md) §4, defeitos 54 a 57:

| Módulo | Antes | Agora |
|---|---|---|
| `api/v1/reports.py` | 80% | 100% |
| `services/recommendation_service.py` | 77% | 94% |
| `reporting/pdf.py` | 77% | 85% |

Medido com a suite completa: **479 testes, 93%**. Tudo o resto está acima de 85%,
excepto o que fica fora pelas razões já ditas.

**Não há um próximo candidato óbvio por cobertura.** O que resta abaixo de 85% é
`reporting/pdf.py` (as ramificações de formatação de um relatório sem dados) e os
módulos que ficam fora por natureza. A partir daqui vale mais procurar por
*padrão* do que por percentagem — a armadilha 5.15 (uma regra aplicada numa porta
e esquecida nas outras) já rendeu três defeitos e não está esgotada.

`core/database.py`, `siem_connectors`, `integrations/base.py` e `main.py` ficam
fora: ligação e arranque, ou código que nada chama.

`core/database.py` (45%) e `siem_connectors` (56%) não são candidatos: o
primeiro é ligação e ciclo de vida do motor, o segundo é código que nada chama.

Meça sempre antes de citar um número destes — o `ESTADO.md` chegou a afirmar 14%
para o `analytics_service`, que estava a 76%:

```bash
./.venv/Scripts/python.exe -m pytest --cov=app --cov-report=term
```

> **Achados que exigiam uma escolha, não uma correcção.** Quatro foram fechados
> em 2026-09-24; dois continuam em aberto, por dependerem de contexto que não
> existe aqui.
>
> 1. **[EM ABERTO] Os playbooks semeados pedem duas aprovações para a mesma
>    decisão**: um `SOLICITAR_APROVACAO` seguido de um `EXECUTAR_ACCAO` crítico,
>    que volta a suspender. Pode ser intencional (autorizar o procedimento,
>    depois o alvo). E o playbook de bloqueio de IP **nunca pode concluir**:
>    nenhum conector executa `BLOQUEAR_IP`, pelo que pára sempre no passo 6 —
>    agora com uma falha honesta, depois da correcção 17.
> 2. **[FECHADO 2026-09-28] A importação do QRadar/NetScout ligada a uma rota
>    real.** `fetch_offenses`/`fetch_alerts` existiam mas nada os accionava — só o
>    teste de ligação. Agora `POST /api/integrations/{id}/import` chama o conector
>    e ingere os sinais pelo mesmo pipeline de qualquer fonte, idempotente por
>    `(fonte, id)`; `supports_pull` distingue pull de push. Testado contra
>    servidor simulado (correcção 68), verificado por reversão. Não verificado
>    contra instâncias reais — instruções em [`INTEGRACOES.md`](INTEGRACOES.md).
>    (O `ensure_catalog` já sincronizava os textos do catálogo, sem tocar no
>    estado configurado pelo operador.)
> 3. **[EM ABERTO] Os comandos de resposta activa do Wazuh não foram verificados,
>    e alguns parecem errados.** `EXECUTAR_VARRIMENTO` envia `restart-wazuh0`
>    (reinicia o agente — não é um varrimento); `RECOLHER_ARTEFACTOS` envia
>    `wazuh-logcollector` (um daemon, não um script de resposta activa);
>    `ISOLAR_ACTIVO` envia `firewall-drop0` sem argumentos (bloqueia um IP, não
>    isola o host). O sucesso é `affected_items` não vazio, que significa que o
>    gestor **enviou** a mensagem, não que o agente a aplicou. No laboratório,
>    em 2026-09-17: o gestor não tem secções `<command>` nem `<active-response>`
>    (a API devolve o erro 1106), e o agente `001 srv-web-lab` está
>    **desligado** — pelo que nada disto pôde ser confrontado. Trocar os nomes
>    sem um agente real seria substituir um palpite por outro. Fica em aberto até
>    haver um Wazuh a sério para confrontar. Os testes não afirmam os nomes dos
>    comandos, para não os fixar. Também `find_related_incidents`, no motor de
>    correlação, não é chamada por nada.
> 4. **[FECHADO 2026-09-24] Um playbook já não encerra um incidente sem
>    `incidents:close`.** A verificação vivia só na rota
>    `POST /incidents/{id}/transition`, e o motor chamava o serviço por baixo
>    dela. `engine._change_incident_status` — o funil das duas transições do
>    motor (estado final e passo `ALTERAR_ESTADO`) — passou a exigir a permissão
>    de quem corre o playbook quando o destino é ENCERRADO. Como
>    `AuthorizationError` é um `SheisaError`, o refuso fica como falha honesta do
>    passo, ou como nota no resumo do estado final, em vez de encerrar à revelia.
> 5. **[FECHADO 2026-09-24] A base de dados passou a impor os valores das
>    enumerações.** A migração `0007_check_enumeracoes` acrescentou uma restrição
>    CHECK a cada uma das 55 colunas de enumeração, por SQL cru (para escaparem à
>    `naming_convention`, que de outro modo duplicava o prefixo e truncava alguns
>    nomes no limite de 63 caracteres do PostgreSQL). Um valor inválido escrito
>    por SQL directo é agora recusado pela própria base. **Custo assumido:**
>    acrescentar um estado novo a uma enumeração passa a exigir uma migração que
>    refaça a restrição da coluna afectada.
> 6. **[FECHADO 2026-09-24] Um incidente ENCERRADO deixou de ser editável.**
>    `incident_service.garantir_editavel` recusa mutações de conteúdo (campos,
>    tarefas, observações, evidências — incluindo eliminá-las) num incidente
>    ENCERRADO, com 409 `INCIDENTE_ENCERRADO`. Os comentários continuam
>    permitidos: são notas de auditoria posteriores, não alteram o que aconteceu.
>    ENCERRADO é terminal (sem transições de saída), pelo que não se reabre — a
>    mensagem manda criar um incidente relacionado, como no ciclo de vida.
>    **Complemento (2026-09-28):** a guarda estava em cinco sítios e faltava em
>    cinco caminhos — técnicas MITRE, propor acção, correr playbook, aceitar ou
>    ligar comunicação, aplicar recomendação. Fechados e fixados em
>    `tests/test_incidente_encerrado.py` (defeito 69). É a armadilha 5.15.

### 4.5 Requisitos da monografia — o que estava em falta, e está feito

Uma verificação dos 20 requisitos funcionais e 14 não funcionais do §4.7/§4.8
contra o sistema a correr encontrou três em falta. Estão feitos (2026-09-19):

**RNF12 — cópia de segurança.** Não existia nada. `scripts/backup.sh` faz
`criar`, `listar`, `verificar` e `restaurar`. O `verificar` **restaura de facto**,
para uma base temporária que apaga a seguir, e o `criar` corre-o
automaticamente: uma cópia que nunca foi restaurada não é uma cópia, é um
ficheiro. Confirmado que detecta corrupção — um ficheiro truncado dá código de
saída 1, um bom dá 0, o que permite usá-lo num agendador. O `pg_dump` corre dentro
do contentor, pelo que a versão do cliente coincide sempre com a do servidor.
`var/` está no `.gitignore`: as cópias contêm dados reais e nunca vão para o
repositório.

**RNF07 — desempenho.** Não havia medição nenhuma. `TempoDeRespostaMiddleware`
põe `X-Tempo-Resposta-ms` em todas as respostas, inclusive nas de erro — o pedido
lento que acaba em erro é justamente o suspeito. Usa `perf_counter`, que é
monótono: com `time()` um ajuste do relógio daria duração negativa. Acima de
`LIMIAR_DE_LENTIDAO_MS` (1000 ms) o pedido é registado com o `request_id`, que é
o que o liga à entrada de auditoria. Medido nesta máquina: `/api/health` 1 ms,
`/api/audit` 59 ms, `/api/incidents` 118 ms, `/api/dashboard` 200 ms, `/api/soc`
377 ms (faz sete consultas).

**RF16 — filtrar por período.** O requisito nomeia "período" e a interface não o
oferecia. `FiltroDePeriodo`, `desdeISO` e `ateISO` em `componentes/listagem.tsx`,
aplicados a incidentes, alertas, eventos e auditoria. **A subtileza está no
`ateISO`:** enviar a data crua daria a meia-noite, pelo que "até hoje" excluía
tudo o que aconteceu hoje. Medido na base de desenvolvimento: 8 registos de
auditoria de hoje que a versão ingénua perdia — um intervalo que corta o último
dia em silêncio é pior do que não ter filtro, porque dá um número que parece
completo.

### 4.7 Comunicações de incidente e portal externo — **feito** (§5 · §37)

Era a única lacuna face ao RTIR que eu recomendaria construir, e é a que separa
uma ferramenta de SOC interno de uma de CSIRT: **quem comunica um incidente não
tem conta na plataforma, e não deve precisar de uma.** Um regulador recebe
comunicações de constituintes que nunca serão utilizadores.

**O modelo conserva a distinção que o RTIR acerta:** a comunicação não é o
incidente, é matéria-prima. A relação é muitos-para-muitos porque as duas
direcções acontecem — várias comunicações sobre a mesma campanha convergem num
incidente, e uma comunicação sobre um ataque a vários sistemas pode dar origem a
mais do que um. Um campo `incident_id` forçaria uma escolha que não existe.

**`/comunicar` é a única rota fora do `ExigirSessao`**, e `POST /api/public/reports`
a única escrita da plataforma sem autenticação. Tratada como tal: classe própria
no limitador de taxa (20/min, contra 300 do geral — verificado a travar com 429
à 19.ª submissão), limites de tamanho em todos os campos, e o endereço de origem
registado para permitir investigar abuso.

**O §37 diz que o utilizador externo nunca deve aceder a dados internos**, e é a
regra com mais vigilância: `ReportPublicStatus` é um esquema **separado** do
interno, com seis campos, e o que o define é o que não traz — nem o incidente
ligado, nem quem avaliou, nem a nota de triagem. Dois testes verificam-no por
*ausência* (procuram `INC-\d+`, endereços de analista, a nota e identificadores
internos no corpo da resposta), e o `verificar_contrato.py` repete a verificação
contra a API a correr. Um teste que confirmasse os campos certos continuaria a
passar depois de alguém acrescentar um campo interno — foi assim que se escolheu
verificar ausências.

**O que o comunicante afirma fica separado do que a equipa conclui.** Os campos
`claimed_category` e `claimed_severity` guardam a classificação de terceiros, e a
interface marca-a com a etiqueta "afirma". Os indicadores que escreve ficam em
texto e **não** são promovidos a IOC: um valor não verificado no catálogo global
contaminaria a triagem de tudo o que o tocasse.

**`ACEITE` exige um incidente ligado**, e a guarda vive numa passagem única
(`_aplicar_estado`) por onde toda a mudança de estado tem de ir — não dentro de
cada decisão. É a lição do defeito 54: uma regra guardada numa porta é uma regra
que as outras portas esquecem.

O código de acompanhamento é mostrado **uma única vez** (a base guarda o resumo
SHA-256), a comparação é em tempo constante, e uma referência inexistente dá a
mesma resposta que um código errado — as referências são sequenciais e
distingui-los permitiria enumerá-las.

### 4.8 Canal de correio electrónico — **feito e a funcionar** (2026-09-20)

As duas direcções funcionam contra um servidor a sério, não um simulador. O
`docker-compose` traz um serviço `mail` (Mailpit) que faz SMTP **e** POP3 e mostra
as mensagens em <http://127.0.0.1:8025> — é o que permite demonstrar o ciclo em
vez de o afirmar. Numa instalação real as variáveis `SHEISA_SMTP_*` e
`SHEISA_IMAP_*`/`SHEISA_POP3_*` apontam para o servidor da organização; o código
é o mesmo.

**Servidor real (Gmail).** A recolha suporta POP3 e IMAP —
`SHEISA_MAIL_COLLECT_PROTOCOL` escolhe. O Mailpit usa POP3; um servidor real usa
IMAP, porque o POP costuma estar desligado e o IMAP marca as mensagens como
lidas (`\Seen`) sem as apagar, o que importa numa caixa partilhada. Para o
Gmail: activar a verificação em duas etapas, gerar uma **palavra-passe de
aplicação** de 16 caracteres em <https://myaccount.google.com/apppasswords>
(não é a palavra-passe normal), e preencher o bloco comentado do `.env.example`.
A app password é um segredo — vive só no `.env`. Provado o quê: a lógica de
selecção de protocolo e o despacho têm testes; o IMAP contra o Gmail só se
confirma pondo a credencial e correndo o teste de ligação, e isso fica do lado
de quem tem a conta.

**Enviar.** Quem comunica pelo portal recebe um aviso com a referência e o código.
`acknowledged_at` só é escrito **depois** de o servidor aceitar a mensagem, e uma
falha de envio nunca faz falhar a submissão — perder uma comunicação porque o
correio está em baixo seria trocar o essencial pelo acessório. O teste de ligação
devolve o `Message-ID` que o servidor atribuiu, porque um `true` não prova nada.

**Recolher.** `POST /api/reports-inbox/recolher-email` lê a caixa e cria uma
comunicação por mensagem nova, com os cabeçalhos preservados em
`channel_metadata` — prova de origem, como o `raw_payload` de um evento.
Duplicados são detectados pelo `Message-ID`, porque o POP3 não guarda estado de
lida e uma reentrega criaria uma comunicação nova.

**O defeito que o servidor a sério revelou, e que um simulador esconderia.** A
caixa de segurança é normalmente o **mesmo endereço** que a plataforma usa como
remetente. Na primeira recolha real, três avisos de recepção voltaram e tornaram-se
três comunicações — cada uma gerando outro aviso. Um ciclo que se alimenta a si
mesmo. Corrigido com quatro sinais de descarte, cada um com o seu motivo
registado: a marca própria `X-SHEISA-Origem`, o `Auto-Submitted` do RFC 3834, o
`multipart/report` de uma notificação de entrega, e a convenção dos remetentes de
sistema (`MAILER-DAEMON`, `postmaster`, `no-reply`). A mensagem que sai leva também
`Auto-Submitted: auto-generated`, que pede ao outro lado que não responda
automaticamente — metade da prevenção do ciclo é nossa, a outra metade é pedida.

**A plataforma não classifica por palavras-chave.** Uma categoria inferida do
assunto seria apresentada com a mesma confiança de uma afirmada, e o §4 proíbe-o:
uma comunicação recolhida por email chega sem classificação, e é o analista que a
dá.

Verificado a correr, ponta a ponta: uma pessoa escreve para `cert@sheisa.local`,
a mensagem torna-se `COM-00034` com os cabeçalhos preservados, e o aviso de
recepção chega — enquanto uma devolução, um `no-reply` e o próprio aviso da
plataforma são ignorados com o motivo à vista.

**O que fica por fazer neste tema:** avisar quem comunicou quando a decisão é
tomada (aceite, recusada, duplicada). O envio já existe e é uma chamada; falta
decidir o que se diz em cada caso, que é uma escolha de processo — uma recusa
mal redigida faz mais dano do que silêncio.

### 4.9 Detecção de rede com Suricata e máquina Kali — **feito** (2026-09-20)

O laboratório passa a ter uma segunda camada de detecção, a par do Wazuh: o
**Suricata** observa o *tráfego de rede* que chega a um alvo e aplica-lhe
assinaturas reais (Emerging Threats Open, o conjunto que um SOC usa, mais regras
locais do laboratório). É o caminho natural de uma máquina Kali, que produz
tráfego e não registos.

**Arquitectura, validada empiricamente antes de a escrever.** Um contentor-alvo
(nginx) expõe a porta 8080; o sensor Suricata **partilha o stack de rede do
alvo** (`network_mode: service:alvo`), o que lhe dá acesso à interface por onde o
tráfego chega sem precisar de ver a interface física do anfitrião — que num
Docker Desktop não é alcançável a partir de um contentor. O sensor escreve
`eve.json`; o integrador `suricata-sheisa.py` segue-o e entrega os alertas em
lote a `POST /api/ingest/suricata`. Ver [`lab/README.md`](../../lab/README.md).

**A máquina Kali é externa** (a forma escolhida). O `lab/README.md` documenta
como a ligar — adaptador *bridged*, atacar `<anfitrião>:8080` com nmap, nikto,
sqlmap, hydra — e a limitação honesta do NAT: o Docker Desktop substitui o IP de
origem pelo do gateway no reencaminhamento, pelo que as assinaturas disparam mas
o "atacante" aparece como o gateway. Preservar o IP real exige rede `macvlan` num
anfitrião Linux, ou correr a Kali na mesma máquina.

**Reprodutível sem a Kali.** `lab/atacar-suricata.sh` dispara os mesmos padrões
de contentores efémeros na rede do laboratório (o que preserva o IP), para a
cadeia se poder demonstrar e verificar. Foi como se validou tudo: 152 eventos
reais, 7 regras locais e **10 regras ET Open genuínas** — incluindo a detecção
do nmap (`ET SCAN Nmap User-Agent`, sondas a portas MSSQL/PostgreSQL/mySQL), o
`/etc/passwd` na URI, e o acesso ao `.env`. Atacante e alvo chegam à plataforma
nos papéis certos, com o alerta Suricata original preservado em `raw_payload`.

**Chaves separadas.** `preparar.sh` cria uma chave de ingestão própria do tipo
SURICATA (`lab/suricata/ingestao.env`, ignorado pelo git), distinta da do Wazuh:
cada fonte é atribuível e revogável isoladamente.

**O que fica por fazer:** o normalizador Suricata tem testes unitários, mas a
cadeia laboratório→plataforma não tem um teste automatizado (depende de
contentores). É verificável à mão com `atacar-suricata.sh`; um teste de
integração exigiria orquestrar o Docker a partir do pytest, o que ainda não se
faz para nenhuma parte do laboratório.

### 4.6 Parâmetros da API que a interface não usa

Auditoria nova, ao nível do parâmetro (a anterior era ao nível da operação).
Eram **30**; são **13**. Os que foram ligados: `dias` no painel (a janela estava
presa nos 30 dias, embora a API aceite 1 a 365), `desde`/`ate` em quatro páginas,
`actor` e `tipo_recurso` na auditoria, `prioridade` nos incidentes,
`sem_incidente` e `pontuacao_minima` nos alertas.

A lista de tipos de recurso vem de `GET /audit/resource-types`, acrescentado para
o efeito — uma lista fixa no código ofereceria filtros para tipos que já ninguém
escreve e faltaria os que aparecessem.

A **verificação inversa deu limpa**, e era a preocupante: nada do que a interface
envia é ignorado em silêncio pela API (armadilha 5.2 sem nenhuma instância viva).

Os 13 que restam são de valor marginal — `risco` nas acções, `profundidade` no
grafo, `responsavel_id` ("os meus incidentes"), `alerta_id` nos eventos,
`avistamentos_minimos`/`incluir_permitidos` nos indicadores, `alvo_id` e
`confianca_minima` nas recomendações, `tactica` no MITRE, `recurso_id` e
`por_triar`. Para refazer a auditoria, note que a detecção tem de reconhecer a
notação abreviada (`consulta({ dias })` não tem dois-pontos), senão reporta
falhas falsas.

### 4.4 Ideias que foram deixadas de fora deliberadamente

Não as retome sem decidir a questão de fundo primeiro:

- **Recomendações de correlação entre incidentes.** O motor de correlação já
  cria essas ligações automaticamente; uma recomendação por cima duplicaria a
  mesma conclusão em dois sítios. Só vale a pena se se decidir tornar a
  correlação uma *proposta* em vez de um automatismo.
- **Marcar eventos como dados de demonstração.** O modelo `Event` não tem
  `is_demo_data` (só o `Alert` tem). Na prática a proveniência lê-se no
  `source_name` — o semeador usa `suricata-demo` — e no `raw_payload`, que é
  prova mais forte que um booleano. Acrescentar a coluna exigiria migração.

---

## 5. Armadilhas — leia esta secção antes de escrever código

Cada uma destas custou tempo real. Nenhuma produz um erro claro; é isso que as
torna caras.

### 5.1 O TypeScript não valida nomes de classes CSS

`className="cartao--compacto"` compila perfeitamente mesmo que essa classe não
exista. Já foram inventadas quatro. **Depois de escrever JSX, confronte cada
classe e cada `var(--token)` com `frontend/src/estilos/`.** Um `grep` chega.

### 5.2 O FastAPI ignora parâmetros de consulta que não declara

Um filtro que a interface oferece e a rota não declara devolve a lista completa,
sem erro — e o utilizador conclui que não havia nada a filtrar. Aconteceu com a
severidade em `/events`. **Um teste que só verifica 200 não apanha isto**: exija
que a contagem filtrada seja diferente da total.

### 5.3 Esquemas de entrada herdam `ApiInput`, nunca `ApiModel`

`ApiModel` é a base das **respostas** e traz `use_enum_values=True`, que
substitui o membro do enum pela string — e qualquer leitura de `.kind.value`
rebenta com `AttributeError`. Foi assim que `POST /integrations/api-keys`
devolveu 500 em todos os pedidos válidos desde que foi escrita. `ApiInput` traz
ainda `extra="forbid"`, logo um nome de campo trocado falha em voz alta em vez
de se perder.

### 5.4 Relógios dessincronizados não produzem erro nenhum

No laboratório, o gerador de alertas escrevia hora local (UTC+2) enquanto os
contentores corriam em UTC. Os registos apareciam, o coletor dizia que estava a
analisar, a regra correspondia no `wazuh-logtest` — e **nenhum alerta era
gerado, sem erro em lado nenhum**. A página `/eventos` mostra agora o atraso
entre ocorrência e recepção e destaca-o quando é negativo, precisamente para
tornar isto visível. Use-a quando algo "desaparece".

### 5.5 O token vive em memória, portanto `<a href>` dá sempre 401

Uma navegação do browser não leva o cabeçalho `Authorization`. Descargas têm de
passar por `descarregar()` em `frontend/src/api/cliente.ts`, que busca o blob
autenticado. Já falhou duas vezes: nas evidências e na exportação PDF.

### 5.6 A ordem das dependências do FastAPI decide quem aparece na auditoria

As dependências resolvem-se na ordem da assinatura. Quando `AuditDep` vinha
antes de `require(...)`, o contexto era construído **antes** da autenticação e
*todas* as acções autenticadas ficavam registadas como `anonimo` — o que
desligava silenciosamente a separação de funções. Está resolvido por o
`AuditContext` resolver a identidade tardiamente, a partir de `request.state`,
no momento da escrita. Não reintroduza resolução antecipada.

### 5.7 `ipaddress.is_private` classifica as redes de documentação como privadas

RFC 5737 (`203.0.113.0/24`, `198.51.100.0/24`) é o que se usa para representar
atacantes em laboratório — e `is_private` diz que são internas, pelo que os IOCs
eram descartados em silêncio. Use `is_external_ip()` de
`app/ingestion/base.py`, que tem uma lista explícita de redes internas.

### 5.8 Correlacionar pelo lado errado conclui "mesmo atacante" a partir da vítima

A estratégia `ENTIDADE_PARTILHADA` agrupava alertas por anfitrião partilhado, o
que junta incidentes só porque atingiram o mesmo servidor. Correlacione apenas
por observações do lado do atacante (`ATTACKER_SIDE_ROLES` em
`app/correlation/engine.py`). No mesmo espírito: no Wazuh, `srcuser` é o **actor**
e `dstuser` é o **alvo** — trocá-los marca a conta atacada como atacante.

### 5.9 Em Windows, `pkill` não acerta no uvicorn e a porta 5173 é reservada

O processo aparece apenas como `python3.11`, pelo que `scripts/api.sh` mata **por
porta** via PowerShell. E o Windows reserva 5141–5240 para Hyper-V/WSL: a 5173
dava `EACCES: permission denied` sem explicação, daí a interface estar na
**5500**. Confirme com
`netsh interface ipv4 show excludedportrange protocol=tcp`.

### 5.10 `session.get()` não carrega relações

Devolve o objecto sem as relações, e a primeira leitura de uma delas dispara IO
fora do contexto assíncrono — `MissingGreenlet`, que chega ao utilizador como
500. Use `selectinload` explícito quando for preciso a relação. Aconteceu com
`Task.depends_on` ao concluir uma tarefa.

### 5.11 `Date.now()` durante o render congela o que depende do tempo

Um render só acontece quando algo muda — e o React Query, quando um refetch traz
os **mesmos** dados, mantém o objecto anterior e não provoca render nenhum.
Resultado: na fila de incidentes, um prazo que expirasse com a página aberta
**não ficava vermelho**; no centro de operações, a contagem "faltam 3 min" ficava
parada depois de o prazo passar. Nenhum erro, nenhum aviso — só um sinal
visual errado, precisamente o que o analista usa para decidir.

**Use `useAgora()` de `frontend/src/componentes/relogio.ts`**, que é um relógio
partilhado (um só intervalo para a aplicação) e faz do tempo uma entrada do
render.

O `eslint` apanhou um dos dois casos. O outro estava dentro de uma função
auxiliar, onde a regra `react-hooks/purity` não vê. **O linter não substitui um
`grep -rn "Date.now()" src`** depois de escrever código que dependa do tempo.

### 5.12 `now()` do PostgreSQL é o início da transacção, não a hora actual

Tudo o que um pedido grava com `now()` fica com o mesmo instante — o do início.
A linha temporal punha comentários escritos no fim de um pedido antes da criação
do incidente, sem erro nenhum. Os valores por omissão de `created_at` e
`updated_at` usam `clock_timestamp()` desde a migração `0005_instantes_reais`:
**não escreva `func.now()` num modelo novo**. Nos testes o efeito é máximo,
porque cada teste corre inteiro numa transacção — o que ajuda: é lá que se vê.

### 5.13 Na retoma de um playbook, o `ctx` é de quem aprovou

`resume_execution` corre dentro do pedido de decisão, pelo que `ctx.actor_id` é o
aprovador, não quem iniciou o playbook. Código do motor que use `ctx.actor_id`
como "quem fez isto" atribui ao aprovador o que é do playbook: foi assim que o
gestor passou a "proponente" do bloqueio e ficou impedido de o aprovar. Para a
autoria use `execution.triggered_by_id`; o `ctx` continua certo para a
auditoria, que regista em que pedido cada coisa aconteceu.

E **aprovar não é executar**: `decide_action` só muda o estado para APROVADA. Se
nada executar a acção, o passo seguinte corre sobre algo que não aconteceu.

### 5.16 Um identificador vindo do cliente não prova que o registo existe

`assignee_id`, `team_id`, `asset_id`: se não existir, a chave estrangeira recusa-o
e a rota responde **500** a um erro do cliente. E numa consulta por lista
(`Model.id.in_(ids)`) é pior — os inexistentes são ignorados em silêncio e a
operação parece ter corrido bem. Acontecia em oito portas. **Numa rota nova que
receba identificadores de outros registos, use `require_existing` ou
`require_all_existing` de `app/core/lookups.py`**, de preferência no serviço, para
valer para todos os chamadores. A interface não o apanha: só escolhe de listas.

### 5.15 Uma regra de estado vale em todas as portas, não só na que a verificou

`ALERT_TRANSITIONS` e `INCIDENT_TRANSITIONS` são a única fonte de verdade do ciclo
de vida — mas só protegem o que as consulta. A rota de triagem consultava; a
promoção e a ligação mudavam o estado do alerta directamente. O mesmo com
`LINKABLE_STATUSES`: o motor de correlação recusava ligar alertas a incidentes
encerrados, a ligação manual não. **Quando acrescentar uma operação que muda um
estado, procure todas as outras que já o mudam** (`grep -rn "\.status = "`) e
confirme que passam pela mesma verificação. A regra deve viver no serviço, não
na rota, para valer também para a correlação automática e para a demonstração.

Esta armadilha voltou a render em 2026-09-28. A guarda do incidente ENCERRADO
(`incident_service.garantir_editavel`, defeito 65) estava em cinco sítios e
faltava em cinco caminhos que entraram depois: associar e remover técnicas MITRE,
propor uma acção, correr um playbook, aceitar ou ligar uma comunicação externa, e
aplicar uma recomendação. Todos foram vistos abertos antes de serem fechados — um
playbook escrevia uma nota dentro de um incidente fechado, e uma recomendação
mudava-lhe a severidade. **A pergunta a fazer não é "protegi esta rota?" mas
"quantos caminhos escrevem isto?"** — e o sítio da guarda é o funil comum: nas
recomendações ficou em `_carregar_incidente`, por onde passam os quatro
aplicadores com alvo incidente. `tests/test_incidente_encerrado.py` fixa as cinco
portas e dois controlos: comentar e relacionar continuam permitidos, e o que já
existia continua consultável.

### 5.14 Num PATCH, omitir um campo não é o mesmo que enviá-lo a `null`

Os esquemas de edição declaram todos os campos opcionais — é o que permite
omiti-los —, e por isso também aceitam `null` em campos que a base de dados exige.
Aplicar `model_dump(exclude_unset=True)` com `setattr` deixava o objecto inválido,
e a rota dava 500 ao serializar. Acontecia em cinco rotas. **Numa rota PATCH nova,
chame `reject_nulls_for_required(objecto, alteracoes)`** de
`app/core/partial_update.py` antes do `setattr`: lê a nulabilidade do próprio
modelo e responde 422. A interface nunca o desencadeia — só envia o que mudou —,
por isso só um teste o apanha.

### 5.17 `datetime.now()` não distingue duas chamadas seguidas

Em Windows a granularidade do relógio do sistema é de cerca de um milissegundo, e
duas chamadas consecutivas devolvem o **mesmo** valor — medido nesta máquina, 20
pares em 20. Qualquer coisa que use o instante como elemento distintivo — um
identificador sintético, uma chave de deduplicação, uma ordenação por chegada —
trata dois acontecimentos como um só. Foi assim que a ingestão genérica perdia o
segundo de dois eventos entregues seguidos, apesar de o código dizer
explicitamente que preferia contar um reenvio duas vezes a perder uma ocorrência.

**Para "cada um conta", use um token próprio** (`uuid4()`), não o relógio. E
repare que isto é o oposto da armadilha 5.12: lá o problema era o `now()` do
PostgreSQL ser demasiado *grosseiro* dentro de uma transacção; aqui é o `now()`
de Python ser demasiado grosseiro entre duas chamadas. Em ambos os casos a
correcção é a mesma: não fazer a identidade depender do tempo.

Confirme antes de assumir:

```bash
./.venv/Scripts/python.exe -c "
from datetime import datetime, UTC
print(sum(datetime.now(UTC) == datetime.now(UTC) for _ in range(20)), '/20 iguais')"
```

### 5.18 Uma permissão nova não chega sozinha aos perfis que já existem

`sync_roles` só concede aos perfis **existentes** as permissões que
`sync_permissions` acabou de criar **nessa chamada** — e é o comportamento certo
em produção, porque respeita ajustes deliberados de um administrador. Mas o
`conftest` descartava o valor de retorno, pelo que os perfis de teste nunca
recebiam nada de novo.

O efeito é silencioso e persistente: a permissão nasce na primeira corrida
depois de ser acrescentada ao código e, a partir daí, deixa de ser "nova". Testes
de autorização passam a falhar com 403 sem que nada no código de produção esteja
errado — e, na direcção oposta, um teste que verifique que alguém **não** tem uma
permissão passa por acidente.

O `conftest` passa agora **todos** os códigos, não só os criados: numa base de
teste o estado tem de espelhar `ROLE_PERMISSIONS` exactamente, porque é contra
esse mapa que os testes afirmam. Depois de acrescentar uma permissão, confirme
com:

```bash
docker compose exec -T db-test psql -U sheisa -d sheisa_test -c   "select r.name, count(*) from roles r join role_permissions rp on rp.role_id=r.id group by 1 order by 1"
```

**E a mesma armadilha existe na base de desenvolvimento, com outra cara.** Aí não
é o `conftest` que falha: é ninguém ter corrido `manage init` depois do `pull`. Em
2026-09-28 mediu-se 51 permissões no código e 49 na base; as duas em falta eram as
da caixa de comunicações, e o efeito era a API a responder 403 em
`/reports-inbox` a **todos** os perfis — administrador incluído, apesar de o mapa
lhe dar `frozenset(Permission)`. Falha fechada, o que é o comportamento certo, mas
silenciosa: nada distingue "não tem permissão" de "a permissão não existe". Quem
só olhasse para `ROLE_PERMISSIONS` concluiria que estava tudo bem. O
`verificar_contrato.py` foi o que apanhou o 403 — mais uma razão para o correr
depois de um `pull`, e não só depois de mexer em esquemas.

**A plataforma passou a dizê-lo** (defeito 71): o `lifespan` chama
`bootstrap.avisar_de_permissoes_em_falta`, que regista as permissões em falta pelo
nome e o comando que as cria. Verificado com a API a correr, apagando uma
permissão da base e repondo-a. Se acrescentar uma permissão nova, o arranque
avisa-o até correr `manage init` — mas o aviso vive no registo, não na interface,
pelo que continua a valer olhar para o `api.log` depois de um `pull`.

### 5.19 `NotFoundError` construía a mensagem no masculino

`f"{recurso} não encontrado."` produzia "Equipa não encontrado" e "Evidência não
encontrado" — metade dos vinte e três recursos da plataforma é feminina. Num
produto cuja regra é ser inteiramente em português, é um erro que se lê, e passou
a ser visível a quem comunica de fora.

Resolvido com **"inexistente"**, que é invariável em género e serve os vinte e
três de uma vez. Passar o género em cada chamada exigiria acertar em vinte sítios
e continuaria a falhar no vigésimo primeiro; inferir da terminação não serve,
porque "Alerta" termina em "a" e é masculino.

### 5.20 A caixa de segurança recebe as mensagens da própria plataforma

`cert@` é ao mesmo tempo a caixa que se lê e o endereço de onde se envia. Tudo o
que a plataforma manda pode voltar — por devolução, por resposta automática, ou
porque o servidor de desenvolvimento entrega tudo na mesma caixa. Sem descarte, o
aviso de recepção era recolhido como comunicação nova, que gerava outro aviso:
**um ciclo que se alimenta a si mesmo.** Observado a correr: três avisos, três
comunicações.

Quatro sinais, por ordem de fiabilidade, cada um registando o seu motivo:

1. `X-SHEISA-Origem: plataforma` — a marca própria. Mais fiável do que comparar o
   remetente, porque o `From` de uma devolução é o do servidor que devolveu.
2. `Auto-Submitted` (RFC 3834) e `Precedence` — respostas automáticas e listas.
3. `Content-Type: multipart/report; report-type=delivery-status` (RFC 3464) — é
   estrutura da mensagem, não convenção.
4. Remetentes de sistema (`MAILER-DAEMON`, `postmaster`, `no-reply`).

**A ausência de `Return-Path` não é sinal de nada.** É o servidor receptor que o
escreve, e muita mensagem legítima chega sem ele; só o `<>` explícito indica
devolução. Tratar a ausência como devolução descartaria comunicações reais, e o
efeito seria invisível — uma comunicação descartada não deixa rasto na fila.

Ao testar isto, note que `smtplib.send_message` usa o `From` como remetente de
envelope, pelo que **não** consegue simular uma devolução: use
`sendmail("", [destino], msg.as_string())`. E o Mailpit não escreve
`Return-Path: <>` nem para um envelope vazio, pelo que esse sinal em particular só
se observa contra um MTA a sério.

### 5.21 `decode_header` levanta uma excepção que não é `ValueError`

Um assunto `=?utf-8?B?...?=` com base64 inválido faz `decode_header` levantar
`email.errors.HeaderParseError`, que **não** é subclasse de `ValueError`. Apanhar
só `(UnicodeDecodeError, LookupError, ValueError)` deixava a desmontagem falhar, e
uma mensagem com um assunto mal codificado era descartada — o oposto do que o
comentário ao lado prometia. Encontrado pelo teste que afirma precisamente que um
cabeçalho mal formado não pode perder a mensagem.

### 5.22 Recolher de uma caixa não é o mesmo que receber uma submissão

A recolha por email chamava o mesmo `submit()` do portal, que envia um aviso de
recepção ao remetente. Contra uma caixa **dedicada** isso é aceitável; contra uma
caixa com correio pessoal, transforma a plataforma numa máquina de auto-resposta
— envia "comunicação recebida" a toda a gente cujo email caia na caixa. Observado
a correr ao apontar a recolha à INBOX de uma conta pessoal.

`submit()` tem agora `avisar: bool`, e `recolher_do_email` passa `avisar=False`:
uma comunicação recolhida **nunca** dispara envio automático; quem tria decide se
responde. A submissão do portal mantém o aviso, porque aí quem preencheu o
formulário está à espera da referência e do código.

Duas defesas, não uma: além disto, aponte a recolha a uma **etiqueta dedicada**
(`SHEISA_IMAP_MAILBOX`), nunca à INBOX de uma conta com correio pessoal — a
recolha marca como lidas as mensagens que processa. No Gmail: criar uma etiqueta
e um filtro que lhe aplique a etiqueta e salte a caixa de entrada.

---

### 5.23 A caixa de correio é estado partilhado, e `recolher` traz um lote

Os testes do ciclo de correio falam com o Mailpit a sério — e a caixa é a mesma
para todos. Pior: a própria suite a enche, porque cada submissão no portal manda
um **aviso de recepção verdadeiro** (`report_inbox_service` chama
`email_service.enviar`). Um teste que esvazie a caixa com uma chamada a
`recolher(apagar=True)` **não a esvazia**: `pop3_max_por_recolha` limita cada
recolha a 50 mensagens, e o limite existe para uma caixa com milhares não
bloquear a recolha inteira.

O sintoma é um teste que passa isolado e falha na suite completa — e só quando a
caixa já passou das 50, o que faz a falha parecer aleatória. Reproduz-se de
propósito injectando 55 mensagens por SMTP em `localhost:1025`. **Num teste que
dependa do conteúdo da caixa, esvazie-a em ciclo** (`_esvaziar_caixa` em
`tests/test_email.py`) e conte só o que o próprio teste enviou. A caixa vê-se em
`http://localhost:8025` e por `curl -s localhost:8025/api/v1/messages?limit=1`.

## 6. Como trabalhar aqui

O ciclo que apanhou quase todos os defeitos acima:

> **construir → verificar tipos → confrontar com a API a correr → só então
> registar**

O terceiro passo é o que conta, e é o que se tende a saltar. Compilar prova
coerência interna, não correspondência com o servidor. Cinco das seis últimas
operações a ganhar interface nunca tinham sido chamadas por ecrã nenhum, e uma
delas devolvia 500 em todos os pedidos válidos sem que nada o revelasse.

**Testes de regressão verificam-se por reversão.** Depois de corrigir um defeito
e escrever o teste, desfaça a correcção e confirme que o teste falha. Um teste
que passa nas duas situações não está a testar nada. Foi feito com todos os
defeitos corrigidos desde 2026-09-17; `ESTADO.md` §4 regista quantos testes cada
reversão fez falhar.

**Asserções ambíguas não valem nada.** `assert codigo in (200, 403)` não afirma
nada. Descubra qual é o valor certo — consultando `ROLE_PERMISSIONS` em
`app/core/permissions.py`, por exemplo — e afirme-o.

**Segredos.** `.env` está no `.gitignore` e nunca foi versionado; só o
`.env.example` com marcadores é que vai para o repositório. Nunca escreva
segredos no código.

> **Pendente de decisão do autor.** A palavra-passe de administração do
> laboratório está em texto claro em [`ESTADO.md` §6](ESTADO.md#6-contas-e-credenciais-do-ambiente-local).
>
> O repositório é **privado** — verificado em 2026-09-17: a API do GitHub
> devolve 404 a um pedido sem autenticação. (Este aviso dizia antes "público",
> o que exagerava o risco.) A palavra-passe não está, portanto, indexável.
>
> O argumento que resta é outro, e é mais forte: **o valor escrito já está errado
> numa das duas máquinas**. Cada base de dados gera a sua no `manage init`, e o
> documento só consegue guardar uma. A alternativa é substituí-la por uma
> instrução de a gerar com `manage init`, que a mostra uma única vez — e que é o
> que acontece de qualquer maneira numa máquina nova.

---

## 7. Mapa mínimo para se orientar

O vocabulário do domínio está em `backend/app/core/enums.py`, e
`INCIDENT_TRANSITIONS` / `ALERT_TRANSITIONS` são a **única** fonte de verdade
dos ciclos de vida — não duplique essas regras em nenhum outro sítio.

Três distinções conceptuais que atravessam o código e que convém não colapsar:

- **Evento ≠ Alerta ≠ Incidente.** Muitos eventos equivalentes convergem num
  alerta; o alerta só se torna incidente por decisão. A página `/eventos` existe
  para tornar essa agregação observável em vez de afirmada.
- **IOC ≠ Observação.** O IOC é global (`203.0.113.212` existe uma vez); a
  observação é o avistamento contextual, com papel (actor, alvo) e incidente.
- **Afirmado ≠ inferido.** Uma técnica MITRE afirmada por um analista e uma
  proposta pelo motor aparecem visualmente distintas, e a confiança de qualquer
  inferência tem tecto.

Para o resto — que serviço faz o quê, que ficheiro tem cada coisa — veja
[`ESTADO.md` §7](ESTADO.md#7-mapa-do-código) e
[`ARQUITECTURA.md`](ARQUITECTURA.md).

Os dois documentos que definem o trabalho:
[`MONOGRAFIA-CAP4.md`](MONOGRAFIA-CAP4.md) (o que vai ser defendido; **§4.14 é o
cenário de demonstração**) e [`BRIEFING.md`](BRIEFING.md) (especificação
técnica). Atenção: a numeração `§4`, `§12`… citada nos comentários do código vem
de um briefing anterior que não está versionado e **não corresponde** a nenhum
dos dois — mas cada citação vem acompanhada da frase que explica a regra, e essa
frase é autossuficiente.
