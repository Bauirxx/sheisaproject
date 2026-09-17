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
> Última actualização: 2026-09-17.

---

## 1. Em três minutos

```bash
cd sheisa_project
docker compose up -d db db-test          # PostgreSQL 16 em :15433 e :15434
cd backend && ./scripts/api.sh start     # API em :8099
cd ../frontend && npm run dev            # interface em :5500
```

Confirmar que está de pé, por esta ordem — cada passo só faz sentido se o
anterior passou:

```bash
curl http://127.0.0.1:8099/api/health/ready
# {"estado":"pronto","base_dados":"acessivel"}

cd backend
./.venv/Scripts/python.exe -m pytest -q                  # 250 a passar
./.venv/Scripts/python.exe -m ruff check .               # All checks passed!
./.venv/Scripts/python.exe scripts/verificar_contrato.py <palavra-passe>

cd ../frontend
npm run verificar                                        # tsc, sem erros
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
| Testes | 250 a passar, 77% de cobertura |
| Qualidade | `ruff check .` limpo em todo o repositório |
| Contrato | `verificar_contrato.py` confere 51 vistas contra a API a correr |
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

### 4.2 Instalar um linter no frontend

Há só `tsc`. Um `eslint` com `eslint-plugin-react-hooks` apanharia dependências
de `useEffect` em falta e variáveis não usadas, que hoje passam silenciosamente.
É a lacuna de qualidade mais concreta que resta.

### 4.3 Subir a cobertura onde ela é baixa por bom motivo

Medido em 2026-09-17: `mitre_service` 19%, `integration_service` 55%,
`timeline_service` e `seed_service` a 0%. Os dois primeiros falam com o exterior
(descarga do bundle STIX, conectores) e testá-los a sério exige duplos de teste,
que ainda não existem; os dois últimos só são exercitados pela CLI e pela rota de
linha temporal.

Meça sempre antes de citar um número destes — o `ESTADO.md` chegou a afirmar 14%
para o `analytics_service`, que está hoje a 76%:

```bash
./.venv/Scripts/python.exe -m pytest --cov=app --cov-report=term
```

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

---

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
que passa nas duas situações não está a testar nada. Foi feito com os dois
últimos defeitos: reverter faz falhar 4 de 6 e 2 de 8.

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
