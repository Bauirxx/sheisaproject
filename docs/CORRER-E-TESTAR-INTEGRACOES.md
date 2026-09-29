# Correr e testar as integrações — playbook para outra máquina

Guia passo a passo para pôr as cinco integrações (Wazuh, Suricata, QRadar,
NetScout, API genérica) **e o canal de correio** a correr e a testar numa máquina
nova. Escrito para retomar o trabalho noutra instância, do zero.

> Complementa [`INTEGRACOES.md`](INTEGRACOES.md) (referência de cada integração) com
> os comandos exactos e as armadilhas do laboratório. Números e comandos foram
> confirmados a correr em 2026-09-28.

## 1. O que é real e o que é simulador (não confundir na defesa)

| Integração | Sentido | O que é testado de verdade | A origem dos dados |
|---|---|---|---|
| **Wazuh** | Envio + resposta | Cadeia completa: log → regra → integrador → SHEISA | Laboratório real (gestor 4.12.0) |
| **Suricata** | Envio | IDS real sobre tráfego real | Laboratório real (ou sensor remoto) |
| **API genérica** | Envio | Ingestão pelo pipeline comum | Qualquer POST |
| **IBM QRadar** | Importação (pull) | Conector + normalização + ingestão reais | **Simulador** da API (`lab/siem-sim`) |
| **NetScout** | Importação (pull) | Conector + normalização + ingestão reais | **Simulador** da API (`lab/siem-sim`) |

O QRadar e o NetScout **não** se instalam: são appliances comerciais, sem imagem
Docker. O `lab/siem-sim` fala a API REST real de cada um, pelo que o código do
conector é o mesmo que falaria com o produto — só a origem é de laboratório.
Trocar por instâncias reais é mudar quatro variáveis, nada de código.

## 2. Portas e serviços (referência)

| Serviço | Porta | Contentor / processo |
|---|---|---|
| API | 8099 | `backend/scripts/api.sh` (uvicorn) |
| Interface | 5500 | `cd frontend && npm run dev` (Vite) |
| PostgreSQL | 15433 / 15434 | `db` / `db-test` |
| Mailpit (correio lab) | 1025 SMTP · 1110 POP3 · 8025 UI | `mail` |
| QRadar simulado | 8110 | `qradar-sim` |
| NetScout simulado | 8111 | `netscout-sim` |
| Wazuh gestor | 1514/1515 · 55000 | `sheisa-wazuh-manager` (lab) |
| Alvo web (Suricata lab) | 8080 | `sheisa-lab-alvo` (lab) |

`db`, `db-test`, `mail`, `qradar-sim` e `netscout-sim` estão no
`docker-compose.yml` da raiz. O Wazuh e o Suricata do laboratório vivem em
`lab/docker-compose.lab.yml`.

## 3. Arranque base (máquina nova, do zero)

```bash
# 1. Segredos: partir do exemplo e preencher (ver secção 4).
cp .env.example .env            # depois editar

# 2. Ambiente Python
cd backend && python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt   # Windows
cd ..

# 3. Bases de dados + serviços de infra + simuladores SIEM
docker compose up -d db db-test mail qradar-sim netscout-sim

# 4. Migrações, permissões, conta de administração e catálogo de integrações
cd backend
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe -m scripts.manage init            # GUARDE a palavra-passe que imprime
./.venv/Scripts/python.exe -m scripts.manage seed-integrations

# 5. API e interface
./scripts/api.sh start
cd ../frontend && npm install && npm run dev
```

> **Depois de qualquer `git pull`**: reiniciar a API (`./scripts/api.sh restart`),
> e correr `python -m scripts.manage init` (idempotente) para as permissões novas
> chegarem à base — senão as rotas respondem 403. Ver `CONTINUAR.md` §5.18.

## 4. Segredos no `.env` (o que definir)

O `.env` **não** vai para o git; cada máquina tem o seu. A partir do
`.env.example`, os que interessam às integrações:

| Variável | Para quê |
|---|---|
| `SHEISA_QRADAR_API_URL` / `_TOKEN` | Apontam para o simulador (`http://127.0.0.1:8110`) e autenticam. O **mesmo** token vai, pelo `docker-compose`, para o simulador — basta defini-lo uma vez. |
| `SHEISA_NETSCOUT_API_URL` / `_TOKEN` | Idem, `http://127.0.0.1:8111`. |
| `SHEISA_SMTP_*`, `SHEISA_MAIL_*`, `SHEISA_IMAP_*`/`POP3_*` | Canal de correio (secção 9). |
| `SHEISA_HOST` | `127.0.0.1` (omissão) ou `0.0.0.0` para aceitar sensores remotos. |

Gerar um token: `python -c "import secrets; print(secrets.token_urlsafe(24))"`.

> **Armadilha:** o `api.sh` carrega o `.env` para o ambiente antes de arrancar o
> uvicorn. Isto é necessário porque o pydantic só lê do `.env` os campos que
> declara (correio, JWT…); os segredos das integrações são lidos de `os.environ`
> pelos conectores. Se arrancar o uvicorn à mão sem carregar o `.env`, o
> `test_connection` do QRadar/NetScout diz "variáveis em falta". Ver `CONTINUAR.md`
> §5.24.

## 5. Obter os identificadores das integrações

As rotas de teste/importação usam o `id` de cada integração (é diferente em cada
base). Para os obter (como administração):

```bash
# TOKEN: substituir <senha> pela palavra-passe de administração
TOKEN=$(curl -s -X POST http://127.0.0.1:8099/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sheisa.local","password":"<senha>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s http://127.0.0.1:8099/api/integrations -H "Authorization: Bearer $TOKEN" \
  | python -c "import sys,json; [print(i['kind'], i['id']) for i in json.load(sys.stdin)]"
```

## 6. QRadar e NetScout (importação, contra o simulador)

```bash
# Os simuladores já sobem no passo 3. Confirmar que respondem:
docker compose ps qradar-sim netscout-sim

# Testar a ligação (ID_QR / ID_NS vindos da secção 5):
curl -s -X POST http://127.0.0.1:8099/api/integrations/$ID_QR/test  -H "Authorization: Bearer $TOKEN"
curl -s -X POST http://127.0.0.1:8099/api/integrations/$ID_NS/test  -H "Authorization: Bearer $TOKEN"
#   -> "Ligação estabelecida com o QRadar 7.5.0 ..." / "... NetScout; 2 alerta(s) ..."

# Importar (ingere pelo pipeline normal; idempotente por (fonte, id)):
curl -s -X POST http://127.0.0.1:8099/api/integrations/$ID_QR/import -H "Authorization: Bearer $TOKEN"
#   -> importados 3, duplicados 0 na 1ª vez; 0/3 na 2ª (não duplica)
curl -s -X POST http://127.0.0.1:8099/api/integrations/$ID_NS/import -H "Authorization: Bearer $TOKEN"
#   -> importados 2
```

Os alertas aparecem em `/api/alerts` (fonte "IBM QRadar" / "NetScout") e na
interface em `/alertas`. Os dados de exemplo estão em
[`lab/siem-sim/servidor.py`](../lab/siem-sim/servidor.py) — editar aí para outros
cenários; os `id` estáveis é o que garante a idempotência.

## 7. Suricata — laboratório local (IDS real sobre tráfego real)

```bash
# 1. Chave de ingestão do Suricata (uma vez). Se o ossec.conf do Wazuh ainda
#    não existir, lab/preparar.sh cria as duas chaves de uma vez; se já existir,
#    criar só a do Suricata:
cd backend && ./.venv/Scripts/python.exe -m scripts.manage \
  create-api-key --name "Suricata laboratorio" --kind SURICATA
#    -> copiar a chave e escrevê-la em lab/suricata/ingestao.env:
#       SHEISA_SURICATA_KEY=<a-chave>
cd ..

# 2. Subir o alvo, o sensor e o integrador:
export SHEISA_SURICATA_KEY=$(grep -o '=.*' lab/suricata/ingestao.env | cut -c2-)
docker compose -f lab/docker-compose.lab.yml up -d --build alvo suricata suricata-integrador

# 3. Atacar o alvo (recon + exploração + força bruta) e ver os alertas a chegar:
export MSYS_NO_PATHCONV=1        # Git Bash no Windows: não converter os caminhos
bash lab/atacar-suricata.sh
docker logs -f sheisa-lab-suricata-integrador     # "N alerta(s) entregue(s) (HTTP 202...)"
```

Dispara regras ET Open (SSH/Tomcat brute force, recon) e regras locais SHEISA
(path traversal, ficheiro sensível, força bruta HTTP). Verificado a correr: um
ataque → **98 alertas** entregues.

### 7.1 Alternativa: Suricata nativo no Windows (sem Docker), para ataques de outro dispositivo

Para capturar tráfego que atravesse mesmo a rede física (ataque de outro
telemóvel/PC contra esta máquina), o laboratório Docker acima não chega — o
alvo é um contentor. `lab/windows-sensor/` corre o Suricata directamente sobre
a placa física do Windows, via WinDivert (**não** Npcap — ver armadilhas 5.25 e
5.26 no `CONTINUAR.md`, incluindo duas tentativas que não funcionam e porquê).
Passos e o comando de ataque de outro dispositivo em
`lab/windows-sensor/README.md`.

## 8. Wazuh — laboratório local

```bash
# 1. Chave e configuração do integrador (uma vez):
bash lab/preparar.sh             # cria a chave WAZUH e escreve lab/config/ossec.conf

# 2. Subir o gestor e o agente:
docker compose -f lab/docker-compose.lab.yml up -d wazuh-manager wazuh-agent

# 3. Gerar actividade (escreve LOGS reais; as regras do Wazuh decidem):
export MSYS_NO_PATHCONV=1
bash lab/gerar-alertas.sh tudo   # força-bruta + acesso-válido + web
docker exec sheisa-wazuh-manager sh -c \
  'grep "$(date +%Y/%m/%d)" /var/ossec/logs/integrations.log | tail'
#   -> "custom-sheisa: alerta ... entregue (HTTP 202, ... estado=criado)"
```

### Duas armadilhas do Wazuh (custaram tempo)

1. **O agente 001 pode estar desligado.** O `gerar-alertas.sh` escreve por
   omissão na pasta do agente; se ele estiver desligado, os logs não viram
   alertas. Forçar o gestor:
   `CONTENTOR=sheisa-wazuh-manager bash lab/gerar-alertas.sh tudo`.
2. **O `logcollector` só vigia um ficheiro que existia ao arrancar.** Se os
   ficheiros de log forem criados depois, ou o gestor tiver dias de uptime, ele
   não os lê e não há alertas. Confirmar com
   `docker exec sheisa-wazuh-manager sh -c "grep 'lab/gestor' /var/ossec/logs/ossec.log"`
   — se não houver "Analyzing file", **reiniciar o gestor**
   (`docker restart sheisa-wazuh-manager`, ~10 s a ficar `healthy`) e voltar a
   gerar. O `logcollector` lê só as linhas **novas** depois de arrancar.

## 9. Correio electrónico (Gmail real)

Ver [`INTEGRACOES.md`](INTEGRACOES.md) §… e o `.env.example` (bloco Gmail). Resumo:

* **SMTP** (envio): `SHEISA_SMTP_HOST=smtp.gmail.com`, `PORT=587`,
  `STARTTLS=true`, `USER=<conta>@gmail.com`, `PASSWORD=<palavra-passe de
  aplicação, sem espaços>`, `MAIL_FROM=<a mesma conta>` (o Gmail exige que seja
  a conta autenticada). Exige verificação em duas etapas + palavra-passe de
  aplicação (myaccount.google.com/apppasswords).
* **IMAP** (recolha): `COLLECT_PROTOCOL=IMAP`, `IMAP_HOST=imap.gmail.com`,
  `IMAP_PORT=993`, `IMAP_TLS=true`; as credenciais da caixa são as **mesmas** que
  o `POP3_USER`/`POP3_PASSWORD` (o código partilha-as).

**Testar:**

```bash
# Estado do canal (o próprio código diz o que falta):
curl -s http://127.0.0.1:8099/api/reports-inbox/canal-de-email -H "Authorization: Bearer $TOKEN"
# Envio real (autentica no Gmail):
curl -s -X POST "http://127.0.0.1:8099/api/reports-inbox/canal-de-email/testar?destino=<alguem@exemplo.com>" \
  -H "Authorization: Bearer $TOKEN"
# Recolha:
curl -s -X POST http://127.0.0.1:8099/api/reports-inbox/recolher-email -H "Authorization: Bearer $TOKEN"
```

> **Armadilha (importante):** a recolha lê as mensagens **não lidas** da caixa
> `SHEISA_IMAP_MAILBOX` e marca-as como lidas. Apontá-la à `INBOX` de uma conta
> **pessoal** converte email pessoal em "comunicações". Para uso real, usar uma
> **conta dedicada** ao CERT (INBOX só com email do CERT) ou uma **etiqueta**
> dedicada no Gmail (`SHEISA_IMAP_MAILBOX=<etiqueta>`) alimentada por um filtro.
> `SHEISA_POP3_MAX_POR_RECOLHA` limita quantas por recolha.

## 10. API genérica

```bash
# Chave de ingestão:
cd backend && ./.venv/Scripts/python.exe -m scripts.manage \
  create-api-key --name "Sensor generico" --kind API_GENERICA
# Enviar um evento (formato interno comum; aceita src_ip, srcip, source_ip, ...):
curl -s -X POST http://127.0.0.1:8099/api/ingest/events \
  -H "X-API-Key: <a-chave>" -H "Content-Type: application/json" \
  -d '{"id":"ev-1","severity":"ALTA","event_type":"acesso_suspeito","description":"...","src_ip":"45.134.20.11"}'
#   -> alerta criado; reenviar o mesmo id -> duplicado_ignorado
```

## 11. Sensores Suricata noutras máquinas (ataques reais distribuídos)

Pacote pronto em [`lab/sensor-remoto/`](../lab/sensor-remoto/) — copiar a pasta
para a outra máquina (Linux, com Docker), preencher `sensor.env` (URL da SHEISA +
chave SURICATA + interface), `docker compose up -d --build`. Requer:

1. Na máquina central, a API a escutar na rede: `SHEISA_HOST=0.0.0.0` no `.env`
   (reiniciar a API), e a **porta 8099 aberta na firewall** (comando no
   `lab/sensor-remoto/README.md`).
2. Uma chave SURICATA por sensor (`manage create-api-key ... --kind SURICATA`).

Nota honesta: o sensor em contentor só vê a interface física em **Linux**; no
Windows/macOS o Docker corre numa VM e não vê a placa real — instalar o Suricata
nativo (ver o README do pacote). Para um agente **Wazuh** noutra máquina é preciso
publicar as portas 1514/1515 do gestor para além de `127.0.0.1` — passo à parte.

## 12. Verificação final

```bash
cd backend
./.venv/Scripts/python.exe -m pytest -q                       # suite (573 a 2026-09-28)
./.venv/Scripts/python.exe -m ruff check .                    # tem de passar limpo
./.venv/Scripts/python.exe scripts/verificar_contrato.py <senha>   # tipos do frontend vs API viva
```

O estado das cinco integrações confirma-se em `/api/integrations` (todas devem
ficar `ACTIVA` depois de receberem/importarem eventos) ou na interface em
`/integracoes`.
