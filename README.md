# SHEISA

Plataforma de gestão e resposta a incidentes cibernéticos (SOC/CSIRT),
desenvolvida como componente prática de uma monografia sobre o Instituto
Nacional das Comunicações de Moçambique (INCM).

Inspirada no **RTIR**, no **TheHive** e no **Wazuh**, mas com arquitectura
própria: nenhuma destas plataformas é copiada, e o capítulo
[`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) explica o que se aproveitou de
cada uma e o que se fez de outra maneira, e porquê.

> **A retomar o desenvolvimento?** Comece em
> [`docs/CONTINUAR.md`](docs/CONTINUAR.md) — estado actual, o que fazer a
> seguir, e as armadilhas que já custaram horas. Este `README` serve para
> instalar de raiz; o `CONTINUAR.md` serve para continuar.

---

## O princípio que governa o projecto

> **Se não está implementado, não é apresentado como implementado.**

Não há dados simulados, contagens inventadas nem integrações decorativas. Em
concreto:

- os números do painel são contados na base de dados **no momento do pedido** —
  não há valores em cache nem pré-calculados;
- uma integração só aparece como **ACTIVA** depois de responder a um teste de
  ligação ou de ter recebido eventos reais; declarar credenciais coloca-a em
  *configurada*, não em *activa*;
- uma acção de resposta sem integração activa **falha de forma explícita**, com
  503 e explicação — não existe modo "simulado" que devolva sucesso;
- as técnicas MITRE distinguem sempre o que a fonte **afirmou** do que o motor
  **inferiu**;
- os dados de demonstração são marcados como tal e entram pelo mesmo caminho
  que os dados reais.

## O que a plataforma faz

```
DETECÇÃO → INGESTÃO → NORMALIZAÇÃO → DEDUPLICAÇÃO → TRIAGEM
         → CORRELAÇÃO → INCIDENTE → INVESTIGAÇÃO → DECISÃO
         → APROVAÇÃO → RESPOSTA → RESOLUÇÃO → RELATÓRIO
```

**O que a distingue de um sistema de bilhetes:**

| | |
|---|---|
| **Evento ≠ Alerta ≠ Incidente** | 4 000 tentativas de força bruta são *um* alerta com `event_count=4000`, não 4 000 alertas. E um alerta só se torna incidente por decisão — humana ou de uma regra de correlação explícita. |
| **Correlação a sério** | Quatro estratégias configuráveis em base de dados, não uma pesquisa por semelhança. Só considera artefactos do **lado do atacante**: partilhar a vítima não é evidência de ser o mesmo actor. |
| **Inteligência explicável** | Cada pontuação traz a decomposição por factor, com os pontos e a razão de cada um. A soma confere sempre com o total — pode ser verificada à frente de um júri. |
| **Decisão auditável** | Quem propõe uma acção não a pode aprovar. Acções críticas exigem justificação escrita. Tudo fica num registo de auditoria que o PostgreSQL recusa alterar. |
| **Grafo investigativo** | As arestas transportam o papel do artefacto (origem, destino, alvo), o que permite navegar de um incidente para outro sem perder o contexto. |

## Arranque rápido

### Windows — um só comando (recomendado)

Numa máquina Windows, o instalador trata de **tudo**: instala as dependências
(Docker, Python, Node) se faltarem, gera a configuração com segredos próprios,
levanta a base de dados, migra, semeia os dados iniciais, instala o Suricata
nativo, e deixa a plataforma a correr. Pede elevação de administrador sozinho.

```powershell
git clone https://github.com/Bauirxx/sheisaproject.git
cd sheisaproject
powershell -ExecutionPolicy Bypass -File instalar.ps1
```

No fim, mostra o endereço da interface e a palavra-passe de administração (uma
única vez). É idempotente: se algo faltar (por exemplo, reiniciar depois de
instalar o Docker pela primeira vez), volte a correr o mesmo comando.

**Gerir a plataforma no dia-a-dia** — um só comando para tudo (base de dados,
API, interface, sensor):

```powershell
.\sheisa.ps1 iniciar     # arranca tudo
.\sheisa.ps1 estado      # o que está a correr
.\sheisa.ps1 parar       # pára a API, a interface e o sensor
.\sheisa.ps1 reiniciar
```

### Manual (qualquer sistema)

**Necessário:** Python 3.11+, Node 20+, Docker.

```bash
git clone https://github.com/Bauirxx/sheisaproject.git
cd sheisaproject

cp .env.example .env
# Gere segredos reais para POSTGRES_PASSWORD, SHEISA_JWT_SECRET,
# SHEISA_LAB_MAIL_PASSWORD e os tokens dos SIEM:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

docker compose up -d db db-test mail qradar-sim netscout-sim

cd backend
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe -m scripts.manage init            # mostra a palavra-passe uma única vez
./.venv/Scripts/python.exe -m scripts.manage mitre-load      # ATT&CK real (~50 MB)
./.venv/Scripts/python.exe -m scripts.manage seed-correlation
./.venv/Scripts/python.exe -m scripts.manage seed-playbooks
./.venv/Scripts/python.exe -m scripts.manage seed-assets
./.venv/Scripts/python.exe -m scripts.manage seed-integrations
./scripts/api.sh start
```

```bash
cd ../frontend
npm install
npm run dev
```

| | |
|---|---|
| Interface | http://127.0.0.1:5500 |
| API | http://127.0.0.1:8099 |
| Documentação da API | http://127.0.0.1:8099/api/docs |
| Portal externo (sem conta) | http://127.0.0.1:5500/comunicar |
| Caixa de correio do laboratório | http://127.0.0.1:8025 |

> **Porta 5500 e não a 5173 habitual do Vite.** O Windows reserva intervalos de
> portas para o Hyper-V/WSL e a 5173 cai dentro de um deles em algumas
> máquinas, com o erro enganador `EACCES: permission denied`. Verifique com
> `netsh interface ipv4 show excludedportrange protocol=tcp` e ajuste com a
> variável `SHEISA_PORTA_UI`.

## Demonstração

```bash
cd backend
./.venv/Scripts/python.exe -m scripts.manage demo --reset
```

Percorre os dez passos do §4.14 da monografia — do alerta do Suricata ao
encerramento do incidente — **pelo fluxo real da aplicação**, não por inserções
directas na base de dados. Tudo fica marcado como dados de demonstração e é
removível com `--reset`.

## Testes

```bash
cd backend
./.venv/Scripts/python.exe -m pytest
```

222 testes. Cobrem autenticação, autorização, ciclo de vida, auditoria,
normalizadores, deduplicação, correlação, pontuação, aprovações, carregamentos
e um percurso ponta-a-ponta de alerta a relatório.

## Laboratório de detecção

```bash
bash lab/preparar.sh
docker compose -f lab/docker-compose.lab.yml up -d --build
bash lab/gerar-alertas.sh
```

Levanta um gestor Wazuh e um agente reais. Os alertas chegam à plataforma pelo
daemon `integrator` do Wazuh, através do script `custom-sheisa` — o mecanismo
que o Wazuh de facto usa, não uma simulação.

## Estrutura

```
backend/     API FastAPI, 106 rotas · SQLAlchemy · PostgreSQL · Alembic
  app/core/         configuração, segurança, permissões, auditoria, ciclos de vida
  app/models/       35 entidades
  app/ingestion/    normalizadores (Wazuh, Suricata, genérico)
  app/correlation/  motor de correlação
  app/intelligence/ triagem e recomendações determinísticas
  app/playbooks/    motor de execução com suspensão em aprovação
  app/integrations/ conectores (Wazuh, QRadar, NetScout)
frontend/    React + TypeScript + Vite, interface em português
lab/         laboratório Wazuh em Docker
docs/        arquitectura, estado do projecto, monografia e briefing
```

## Documentação

- [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) — análise crítica do RTIR, do
  TheHive e do Wazuh, e as decisões de modelação que daí resultaram.
- [`docs/ESTADO.md`](docs/ESTADO.md) — o que está feito e verificado, o que
  falta, e como retomar o trabalho.
- [`docs/MONOGRAFIA-CAP4.md`](docs/MONOGRAFIA-CAP4.md) — o capítulo que será
  defendido.
- [`docs/BRIEFING.md`](docs/BRIEFING.md) — especificação técnica.

## Licença e contexto

Trabalho académico. As referências ao INCM descrevem o enquadramento do estudo
de caso; as funcionalidades aqui implementadas são **propostas do protótipo** e
não descrevem sistemas em uso naquela instituição.
