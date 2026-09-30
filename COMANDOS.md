# SHEISA — lista de comandos

Referência rápida, para copiar e colar. Windows, numa **PowerShell**.
Para o guia com explicações, ver [`INSTALAR.md`](INSTALAR.md).

---

## 1. Obter / actualizar o código

```powershell
# primeira vez:
git clone https://github.com/Bauirxx/sheisaproject.git
cd sheisaproject

# já tem o clone (traz as últimas alterações):
cd sheisaproject
git pull origin main
```

## 2. Instalar tudo (um só comando)

```powershell
powershell -ExecutionPolicy Bypass -File instalar.ps1
```

Instala dependências (Docker, Python, Node), gera a configuração, levanta a base
de dados, migra, semeia, **liga as integrações** (QRadar/NetScout ficam ACTIVA),
instala o Suricata e arranca a plataforma. Pede administrador sozinho.
No fim, mostra a **palavra-passe de administração** — guarde-a (só aparece uma vez).

> Se instalou o Docker agora: reinicie o Windows, abra o Docker Desktop uma vez,
> e volte a correr `instalar.ps1` (retoma de onde parou).

## 3. Gerir a plataforma no dia-a-dia

```powershell
.\sheisa.ps1 iniciar      # arranca tudo e liga as integrações
.\sheisa.ps1 estado       # mostra o que está a correr
.\sheisa.ps1 parar        # pára a API, a interface e o sensor
.\sheisa.ps1 reiniciar    # pára e volta a arrancar
.\sheisa.ps1 conectar     # (re)liga QRadar/NetScout, se preciso
```

> Para o sensor Suricata arrancar, corra o `sheisa.ps1` **como administrador**.

## 4. Aceder

| | |
|---|---|
| Interface | http://127.0.0.1:5500 |
| API (docs) | http://127.0.0.1:8099/api/docs |
| Portal externo | http://127.0.0.1:5500/comunicar |
| Correio (laboratório) | http://127.0.0.1:8025 |

Conta: **`admin@sheisa.local`** + a palavra-passe que o instalador mostrou.

---

## Comandos avançados (opcionais)

```powershell
cd backend

# Ligar/reimportar integrações de pull (QRadar, NetScout):
.\.venv\Scripts\python.exe -m scripts.manage conectar-integracoes

# Repor / carregar dados:
.\.venv\Scripts\python.exe -m scripts.manage mitre-load           # catálogo MITRE ATT&CK
.\.venv\Scripts\python.exe -m scripts.manage seed-integrations    # catálogo de integrações

# Criar chave de ingestão (para um sensor: WAZUH | SURICATA | API_GENERICA):
.\.venv\Scripts\python.exe -m scripts.manage create-api-key --name "Nome" --kind SURICATA

# Cenário de demonstração (marcado como dados de demo, removível):
.\.venv\Scripts\python.exe -m scripts.manage demo --reset

# Testes:
.\.venv\Scripts\python.exe -m pytest -q
```

## Laboratório de detecção (Wazuh + Suricata, opcional)

```powershell
bash lab/preparar.sh
docker compose -f lab/docker-compose.lab.yml up -d --build
bash lab/gerar-alertas.sh tudo
```

## Sensor Suricata noutra máquina (ataques reais)

- Windows nativo: ver [`lab/windows-sensor/README.md`](lab/windows-sensor/README.md)
- Linux: ver [`lab/sensor-remoto/README.md`](lab/sensor-remoto/README.md)

## Ligar a QRadar / NetScout reais

Ver [`docs/QRADAR-NETSCOUT-INSTANCIAS-REAIS.md`](docs/QRADAR-NETSCOUT-INSTANCIAS-REAIS.md).
