# Configuracao do sensor Suricata nativo Windows. Copie para `sensor.env.ps1`
# (ignorado pelo git) e preencha a chave.

$env:SHEISA_HOOK_URL = "http://127.0.0.1:8099/api/ingest/suricata"

# Chave de ingestao do tipo SURICATA, criada na maquina central com:
#   cd backend; .\.venv\Scripts\python.exe -m scripts.manage `
#     create-api-key --name "Sensor Windows nativo" --kind SURICATA
$env:SHEISA_API_KEY = "cole-aqui-a-chave-de-ingestao"
