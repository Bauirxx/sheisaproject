# =====================================================================
#  SHEISA — instalador de um só comando (Windows)
#
#  Instala TUDO o que a plataforma precisa e deixa-a a correr:
#    dependencias (Docker, Python, Node), a base de dados, a API, a
#    interface, o Suricata nativo (captura real de rede) e as chaves.
#
#  Uso, numa PowerShell (pede elevacao de administrador sozinho):
#    powershell -ExecutionPolicy Bypass -File instalar.ps1
#
#  E idempotente: se algo faltar (ex.: reiniciar depois de instalar o
#  Docker), volte a correr o mesmo comando e ele retoma de onde parou.
# =====================================================================

# "Continue" e nao "Stop": os comandos nativos que este instalador chama (docker,
# winget, npm, msiexec) escrevem progresso no stderr como rotina, e "Stop"
# trataria isso como erro fatal. As falhas reais sao apanhadas por $LASTEXITCODE
# e por try/catch, e sinalizadas com Falhar().
$ErrorActionPreference = "Continue"
$RAIZ = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RAIZ

# --- elevacao: o Suricata (WinDivert) e a firewall exigem administrador ---
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$souAdmin = ([Security.Principal.WindowsPrincipal]$ident).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $souAdmin) {
    Write-Host "A pedir elevacao de administrador..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    exit
}

# --------------------------------------------------------------- utilidades
function Passo($n, $texto) {
    Write-Host ""
    Write-Host "==== [$n] $texto" -ForegroundColor Cyan
}
function Ok($texto)   { Write-Host "  OK  $texto" -ForegroundColor Green }
function Aviso($texto){ Write-Host "  !!  $texto" -ForegroundColor Yellow }
function Falhar($texto) { Write-Host "  XX  $texto" -ForegroundColor Red; exit 1 }

function Existe($cmd) {
    $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

function Token([int]$bytes = 24) {
    # Token URL-safe (letras, digitos, - e _), sem = / + que confundiriam o
    # leitor do .env. Gerado com o RNG criptografico do Windows.
    $b = New-Object 'System.Byte[]' $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ([Convert]::ToBase64String($b)).Replace('+','-').Replace('/','_').TrimEnd('=')
}

Write-Host ""
Write-Host "  SHEISA — instalacao completa" -ForegroundColor White
Write-Host "  Plataforma de gestao e resposta a incidentes (SOC/CSIRT)" -ForegroundColor Gray
Write-Host "  Pasta: $RAIZ" -ForegroundColor Gray

# =====================================================================
Passo 1 "Verificar e instalar dependencias (Docker, Python, Node)"
# =====================================================================
$temWinget = Existe winget
if (-not $temWinget) {
    Aviso "winget nao encontrado. Instale manualmente Docker Desktop, Python 3.11+ e Node 20+, depois volte a correr."
}

function GarantirPrograma($cmd, $wingetId, $nome) {
    if (Existe $cmd) { Ok "$nome ja instalado."; return $true }
    if (-not $temWinget) { Aviso "$nome em falta e sem winget para o instalar."; return $false }
    Write-Host "  A instalar $nome (winget)..." -ForegroundColor Gray
    winget install --id $wingetId --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
    # O PATH da sessao nao actualiza logo; recarrega-o.
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path","User")
    if (Existe $cmd) { Ok "$nome instalado."; return $true }
    Aviso "$nome instalado mas ainda nao esta no PATH desta sessao."
    return $false
}

GarantirPrograma "python"  "Python.Python.3.13"        "Python"  | Out-Null
GarantirPrograma "node"    "OpenJS.NodeJS.LTS"         "Node.js" | Out-Null
$temDockerCli = GarantirPrograma "docker" "Docker.DockerDesktop" "Docker Desktop"

# O Docker Desktop precisa de arrancar e, na primeira vez, de um reinicio.
if ($temDockerCli) {
    Write-Host "  A confirmar que o motor Docker responde..." -ForegroundColor Gray
    $dockerOk = $false
    for ($i = 0; $i -lt 3; $i++) {
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $dockerOk = $true; break }
        $exe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $exe) { Start-Process $exe | Out-Null }
        Write-Host "    a aguardar o motor Docker (ate 90s)..." -ForegroundColor DarkGray
        for ($s = 0; $s -lt 30; $s++) {
            Start-Sleep 3
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $dockerOk = $true; break }
        }
        if ($dockerOk) { break }
    }
    if ($dockerOk) { Ok "Motor Docker a responder." }
    else {
        Aviso "O Docker esta instalado mas o motor nao arrancou."
        Aviso "Se acabou de o instalar, REINICIE o Windows, abra o Docker Desktop uma vez, e volte a correr este instalador."
        exit 1
    }
} else {
    Falhar "Sem Docker nao e possivel continuar. Instale o Docker Desktop e volte a correr."
}

$py = "python"
if (-not (Existe $py)) { $py = "py" }

# =====================================================================
Passo 2 "Gerar a configuracao (.env) com segredos proprios"
# =====================================================================
$envPath = Join-Path $RAIZ ".env"
if (Test-Path $envPath) {
    Ok ".env ja existe — mantido (apague-o para gerar de novo)."
} else {
    $pgPass    = Token 24
    $jwt       = Token 48
    $labMail   = Token 18
    $qradarTok = Token 24
    $netscTok  = Token 24
    @"
# ====================================================================
# SHEISA — configuracao gerada por instalar.ps1. NAO versionar.
# ====================================================================
POSTGRES_USER=sheisa
POSTGRES_PASSWORD=$pgPass
POSTGRES_DB=sheisa
POSTGRES_PORT=15433
POSTGRES_TEST_PORT=15434

SHEISA_DATABASE_URL=postgresql+asyncpg://sheisa:$pgPass@127.0.0.1:15433/sheisa
SHEISA_TEST_DATABASE_URL=postgresql+asyncpg://sheisa:sheisa_test@127.0.0.1:15434/sheisa_test

SHEISA_JWT_SECRET=$jwt
SHEISA_ENVIRONMENT=development
SHEISA_CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500
SHEISA_EVIDENCE_STORAGE_PATH=./var/evidence

# Escuta da API: 0.0.0.0 aceita ligacoes da rede local (sensores remotos).
SHEISA_HOST=0.0.0.0

# --- Canal de correio da aplicacao (por omissao aponta ao Mailpit local) ---
SHEISA_SMTP_HOST=127.0.0.1
SHEISA_SMTP_PORT=1025
SHEISA_SMTP_USER=
SHEISA_SMTP_PASSWORD=
SHEISA_SMTP_STARTTLS=false
SHEISA_MAIL_FROM=cert@sheisa.local
SHEISA_MAIL_FROM_NAME=Equipa de Resposta a Incidentes
SHEISA_MAIL_COLLECT_PROTOCOL=POP3
SHEISA_POP3_HOST=127.0.0.1
SHEISA_POP3_PORT=1110
SHEISA_POP3_USER=cert@sheisa.local
SHEISA_POP3_PASSWORD=$labMail
SHEISA_POP3_TLS=false
SHEISA_IMAP_HOST=
SHEISA_IMAP_PORT=993
SHEISA_IMAP_TLS=true
SHEISA_IMAP_MAILBOX=INBOX
SHEISA_MAIL_UI_PORT=8025

# --- Servidor de correio do LABORATORIO (Mailpit), separado do canal acima ---
SHEISA_LAB_MAIL_USER=cert@sheisa.local
SHEISA_LAB_MAIL_PASSWORD=$labMail
SHEISA_LAB_SMTP_PORT=1025
SHEISA_LAB_POP3_PORT=1110

# --- SIEM de pull: simuladores de laboratorio (lab/siem-sim) ---
SHEISA_QRADAR_API_URL=http://127.0.0.1:8110
SHEISA_QRADAR_API_TOKEN=$qradarTok
SHEISA_NETSCOUT_API_URL=http://127.0.0.1:8111
SHEISA_NETSCOUT_API_TOKEN=$netscTok
"@ | Set-Content -Path $envPath -Encoding UTF8
    Ok ".env gerado com segredos proprios."
}

# =====================================================================
Passo 3 "Levantar os servicos de base (Docker)"
# =====================================================================
docker compose up -d --build db db-test mail qradar-sim netscout-sim 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Falhar "Falha ao levantar os contentores." }
Write-Host "  A aguardar a base de dados ficar saudavel..." -ForegroundColor Gray
$dbOk = $false
for ($i = 0; $i -lt 30; $i++) {
    $estado = (docker inspect -f "{{.State.Health.Status}}" sheisa-db 2>$null)
    if ($estado -eq "healthy") { $dbOk = $true; break }
    Start-Sleep 2
}
if ($dbOk) { Ok "Contentores a correr (db, db-test, mail, qradar-sim, netscout-sim)." }
else { Falhar "A base de dados nao ficou saudavel a tempo." }

# =====================================================================
Passo 4 "Preparar o backend (Python, migracoes, dados iniciais)"
# =====================================================================
Set-Location (Join-Path $RAIZ "backend")
$venvPy = Join-Path $RAIZ "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Write-Host "  A criar o ambiente virtual..." -ForegroundColor Gray
    & $py -m venv .venv
}
Write-Host "  A instalar dependencias Python (pode demorar)..." -ForegroundColor Gray
& $venvPy -m pip install --quiet --upgrade pip | Out-Null
& $venvPy -m pip install --quiet -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { Falhar "Falha a instalar as dependencias Python." }
Ok "Dependencias Python instaladas."

Write-Host "  A aplicar migracoes..." -ForegroundColor Gray
& $venvPy -m alembic upgrade head 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Falhar "Falha nas migracoes da base de dados." }
Ok "Base de dados migrada."

Write-Host "  A inicializar permissoes, perfis e conta de administracao..." -ForegroundColor Gray
$saidaInit = & $venvPy -m scripts.manage init 2>&1 | Out-String
$senhaAdmin = $null
if ($saidaInit -match "Palavra-passe:\s*(\S+)") { $senhaAdmin = $Matches[1] }
if ($senhaAdmin) { Ok "Conta de administracao criada." }
else { Aviso "Conta de administracao ja existia (a palavra-passe nao muda)." }

foreach ($semente in @("seed-correlation","seed-playbooks","seed-assets","seed-integrations")) {
    & $venvPy -m scripts.manage $semente 2>&1 | Out-Null
}
Ok "Regras, playbooks, inventario e catalogo de integracoes instalados."

Write-Host "  A carregar o catalogo MITRE ATT&CK (~50 MB, pode demorar)..." -ForegroundColor Gray
& $venvPy -m scripts.manage mitre-load 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Ok "MITRE ATT&CK carregado." }
else { Aviso "Nao foi possivel carregar o MITRE agora (sem rede?). Corra depois: python -m scripts.manage mitre-load" }

# Chave de ingestao para o sensor Suricata nativo.
$chaveSuricata = & $venvPy -m scripts.manage create-api-key --name "Sensor Windows nativo" --kind SURICATA 2>&1 | Out-String
$chaveSur = $null
if ($chaveSuricata -match "Chave:\s*(\S+)") { $chaveSur = $Matches[1] }

# =====================================================================
Passo 5 "Preparar a interface (Node)"
# =====================================================================
Set-Location (Join-Path $RAIZ "frontend")
if (Test-Path (Join-Path $RAIZ "frontend\node_modules")) {
    Ok "Dependencias da interface ja instaladas."
} else {
    Write-Host "  A instalar dependencias da interface (pode demorar)..." -ForegroundColor Gray
    npm install --silent 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Aviso "npm install devolveu erro; verifique com 'npm install' na pasta frontend." }
    else { Ok "Dependencias da interface instaladas." }
}
Set-Location $RAIZ

# =====================================================================
Passo 6 "Instalar o Suricata nativo (captura real de rede)"
# =====================================================================
$suricataExe = "C:\Program Files\Suricata\suricata.exe"
if (Test-Path $suricataExe) {
    Ok "Suricata ja instalado."
} else {
    $msi = Join-Path $env:TEMP "sheisa-suricata-windivert.msi"
    $url = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.17-windivert-1-64bit.msi"
    Write-Host "  A descarregar o Suricata (variante WinDivert)..." -ForegroundColor Gray
    try {
        Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing -TimeoutSec 180
        Write-Host "  A instalar o Suricata..." -ForegroundColor Gray
        Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet" -Wait
        if (Test-Path $suricataExe) { Ok "Suricata instalado (7.0.17, WinDivert)." }
        else { Aviso "O instalador do Suricata correu mas o executavel nao aparece." }
    } catch {
        Aviso "Nao foi possivel descarregar/instalar o Suricata agora: $($_.Exception.Message)"
        Aviso "Ver lab/windows-sensor/README.md para o instalar depois."
    }
}

# Configura o sensor (aponta para a API local) se ainda nao estiver.
$sensorEnv = Join-Path $RAIZ "lab\windows-sensor\sensor.env.ps1"
if ($chaveSur -and -not (Test-Path $sensorEnv)) {
    @"
`$env:SHEISA_HOOK_URL = "http://127.0.0.1:8099/api/ingest/suricata"
`$env:SHEISA_API_KEY = "$chaveSur"
"@ | Set-Content -Path $sensorEnv -Encoding UTF8
    Ok "Sensor Suricata configurado (lab/windows-sensor/sensor.env.ps1)."
}

# Abre a porta 8099 na firewall (ingestao a partir de sensores remotos).
if (-not (Get-NetFirewallRule -DisplayName "SHEISA API (ingestao 8099)" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "SHEISA API (ingestao 8099)" -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort 8099 -Profile Private -ErrorAction SilentlyContinue | Out-Null
    Ok "Porta 8099 aberta na firewall (perfil privado)."
}

# =====================================================================
Passo 7 "Arrancar a plataforma"
# =====================================================================
& (Join-Path $RAIZ "sheisa.ps1") iniciar

# =====================================================================
Write-Host ""
Write-Host "  =====================================================" -ForegroundColor Green
Write-Host "   SHEISA instalada e a correr." -ForegroundColor Green
Write-Host "  =====================================================" -ForegroundColor Green
Write-Host ""
Write-Host "   Interface:    http://127.0.0.1:5500" -ForegroundColor White
Write-Host "   API:          http://127.0.0.1:8099/api/docs" -ForegroundColor White
Write-Host "   Correio lab:  http://127.0.0.1:8025" -ForegroundColor White
Write-Host ""
Write-Host "   Conta:        admin@sheisa.local" -ForegroundColor White
if ($senhaAdmin) {
    Write-Host "   Palavra-passe: $senhaAdmin" -ForegroundColor Yellow
    Write-Host "   (mostrada uma unica vez — guarde-a agora)" -ForegroundColor Gray
} else {
    Write-Host "   Palavra-passe: (a que foi mostrada na primeira instalacao)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "   Gerir a plataforma:  .\sheisa.ps1 iniciar | parar | estado" -ForegroundColor Gray
Write-Host ""
