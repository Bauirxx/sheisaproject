# =====================================================================
#  SHEISA — orquestrador da plataforma (Windows)
#
#  Um so comando para gerir o sistema inteiro: base de dados, API,
#  interface e sensor Suricata.
#
#    .\sheisa.ps1 iniciar    arranca tudo e liga as integracoes
#    .\sheisa.ps1 parar      para a API, a interface e o sensor
#    .\sheisa.ps1 estado     mostra o que esta a correr
#    .\sheisa.ps1 reiniciar  para e volta a arrancar
#    .\sheisa.ps1 conectar   liga QRadar/NetScout (testa e importa)
#
#  (A instalacao de raiz e feita uma vez por instalar.ps1.)
# =====================================================================

param(
    [Parameter(Position = 0)]
    [ValidateSet("iniciar", "parar", "estado", "reiniciar", "conectar")]
    [string]$accao = "estado"
)

# "Continue" e nao "Stop": comandos nativos (docker, npm) escrevem progresso no
# stderr como rotina, e com "Stop" o PowerShell trataria isso como erro fatal e
# abortaria o arranque. As falhas reais sao apanhadas por $LASTEXITCODE e por
# try/catch nos pontos que importam.
$ErrorActionPreference = "Continue"
$RAIZ = Split-Path -Parent $MyInvocation.MyCommand.Path
$PORTA_API = 8099
$PORTA_UI  = 5500
$runDir = Join-Path $RAIZ "var\run"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

# O sensor Suricata (WinDivert) so arranca/para com administrador. O resto da
# plataforma nao precisa. Detecta-se aqui para nunca pendurar num pedido de
# elevacao (UAC) que uma sessao nao-interactiva nao consegue responder.
$souAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Ok($t)    { Write-Host "  OK  $t" -ForegroundColor Green }
function Info($t)  { Write-Host "  ..  $t" -ForegroundColor Gray }
function Aviso($t) { Write-Host "  !!  $t" -ForegroundColor Yellow }

# Carrega o .env da raiz para o AMBIENTE do processo. E preciso porque os
# conectores das integracoes leem os segredos de os.environ (o pydantic so le do
# .env os campos que declara). Le linha a linha, tomando tudo apos o primeiro
# '=' como valor -- valores com espacos nao sao reinterpretados.
function CarregarEnv {
    $envPath = Join-Path $RAIZ ".env"
    if (-not (Test-Path $envPath)) { return }
    foreach ($linha in Get-Content $envPath) {
        $l = $linha.Trim()
        if ($l -eq "" -or $l.StartsWith("#")) { continue }
        $i = $l.IndexOf("=")
        if ($i -lt 1) { continue }
        $chave = $l.Substring(0, $i).Trim()
        $valor = $l.Substring($i + 1)
        Set-Item -Path "env:$chave" -Value $valor
    }
}

function ProcessoNaPorta($porta) {
    $c = Get-NetTCPConnection -LocalPort $porta -State Listen -ErrorAction SilentlyContinue
    if ($c) { return ($c | Select-Object -ExpandProperty OwningProcess -Unique) }
    return $null
}

function PararPorta($porta, $nome) {
    $procs = ProcessoNaPorta $porta
    if ($procs) {
        foreach ($p in $procs) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
        Ok "$nome parado (porta $porta)."
    } else {
        Info "$nome ja estava parado."
    }
}

# ------------------------------------------------------------------ arrancar
function Iniciar {
    Write-Host ""
    Write-Host "  A arrancar a SHEISA..." -ForegroundColor Cyan

    # 1. Contentores de base.
    Info "Contentores (base de dados, correio, simuladores)..."
    docker compose -f (Join-Path $RAIZ "docker-compose.yml") up -d db db-test mail qradar-sim netscout-sim 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "Contentores a correr." }
    else { Aviso "Docker nao respondeu — o motor esta a correr? (Docker Desktop aberto?)" }

    # 2. API (uvicorn), com o .env carregado no ambiente.
    if (ProcessoNaPorta $PORTA_API) {
        Ok "API ja estava a correr (porta $PORTA_API)."
    } else {
        CarregarEnv
        $host_ = if ($env:SHEISA_HOST) { $env:SHEISA_HOST } else { "127.0.0.1" }
        $venvPy = Join-Path $RAIZ "backend\.venv\Scripts\python.exe"
        $logApi = Join-Path $runDir "api.log"
        $p = Start-Process -FilePath $venvPy `
            -ArgumentList "-m uvicorn app.main:app --host $host_ --port $PORTA_API --log-level warning" `
            -WorkingDirectory (Join-Path $RAIZ "backend") `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $logApi -RedirectStandardError (Join-Path $runDir "api.err.log")
        $p.Id | Out-File (Join-Path $runDir "api.pid") -Encoding ascii
        $subiu = $false
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep 1
            try {
                if ((Invoke-WebRequest "http://127.0.0.1:$PORTA_API/api/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) {
                    $subiu = $true; break
                }
            } catch {}
        }
        if ($subiu) { Ok "API operacional em http://127.0.0.1:$PORTA_API" }
        else { Aviso "A API nao respondeu a tempo. Ver $logApi" }
    }

    # 3. Interface (Vite).
    if (ProcessoNaPorta $PORTA_UI) {
        Ok "Interface ja estava a correr (porta $PORTA_UI)."
    } else {
        $logUi = Join-Path $runDir "interface.log"
        $npmCmd = (Get-Command npm.cmd -ErrorAction SilentlyContinue).Source
        if (-not $npmCmd) { $npmCmd = "npm" }
        $p = Start-Process -FilePath $npmCmd -ArgumentList "run dev" `
            -WorkingDirectory (Join-Path $RAIZ "frontend") `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $logUi -RedirectStandardError (Join-Path $runDir "interface.err.log")
        $p.Id | Out-File (Join-Path $runDir "interface.pid") -Encoding ascii
        Start-Sleep 3
        if (ProcessoNaPorta $PORTA_UI) { Ok "Interface em http://127.0.0.1:$PORTA_UI" }
        else { Info "Interface a arrancar (pode demorar alguns segundos)..." }
    }

    # 4. Sensor Suricata (se instalado e configurado). Opcional; nao falha o
    #    arranque se faltar. So se toca com administrador (exigencia do WinDivert).
    $sensor = Join-Path $RAIZ "lab\windows-sensor\iniciar.ps1"
    $sensorEnv = Join-Path $RAIZ "lab\windows-sensor\sensor.env.ps1"
    $temSensor = (Test-Path $sensor) -and (Test-Path $sensorEnv) -and (Test-Path "C:\Program Files\Suricata\suricata.exe")
    if ($temSensor -and (Get-Process -Name suricata -ErrorAction SilentlyContinue)) {
        Ok "Sensor Suricata ja estava a capturar."
    } elseif ($temSensor -and $souAdmin) {
        # Ja somos administrador: o iniciar.ps1 nao volta a pedir elevacao.
        & $sensor 2>&1 | Out-Null
        if (Get-Process -Name suricata -ErrorAction SilentlyContinue) {
            Ok "Sensor Suricata iniciado (captura de rede real)."
        }
    } elseif ($temSensor) {
        Info "Sensor Suricata por arrancar: corra '.\sheisa.ps1 iniciar' como administrador."
    } else {
        Info "Sensor Suricata nao configurado (opcional) — ver lab/windows-sensor/."
    }

    # 5. Ligar as integracoes de pull (QRadar, NetScout) contra os simuladores.
    if (ProcessoNaPorta $PORTA_API) { Conectar }
    Write-Host ""
}

# ---------------------------------------------------- ligar integracoes de pull
function Conectar {
    Info "A ligar as integracoes (QRadar, NetScout)..."
    $venvPy = Join-Path $RAIZ "backend\.venv\Scripts\python.exe"
    if (-not (Test-Path $venvPy)) { Info "Backend nao instalado — corra instalar.ps1."; return }
    Push-Location (Join-Path $RAIZ "backend")
    try {
        & $venvPy -m scripts.manage conectar-integracoes 2>&1 | ForEach-Object {
            if ($_ -match "OK|--") { Write-Host "    $_" -ForegroundColor DarkGray }
        }
        Ok "Integracoes de importacao ligadas (QRadar, NetScout ACTIVA)."
    } finally { Pop-Location }
}

# --------------------------------------------------------------------- parar
function Parar {
    Write-Host ""
    Write-Host "  A parar a SHEISA..." -ForegroundColor Cyan
    if (Get-Process -Name suricata -ErrorAction SilentlyContinue) {
        if ($souAdmin) {
            Get-Process -Name suricata -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Ok "Sensor Suricata parado."
        } else {
            Aviso "Sensor Suricata a correr, mas parar precisa de administrador."
        }
    }
    PararPorta $PORTA_UI  "Interface"
    PararPorta $PORTA_API "API"
    Info "Os contentores (Docker) continuam a correr. Para os parar: docker compose stop"
    Write-Host ""
}

# -------------------------------------------------------------------- estado
function Estado {
    Write-Host ""
    Write-Host "  Estado da SHEISA" -ForegroundColor Cyan
    # Docker.
    $cont = docker ps --filter "name=sheisa-" --format "{{.Names}}" 2>$null
    if ($cont) { Ok ("Contentores: " + (($cont -split "`n" | Where-Object { $_ }) -join ", ")) }
    else { Aviso "Sem contentores a correr (Docker parado?)." }
    # API.
    try {
        $h = Invoke-WebRequest "http://127.0.0.1:$PORTA_API/api/health" -UseBasicParsing -TimeoutSec 3
        if ($h.StatusCode -eq 200) { Ok "API a responder em http://127.0.0.1:$PORTA_API" }
    } catch { Aviso "API nao responde (porta $PORTA_API)." }
    # Interface.
    if (ProcessoNaPorta $PORTA_UI) { Ok "Interface a correr em http://127.0.0.1:$PORTA_UI" }
    else { Aviso "Interface nao esta a correr (porta $PORTA_UI)." }
    # Suricata.
    if (Get-Process -Name suricata -ErrorAction SilentlyContinue) { Ok "Sensor Suricata a capturar." }
    else { Info "Sensor Suricata nao esta a correr (opcional)." }
    Write-Host ""
}

switch ($accao) {
    "iniciar"   { Iniciar }
    "parar"     { Parar }
    "reiniciar" { Parar; Iniciar }
    "estado"    { Estado }
    "conectar"  { Conectar }
}
