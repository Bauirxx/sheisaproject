# Arranca o sensor Suricata nativo no Windows (WinDivert) + o integrador.
#   .\iniciar.ps1
#
# Precisa de Administrador (o WinDivert recusa abrir sem isso, com um erro
# limpo — "Suricata must be run with Administrator privileges" — não um
# crash). Se não estiver elevado, este script relança-se a si próprio elevado.
#
# Pressupõe: Suricata para Windows instalado (variante windivert), Npcap NÃO é
# necessário para este modo. Ver README.md para a instalação e o porquê desta
# escolha em vez de captura por interface (`-i`).

$ErrorActionPreference = "Stop"
$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $aqui

$actual = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevado = ([Security.Principal.WindowsPrincipal]$actual).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevado) {
    Write-Output "Sem privilegios de administrador -- a relancar elevado..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

if (-not (Test-Path ".\sensor.env.ps1")) {
    Write-Output "ERRO: falta sensor.env.ps1 (copie sensor.env.exemplo.ps1 e preencha)."
    exit 1
}
. .\sensor.env.ps1

$suricataExe = "C:\Program Files\Suricata\suricata.exe"
if (-not (Test-Path $suricataExe)) {
    Write-Output "ERRO: Suricata nao encontrado em $suricataExe. Ver README.md para instalar."
    exit 1
}

New-Item -ItemType Directory -Force -Path ".\log" | Out-Null

Write-Output "A arrancar o Suricata (WinDivert, todo o trafego)..."
$suricata = Start-Process -FilePath $suricataExe `
    -ArgumentList "-c suricata.yaml --windivert true -l `"$aqui\log`"" `
    -PassThru -WindowStyle Hidden
$suricata.Id | Out-File ".\suricata.pid" -Encoding ascii
Start-Sleep -Seconds 3

if (-not (Get-Process -Id $suricata.Id -ErrorAction SilentlyContinue)) {
    Write-Output "ERRO: o Suricata nao arrancou ou caiu logo a seguir."
    Write-Output "Verifique o Visualizador de Eventos (Aplicacao) por APPCRASH, ou log\suricata.log."
    exit 1
}
Write-Output "Suricata a correr, PID $($suricata.Id)."

Write-Output "A arrancar o integrador..."
$env:EVE_PATH = "$aqui\log\eve.json"
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $python) {
    Write-Output "ERRO: Python nao encontrado no PATH. O integrador precisa dele."
    exit 1
}
$integrador = Start-Process -FilePath $python -ArgumentList "`"$aqui\suricata-sheisa.py`"" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$aqui\log\integrador.log" -RedirectStandardError "$aqui\log\integrador-erro.log"
$integrador.Id | Out-File ".\integrador.pid" -Encoding ascii
Start-Sleep -Seconds 1
Write-Output "Integrador a correr, PID $($integrador.Id)."

Write-Output ""
Write-Output "Para acompanhar:"
Write-Output "  Get-Content log\fast.log -Wait"
Write-Output "  Get-Content log\integrador.log -Wait"
Write-Output "Para parar: .\parar.ps1"
