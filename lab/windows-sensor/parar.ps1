# Para o sensor Suricata nativo no Windows + o integrador.
#   .\parar.ps1
#
# Matar o Suricata precisa de Administrador (o processo corre elevado, por
# causa do WinDivert) -- este script relança-se elevado tal como o iniciar.ps1.

$aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $aqui

$actual = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevado = ([Security.Principal.WindowsPrincipal]$actual).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevado) {
    Write-Output "Sem privilegios de administrador -- a relancar elevado..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs -Wait
    exit
}

foreach ($nome in @("suricata.pid", "integrador.pid")) {
    if (Test-Path $nome) {
        $procId = Get-Content $nome
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p) {
            Stop-Process -Id $procId -Force
            Write-Output "parado: PID $procId ($nome)"
        }
        Remove-Item $nome -ErrorAction SilentlyContinue
    }
}
# Rede de segurança: garante que nenhum suricata.exe fica pendurado.
Get-Process -Name suricata -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Output "feito."
