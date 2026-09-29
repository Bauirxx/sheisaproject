# Sensor Suricata nativo no Windows — ataques reais, sem Docker nem WSL

Suricata a correr **directamente no Windows**, sobre a placa de rede física,
via **WinDivert** — sem contentor, sem máquina virtual, sem WSL pelo meio.
Verificado a capturar tráfego real e a disparar alertas reais (2026-09-29):
um pedido HTTP com `User-Agent: sqlmap/1.7.2` foi capturado, gerou o alerta
`SHEISA LOCAL sqlmap detectado pelo User-Agent`, entregue à SHEISA, e o motor
de correlação da própria plataforma criou um incidente sozinho — a cadeia
completa, ponta a ponta, contra tráfego genuíno.

## Como se chegou aqui (dois becos sem saída, para não os repetir)

Antes desta configuração, tentaram-se dois caminhos que pareciam óbvios e
**nenhum funciona nesta plataforma**:

1. **WSL2 com rede espelhada** (`networkingMode=mirrored` no `.wslconfig`).
   Dá à WSL o mesmo IP da placa física, mas **não é uma cópia real do
   tráfego ao nível de ligação** — só dá conectividade. Confirmado com três
   testes independentes: `tcpdump` directo na interface espelhada (0 pacotes
   em 8s), modo promíscuo activado (0 pacotes), e até o **próprio tráfego de
   saída da WSL** (um `curl` de dentro da WSL, 0 pacotes vistos por um
   `tcpdump` a correr ao mesmo tempo). Ver `lab/wsl-sensor/` (mantido para
   referência, não para uso).

2. **Suricata para Windows via Npcap** (captura `-i <interface>`, como no
   Linux). Testado em duas versões — **8.0.7** e **7.0.17** — e **ambas
   crasham** ao abrir qualquer interface, com o mesmo código de erro exacto
   (`0xc0000005` em `msvcrt.dll`, mesmo deslocamento `0x7b7e1`), em qualquer
   interface (Wi-Fi e uma interface virtual, testadas as duas). O facto de
   duas versões diferentes do Suricata crasharem no mesmo ponto do sistema
   aponta para uma incompatibilidade desta instalação Windows (build
   Insider/Canary 26200) com a captura por Npcap — não um defeito do
   Suricata em si.

O que **funciona**: `--windivert true` (modo inline, via Windows Filtering
Platform, não Npcap) na variante **windivert** do instalador, com Suricata
**7.0.17** — a 8.0.7 não foi testada nesta variante. Exige Administrador; sem
isso falha de forma limpa ("must be run with Administrator privileges"), não
com um crash.

## Instalar (uma vez)

1. **Suricata 7.0.17 (variante windivert):**
   `https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.17-windivert-1-64bit.msi`
   — correr o `.msi`, aceitar o UAC. **Não** instalar a variante normal
   (usa Npcap, crasha nesta máquina) nem a 8.0.7 (crasha também).
2. **Não é preciso instalar Npcap** para este modo — o WinDivert traz o seu
   próprio controlador, incluído no instalador do Suricata.
3. **Python** (para o integrador) — qualquer 3.x no `PATH`.
4. Criar a chave de ingestão (na máquina central):
   ```powershell
   cd backend
   .\.venv\Scripts\python.exe -m scripts.manage `
     create-api-key --name "Sensor Windows nativo" --kind SURICATA
   ```
5. `Copy-Item sensor.env.exemplo.ps1 sensor.env.ps1` e colar a chave.

## Arrancar

```powershell
cd lab\windows-sensor
.\iniciar.ps1
```

Pede elevação (UAC) automaticamente se a consola não estiver já como
administrador. Arranca o Suricata (WinDivert, filtro `true` = todo o
tráfego) e o integrador Python, os dois em segundo plano. Escreve
`suricata.pid` e `integrador.pid`.

Para parar: `.\parar.ps1` (também pede elevação — matar o processo do
Suricata precisa dela).

## Verificar que está a funcionar

```powershell
Get-Content log\fast.log -Wait          # alertas, em texto
Get-Content log\integrador.log -Wait    # entregas à SHEISA (HTTP 202)
```

Um pedido de teste inofensivo que dispara uma regra local (prova a cadeia
sem precisar de outra máquina):

```powershell
Invoke-WebRequest -Uri "http://example.com" -UserAgent "Mozilla/5.0 sqlmap/1.7.2" -UseBasicParsing
```

Ou, do lado Linux/WSL/outra máquina: `curl -A "sqlmap/1.7.2" http://example.com`.

## Ataque real, de outro dispositivo

Como o WinDivert intercepta **todo** o tráfego da placa física — de saída e
de **entrada** —, um ataque de outro aparelho na mesma rede contra o IP desta
máquina é capturado tal como qualquer tráfego de saída. Descubra o IP desta
máquina (`ipconfig`, adaptador Wi-Fi) e, de outro telemóvel/PC na mesma rede:

```bash
nmap -sV 192.168.18.116                                    # reconhecimento
hydra -l teste -P wordlist.txt ssh://192.168.18.116         # forca bruta
# DoS controlado -- so em rede propria, por pouco tempo:
sudo hping3 -S --flood -p 445 192.168.18.116
```

Os alertas aparecem em `/api/alerts` e em `/alertas` na interface, fonte
"Sensor Windows nativo (WinDivert)" — e, como se viu no teste de 2026-09-29,
uma sequência de ataques coordenados pode fazer o motor de correlação criar
um incidente sozinho.

## Segurança

- **Falha aberta, não fechada**: se o Suricata cair a meio, o WinDivert deixa
  passar os pacotes sem os bloquear — confirmado (a rede continuou a
  funcionar depois de um crash de teste).
- Precisa de Administrador porque intercepta tráfego ao nível do sistema —
  é esperado, não um sinal de mau funcionamento.
- Filtro `true` = todo o tráfego, incluindo o desta própria máquina para a
  Internet. Para restringir (ex.: só tráfego de/para uma sub-rede), o WinDivert
  aceita filtros no estilo BPF — ver `--help` do Suricata.
- Sem `suricata-update`/ET Open nesta primeira versão: só as regras locais em
  `local.rules` (as mesmas do laboratório Docker). Pode acrescentar-se depois.
