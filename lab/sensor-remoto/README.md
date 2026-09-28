# Sensor Suricata remoto — noutra máquina, a reportar a esta SHEISA

Este pacote põe um sensor **Suricata** noutro computador a observar o **tráfego de
rede real** dessa máquina e a entregar os alertas à plataforma SHEISA que corre na
máquina central (`192.168.18.116`). Serve para testes reais: um ataque de força
bruta ou DoS visto por um IDS a sério, não injectado à mão.

É o mesmo Suricata e o mesmo integrador do laboratório local
(`lab/docker-compose.lab.yml`); a diferença é a rede — aqui o sensor vê a interface
física do anfitrião, e o integrador entrega pela rede local.

## O que é preciso na máquina central (já feito nesta instalação)

1. A API a escutar na rede: `SHEISA_HOST=0.0.0.0` no `.env` (já está). Confirme
   com `netstat -ano | findstr :8099` — deve mostrar `0.0.0.0:8099`.
2. A porta 8099 aberta na firewall do Windows (regra a criar como administrador —
   ver a secção no fim).
3. Uma chave de ingestão do tipo `SURICATA` por sensor. O `sensor.env` deste
   pacote já traz uma criada. Para outra máquina, gere outra na central:
   `cd backend && ./.venv/Scripts/python.exe -m scripts.manage create-api-key --name "Sensor X" --kind SURICATA`

## Requisito importante (honesto)

O sensor em contentor só vê a interface física num anfitrião **Linux**
(`network_mode: host` + `NET_ADMIN`). No **Windows/macOS** o Docker corre dentro
de uma VM e um contentor **não** vê a placa de rede física — o mesmo motivo que
obrigou o laboratório local ao truque da rede partilhada. Nessas máquinas, instale
o Suricata **nativamente** (secção "Sem Docker" abaixo).

## Correr (anfitrião Linux, com Docker)

1. Copie esta pasta inteira (`lab/sensor-remoto/`) para a outra máquina.
2. Descubra o nome da interface a vigiar: `ip -o link show` (ex.: `eth0`,
   `ens33`, `enp0s3`). Ponha-o em `sensor.env` (`SURICATA_IFACE=`).
3. Confirme no `sensor.env` o `SHEISA_HOOK_URL` (o IP da máquina central) e a
   `SHEISA_API_KEY`. Se copiou o `sensor.env` deste pacote, já vêm preenchidos;
   senão, copie `sensor.env.exemplo` para `sensor.env` e preencha.
4. Suba: `docker compose up -d --build`
5. Veja o sensor a carregar as regras e o integrador a ligar:
   `docker compose logs -f`

## Provocar e verificar um ataque real

Numa terceira máquina (ou nesta), contra a máquina do sensor:

```bash
# Varrimento / reconhecimento
nmap -sV -p- <ip-da-maquina-do-sensor>

# Força bruta SSH (exemplo com hydra; use uma conta de teste sua)
hydra -l teste -P /usr/share/wordlists/rockyou.txt ssh://<ip-da-maquina-do-sensor>

# Inundação DoS (exemplo com hping3 — use só em rede sua)
sudo hping3 -S --flood -p 80 <ip-da-maquina-do-sensor>
```

Depois:
* no sensor: `docker compose logs integrador` mostra `N alerta(s) entregue(s)
  (HTTP 202, ...)`;
* na SHEISA: os alertas aparecem em `/api/alerts` e na interface (`/alertas`),
  com a fonte Suricata. A força bruta dispara regras ET SCAN / brute force; o
  varrimento dispara regras de recon; o DoS dispara regras de inundação.

## Sem Docker (Windows/macOS, ou Linux sem Docker)

Instale o Suricata nativo (site oficial ou gestor de pacotes), aponte-o à sua
interface, e use os ficheiros deste pacote: `suricata.yaml`, `local.rules`, e o
integrador `suricata-sheisa.py` (precisa de Python 3). Defina as variáveis
`SHEISA_HOOK_URL`, `SHEISA_API_KEY` e `EVE_PATH` (o caminho do `eve.json` que o
seu Suricata escreve) e corra `python3 suricata-sheisa.py`.

## Abrir a porta 8099 na firewall da máquina central (uma vez, como admin)

Numa PowerShell **como administrador**, na máquina que corre a SHEISA:

```powershell
New-NetFirewallRule -DisplayName "SHEISA API (ingestao 8099)" `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8099 -Profile Private
```

`-Profile Private` limita à rede classificada como privada (a sua rede local);
não abre à internet. Para remover depois:
`Remove-NetFirewallRule -DisplayName "SHEISA API (ingestao 8099)"`.

## Segurança (não esquecer)

É um servidor de desenvolvimento, sem TLS e com credenciais de laboratório. Isto
destina-se a uma rede de confiança para a demonstração da monografia — **nunca**
exponha a porta 8099 à internet. Cada sensor tem a sua chave; para desligar um
sensor, revogue a chave dele na plataforma.
