# Sensor Suricata na WSL (rede espelhada) — NÃO FUNCIONA, mantido por registo

> **Este caminho não funciona.** Mantido no repositório só para não se repetir
> a tentativa. **Use [`lab/windows-sensor/`](../windows-sensor/) — Suricata
> nativo no Windows via WinDivert — que está verificado a funcionar.**

## O que se tentou

Suricata a correr nativamente dentro do WSL2 (Ubuntu 24.04), com a WSL em modo
de rede espelhado (`networkingMode=mirrored`): a ideia era a WSL passar a ver a
mesma placa de rede física (Wi-Fi) do Windows, com o mesmo IP, e um ataque de
outro dispositivo na rede atravessar essa placa e ser capturado como tráfego
genuíno.

## Porque não funciona

O modo espelhado dá à WSL o **mesmo endereço IP** da placa física — e só isso.
**Não é uma cópia do tráfego ao nível de ligação** (não é um SPAN/porta-espelho
real). Confirmado com três testes independentes, nesta máquina, em
2026-09-29:

1. `tcpdump -i eth4` directo, 8 segundos: **0 pacotes capturados**, mesmo numa
   rede doméstica onde ARP/mDNS/broadcast de outros aparelhos normalmente
   aparece em segundos.
2. Interface posta em modo promíscuo (`ip link set eth4 promisc on`) e
   repetido o teste: **0 pacotes**, na mesma.
3. O teste decisivo: um `curl` de **dentro da própria WSL** para um site
   externo, com `tcpdump` a correr ao mesmo tempo na mesma interface — **0
   pacotes vistos**, apesar do pedido ter tido sucesso (HTTP 200). Se nem o
   próprio tráfego da WSL aparece na interface que supostamente o transporta,
   não há promiscuidade nenhuma a corrigir: a interface não é o caminho real
   dos dados.

Conclusão: `networkingMode=mirrored` resolve conectividade (WSL alcançável
pelo mesmo IP, ligações a sair funcionam), mas não expõe nada a uma ferramenta
de captura bruta (AF_PACKET/libpcap) — nem Suricata, nem `tcpdump`, nem
qualquer IDS. É uma limitação arquitectural da virtualização de rede da WSL2,
não uma questão de configuração.

## O que ficou desta tentativa

Os ficheiros aqui (`suricata.yaml`, `iniciar.sh`, `detectar_interface.sh`,
`suricata-sheisa.py`) são funcionais **enquanto código** — a configuração
carrega, o Suricata arranca sem erro, o integrador liga-se à SHEISA. O que
falta é o próprio tráfego a capturar, e isso não se resolve por aqui.
`detectar_interface.sh` (o nome da interface muda entre arranques em modo
espelhado) e a distinção `af-packet` vs `pcap` continuam correctos e podem
servir de referência para outro ambiente Linux onde a WSL não seja o
obstáculo — ver [`lab/sensor-remoto/`](../sensor-remoto/), pensado
precisamente para uma máquina Linux a sério.

## Reverter o modo de rede espelhado (opcional)

Se não estiver a usar a rede espelhada para mais nada:

```powershell
Remove-Item "$env:UserProfile\.wslconfig"
wsl --shutdown
```

Repare que isto reinicia toda a WSL, incluindo o Docker Desktop (todos os
contentores da SHEISA páram e voltam sozinhos, se tiverem `restart:
unless-stopped`).
