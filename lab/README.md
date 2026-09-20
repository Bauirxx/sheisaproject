# Laboratório de detecção SHEISA (§26)

Duas camadas de detecção reais, a alimentar a plataforma com sinais que ela não
inventou:

- **Wazuh** — deteta a partir de *registos* (SSH, Apache). Um agente vigia os
  ficheiros de log de um servidor e o gestor aplica-lhe regras.
- **Suricata** — deteta a partir do *tráfego de rede*. Um sensor observa os
  pacotes que chegam ao alvo e aplica-lhes assinaturas (Emerging Threats Open,
  o mesmo conjunto que um SOC usa, mais regras locais do laboratório).

O que o laboratório **não** tem, de propósito: o Wazuh Indexer e o Dashboard. O
Wazuh e o Suricata servem aqui como camada de detecção; quem organiza, investiga
e responde é a SHEISA. Montar os painéis deles ao lado seria pôr duas interfaces
a competir pelo mesmo papel.

```
  VM Kali  ──ataca──►  alvo (nginx)          servidor monitorizado
     │                    │                        │  (logs)
     │              sensor Suricata           agente Wazuh
     │                    │                        │
     │              eve.json                  gestor Wazuh
     │                    │                        │
     │           integrador Suricata          integrador custom-sheisa
     │                    │                        │
     └────────────►  POST /api/ingest/suricata  │  POST /api/ingest/wazuh
                              │                    │
                              └──────► SHEISA ◄────┘
```

---

## Arranque

A plataforma tem de estar de pé primeiro (a criação das chaves fala com a API):

```bash
docker compose up -d db mail
cd backend && ./scripts/api.sh start && cd ..
```

Preparar o laboratório (cria as chaves de ingestão do Wazuh e do Suricata, uma
vez):

```bash
./lab/preparar.sh
```

Arrancar as duas camadas:

```bash
docker compose -f lab/docker-compose.lab.yml --env-file lab/suricata/ingestao.env up -d --build
```

O alvo fica exposto em **`http://<ip-do-anfitrião>:8080`** — é para aqui que a
máquina Kali dispara.

---

## Ligar a máquina Kali

A Kali precisa de alcançar o anfitrião onde o laboratório corre. O mais simples
é pô-la na **mesma rede** que a máquina anfitriã (adaptador *bridged* na VM, não
NAT), e confirmar:

```bash
# na Kali
ping <ip-do-anfitrião>
curl http://<ip-do-anfitrião>:8080/      # deve devolver a página do alvo
```

Com isso, os ataques típicos de um reconhecimento e exploração:

```bash
# na Kali — ALVO=<ip-do-anfitrião>
nmap -sV -T4 --top-ports 1000 $ALVO -p 8080        # scan de portas e serviços
nikto -h http://$ALVO:8080                          # scanner web
gobuster dir -u http://$ALVO:8080 -w /usr/share/wordlists/dirb/common.txt
sqlmap -u "http://$ALVO:8080/api/clientes?id=1" --batch   # injecção SQL
hydra -l admin -P /usr/share/wordlists/rockyou.txt $ALVO http-get /admin -s 8080
curl "http://$ALVO:8080/../../../../etc/passwd"     # path traversal
curl http://$ALVO:8080/.env                         # ficheiro sensível
```

Cada um destes gera tráfego que o Suricata deteta e entrega à plataforma em
segundos. Acompanhe em <http://127.0.0.1:5500/alertas> (filtre pela fonte
Suricata) ou no sensor:

```bash
docker exec sheisa-lab-suricata tail -f /var/log/suricata/fast.log
docker logs -f sheisa-lab-suricata-integrador
```

### Uma limitação a saber, não a esconder (§4)

Quando a Kali ataca `<anfitrião>:8080`, o Docker reencaminha o tráfego para o
contentor-alvo e, nesse reencaminhamento, **substitui o endereço de origem pelo
do gateway do Docker**. As assinaturas disparam à mesma — a detecção é pelo
conteúdo do tráfego, não pelo IP —, mas na plataforma o "atacante" aparecerá
como o gateway (algo como `172.x.0.1`) e não como o IP real da Kali.

Preservar o IP real exige que a Kali e os contentores partilhem a mesma rede de
camada 2, o que em Docker Desktop (Windows/macOS) não é directo. As duas formas
de o conseguir:

- Correr o laboratório num anfitrião **Linux** e ligar a Kali por uma rede
  `macvlan`.
- Correr a Kali **na mesma máquina Linux**, num contentor na rede do laboratório
  (é o que o `atacar-suricata.sh` faz, e por isso preserva o IP).

Para uma demonstração da cadeia de detecção, o NAT não tira nada: o que se mostra
é que um ataque real é detetado e chega à plataforma classificado. Para uma
investigação que dependa do IP de origem exacto, use uma das formas acima.

---

## Sem a Kali à mão: reproduzir os ataques

`atacar-suricata.sh` dispara os mesmos padrões a partir de contentores efémeros
na rede do laboratório — ferramentas reais (nmap, e as cargas de sqlmap/nikto/
hydra), só que partindo de dentro, o que **preserva o IP de origem**. Serve para
demonstrar e verificar a cadeia sem depender de uma VM externa:

```bash
./lab/atacar-suricata.sh reconhecimento   # scan de portas + fingerprint web
./lab/atacar-suricata.sh exploracao        # traversal, SQLi, ficheiros expostos
./lab/atacar-suricata.sh forca-bruta       # tentativas repetidas de acesso
./lab/atacar-suricata.sh tudo
```

---

## A camada Wazuh (registos)

Independente do Suricata. Gera actividade escrevendo linhas nos registos que o
agente vigia — no formato exacto que o `sshd` e o Apache produzem, para que
sejam as regras do Wazuh a decidir o que é alerta:

```bash
./lab/gerar-alertas.sh forca-bruta     # tentativas SSH falhadas
./lab/gerar-alertas.sh acesso-valido   # autenticação bem-sucedida
./lab/gerar-alertas.sh web             # varrimento de um serviço web
./lab/gerar-alertas.sh tudo
```

Uma máquina Kali também pode alimentar o Wazuh, se apontar os ataques a um
serviço cujos registos o agente vigie — mas o caminho natural da Kali é o
Suricata, porque o que ela produz é tráfego de rede.

---

## Desligar

```bash
docker compose -f lab/docker-compose.lab.yml down          # mantém os volumes
docker compose -f lab/docker-compose.lab.yml down -v       # apaga tudo
```

O laboratório pode ser desligado sem afectar a plataforma: são `docker-compose`
separados de propósito.
