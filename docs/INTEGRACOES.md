# SHEISA — Integrações: configurar e testar

As cinco integrações do SHEISA, o que cada uma faz, e **como a pôr a funcionar e
a testar**. O princípio §4 aplica-se: nenhuma aparece como activa sem ter falado
com o serviço, e o que não foi verificado contra um sistema real é dito.

## Panorama

| Integração | Sentido | Verificada | Como entram os dados |
|---|---|---|---|
| **Wazuh** | Envio + resposta | Laboratório real (gestor 4.12.0) | O agente/gestor envia; a plataforma recebe |
| **Suricata** | Envio | Laboratório real | O IDS envia os eventos EVE JSON |
| **API genérica** | Envio | Sim | Qualquer ferramenta faz POST no formato comum |
| **IBM QRadar** | Importação (pull) | Simulador de laboratório da API (`lab/siem-sim`); não contra QRadar real | A plataforma vai buscar as offenses |
| **NetScout** | Importação (pull) | Simulador de laboratório da API (`lab/siem-sim`); não contra NetScout real | A plataforma vai buscar os alertas |

**Envio (push) vs Importação (pull):** Wazuh, Suricata e a API genérica *enviam*
para a plataforma (autenticam-se com uma **chave de ingestão**). O QRadar e o
NetScout são o contrário: a plataforma *vai buscar* (importa) com
`POST /api/integrations/{id}/import` (precisa de token de administração).

> **Simuladores de laboratório (QRadar/NetScout).** Nem o QRadar nem o NetScout se
> distribuem como contentor, e o ambiente não tem instâncias reais. `lab/siem-sim`
> é um servidor que fala a API REST de cada um, levantado pelo `docker-compose`
> como `qradar-sim` (:8110) e `netscout-sim` (:8111). Exercita o código real dos
> conectores (pedido, autenticação, normalização, ingestão); só a origem dos dados
> é de laboratório. **Não** é o produto do fornecedor, e nada aqui o apresenta como
> tal — ver `lab/siem-sim/README.md`.

## Variáveis de ambiente (segredos)

Nunca vão para a base de dados nem para o git — só o **nome** da variável é
guardado. Definir no `.env` (ver `.env.example`).

| Integração | Variáveis |
|---|---|
| Wazuh | `SHEISA_WAZUH_API_URL`, `SHEISA_WAZUH_API_USER`, `SHEISA_WAZUH_API_PASSWORD` |
| QRadar | `SHEISA_QRADAR_API_URL`, `SHEISA_QRADAR_API_TOKEN` |
| NetScout | `SHEISA_NETSCOUT_API_URL`, `SHEISA_NETSCOUT_API_TOKEN` |
| Suricata / API genérica | Nenhuma — usam uma **chave de ingestão** (abaixo) |

---

## 1. Wazuh (envio + resposta activa)

**O que faz.** Recebe alertas do gestor Wazuh, pelo script integrador
(`custom-sheisa`) ou pela API do Wazuh. É bidirecional: a plataforma também pode
pedir acções de resposta ao gestor.

**Configurar e testar a ligação:**

1. Definir `SHEISA_WAZUH_API_URL`, `SHEISA_WAZUH_API_USER`,
   `SHEISA_WAZUH_API_PASSWORD` no `.env`.
2. Reiniciar a API.
3. Testar: `POST /api/integrations/{id}/test` (com token de administração). Só
   fica **ACTIVA** se o gestor responder.

**Testar a recepção de alertas** (laboratório): correr o cenário em
[`lab/README.md`](../lab/README.md). Os alertas chegam a `POST /api/ingest/wazuh`
com a chave de ingestão no cabeçalho `X-API-Key`.

> **Por confirmar:** os comandos de **resposta activa** (isolar activo, varrimento)
> não foram verificados contra um agente Wazuh real e alguns nomes de comando
> parecem errados. Ver a nota em [`docs/CONTINUAR.md`](CONTINUAR.md) (achado 3).
> A ligação e a recepção de alertas estão verificadas; a resposta activa não.

## 2. Suricata (envio)

**O que faz.** Recebe os eventos EVE JSON do IDS Suricata.

**Testar:** correr o laboratório Suricata + Kali de [`lab/README.md`](../lab/README.md).
O integrador lê o `eve.json` e faz `POST /api/ingest/suricata` com a chave de
ingestão. Cadeia comprovada no laboratório (nmap, `/etc/passwd`, etc.).

## 3. API genérica (envio)

**O que faz.** Aceita eventos no **formato interno comum** de qualquer ferramenta,
sem código novo.

**Testar:**

1. Criar uma chave de ingestão:
   `python -m scripts.manage create-api-key --name "teste" --kind API_GENERICA`
   (a chave é mostrada uma única vez).
2. Enviar um evento:
   ```bash
   curl -X POST http://localhost:8099/api/ingest/events \
     -H "X-API-Key: <chave>" -H "Content-Type: application/json" \
     -d '{"id":"t-1","severity":"high","event_type":"teste","description":"evento de teste","source_ip":"203.0.113.10"}'
   ```
3. O evento aparece em `/api/events` e gera um alerta.

## 4. IBM QRadar (importação / pull)

**O que faz.** Vai buscar as *offenses* abertas à API REST do QRadar
(`fetch_offenses`), converte-as para o formato interno e **ingere-as pelo mesmo
pipeline** de qualquer outra fonte. Idempotente por `(fonte, id)`: reimportar não
duplica.

**Configurar e testar a ligação:**

1. As variáveis `SHEISA_QRADAR_API_URL` e `SHEISA_QRADAR_API_TOKEN` já vêm no
   `.env` a apontar para o **simulador de laboratório** (`lab/siem-sim`), que fala
   a API REST real do QRadar. Levante-o: `docker compose up -d qradar-sim`.
2. `POST /api/integrations/{id}/test` — confirma que fala com o QRadar.

**Importar:** `POST /api/integrations/{id}/import?limite=50` (token de
administração). Devolve `{sucesso, importados, duplicados, total}` e os sinais
ficam em `/api/events` / `/api/alerts` com a fonte QRADAR.

> **Estado (verificado a correr, 2026-09-28):** contra o simulador
> (`lab/siem-sim`), o teste de ligação devolveu *"Ligação estabelecida com o
> QRadar 7.5.0…"* e a importação criou 3 alertas; reimportar deu 0 importados / 3
> duplicados (idempotência por `(fonte, id)`). **Não** verificado contra uma
> instância QRadar real — não existe no ambiente, e o QRadar não se distribui como
> contentor. Para verificar de verdade, basta apontar as duas variáveis a um
> QRadar acessível: **o código do conector não muda**.

## 5. NetScout (importação / pull)

**O que faz.** Vai buscar os alertas de tráfego à API REST do NetScout / Arbor
Sightline (`fetch_alerts`) e ingere-os como o QRadar.

**Configurar e testar:** igual ao QRadar, com `SHEISA_NETSCOUT_API_URL` e
`SHEISA_NETSCOUT_API_TOKEN` (já no `.env`, a apontar para o simulador). Levante-o:
`docker compose up -d netscout-sim`. Depois `test` e `import`.

> **Estado (verificado a correr, 2026-09-28):** contra o simulador, o teste
> devolveu *"Ligação estabelecida com o NetScout; 2 alerta(s) acessível(is)"* e a
> importação criou 2 alertas. **Não** verificado contra uma instância NetScout
> real (não existe no ambiente); trocar por uma é só mudar as duas variáveis.

---

## Correr os testes automáticos das integrações

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests/test_integracoes.py -q
```

Cobrem: catálogo, teste de ligação (Wazuh contra as respostas reais do gestor
4.12.0 capturadas no laboratório), e **importação do QRadar e do NetScout** contra
um servidor HTTP simulado — incluindo a idempotência (reimportar não duplica) e a
recusa honesta das fontes de envio (Suricata/Wazuh não se importam).

## O que ainda depende de acesso a sistemas reais

Estas verificações **não podem ser feitas neste ambiente** por faltarem os
sistemas; ficam como instruções para quem os tiver:

1. **QRadar real** — apontar `SHEISA_QRADAR_API_*` a uma instância, testar a
   ligação e importar. Confirmar o mapeamento de magnitude → severidade.
2. **NetScout real** — o mesmo com `SHEISA_NETSCOUT_API_*`.
3. **Resposta activa do Wazuh** — confrontar os comandos (isolar, varrimento)
   com um agente activo; hoje o gestor do laboratório não tem as secções
   `<active-response>` configuradas.
4. **Botão "Importar" na interface** — a rota `/import` existe e está testada; o
   botão no ecrã de integrações é um passo de interface a acrescentar e a
   verificar visualmente.
