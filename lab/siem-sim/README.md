# Simulador de laboratório — QRadar e NetScout

**Isto não é o IBM QRadar nem o NetScout.** É um servidor que responde nos mesmos
caminhos e formatos das APIs REST desses produtos, para se poder testar os
conectores reais da SHEISA sem uma instância comercial — que não existe neste
ambiente e não se distribui como contentor Docker.

## Porque existe

Os conectores `QRadarConnector` e `NetScoutConnector`
([`backend/app/integrations/siem_connectors.py`](../../backend/app/integrations/siem_connectors.py))
foram escritos contra a documentação pública das APIs, mas nunca puderam ser
confrontados com um servidor a responder. Este simulador é esse servidor. O que
fica exercitado a sério: **conector → normalizador → ingestão → correlação →
alerta**. O que é de laboratório: a origem dos dados.

A fronteira é a rede — o mesmo ponto onde os testes automáticos já usam um duplo
HTTP (`httpx.MockTransport`). A diferença é que aqui é um serviço persistente,
para se importar à mão e ver o resultado na plataforma.

## O que serve

| Vendor | Caminho | Autenticação |
|---|---|---|
| QRadar | `GET /api/system/about` · `GET /api/siem/offenses` | cabeçalho `SEC` = token |
| NetScout | `GET /api/sp/v7/alerts` | cabeçalho `X-Arbux-APIToken` = token |

Um pedido sem token, ou com o token errado, recebe **401** — tal como o produto
real, e é o que torna o `test_connection` uma verificação genuína.

## Como correr

Levantam-se pelo `docker-compose` da raiz, como `qradar-sim` e `netscout-sim`:

```bash
docker compose up -d qradar-sim netscout-sim
```

As variáveis `SHEISA_QRADAR_API_URL/TOKEN` e `SHEISA_NETSCOUT_API_URL/TOKEN` no
`.env` apontam a API para eles. Depois, na plataforma: testar a ligação e
importar (`POST /api/integrations/{id}/import`).

## Honestidade (regra do §4)

Na monografia e na demonstração, estas duas integrações apresentam-se como
**testadas contra um simulador de laboratório da API do fornecedor**, não como
integrações verificadas contra o produto real. Trocar um servidor de laboratório
por instâncias reais é só mudar as quatro variáveis de ambiente — o código dos
conectores não muda.
