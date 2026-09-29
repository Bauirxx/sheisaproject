# Ligar o SHEISA a QRadar e NetScout reais

Guia de implantação para trocar os simuladores de laboratório (`lab/siem-sim`)
por **instâncias reais**. O código dos conectores já fala a API real de cada
produto — não muda nada no SHEISA além de configuração. O que muda é o outro
lado: pôr o produto de pé e dar-lhe as credenciais.

> **Porque não corre nesta máquina.** O IBM QRadar Community Edition exige **24 GB
> de RAM** e 250 GB de disco ([requisitos IBM](https://www.ibm.com/community/101/qradar/ce/));
> a máquina de desenvolvimento tem 15,7 GB. O NetScout (Arbor Sightline) não tem
> edição comunitária instalável. Por isso este guia é para a **máquina de
> implantação** (24 GB+), não para a de desenvolvimento.

---

## Parte A — IBM QRadar Community Edition

### A.1 Requisitos da máquina de implantação

| Recurso | Mínimo | Recomendado |
|---|---|---|
| RAM | 24 GB (só para a VM do QRadar) | 32 GB no anfitrião |
| Disco | 250 GB livres | SSD |
| CPU | 4 núcleos | 6 núcleos |
| Rede | **IP estático** e um **FQDN** (nome qualificado) | — |

O QRadar CE é uma *appliance* (uma ISO/OVA de RHEL), **não** um contentor. Corre
numa VM — VirtualBox, VMware ou KVM. O VirtualBox já está instalado na máquina de
desenvolvimento; na de implantação, instale-o se não estiver.

### A.2 Descarregar e instalar

1. Criar conta IBM e descarregar o **QRadar CE** (OVA, ~4 GB) de
   <https://www.ibm.com/community/101/qradar/ce/>.
2. Importar o OVA no VirtualBox; atribuir à VM **24 GB de RAM** e 250 GB de
   disco, e uma rede em modo **bridge** (para ter IP próprio na LAN, alcançável
   pela máquina que corre o SHEISA).
3. Arrancar a VM e seguir o instalador (utilizador `root`, define a
   palavra-passe do `admin` da consola web). A primeira instalação demora
   bastante — é normal.
4. Confirmar que a consola web abre em `https://<ip-do-qradar>` (certificado
   auto-assinado; o browser avisa, aceite).

### A.3 Gerar o token de serviço (o que o SHEISA usa)

Na consola web do QRadar: **Admin → User Management → Authorized Services →
Add Authorized Service**. Dar um nome (ex.: `sheisa`), perfil com leitura de
*offenses*, e **copiar o token** (só se vê uma vez). É este o valor de
`SHEISA_QRADAR_API_TOKEN`.

### A.4 Configurar o SHEISA (na máquina que o corre)

No `.env`:

```bash
SHEISA_QRADAR_API_URL=https://<ip-ou-fqdn-do-qradar>
SHEISA_QRADAR_API_TOKEN=<o-token-do-passo-A.3>
```

Reiniciar a API (`./scripts/api.sh restart` — o `api.sh` carrega o `.env`).

O QRadar CE serve com **certificado auto-assinado**, que o SHEISA rejeita por
omissão (e bem — em produção não se aceita um certificado por verificar). Ligar a
aceitação **para esta integração**, via a rota de configuração (token de
administração):

```bash
# ID da integração QRadar:
curl -s http://127.0.0.1:8099/api/integrations -H "Authorization: Bearer $TOKEN" \
  | python -c "import sys,json;print(next(i['id'] for i in json.load(sys.stdin) if i['kind']=='QRADAR'))"

# Aceitar o certificado auto-assinado do QRadar CE:
curl -s -X PATCH http://127.0.0.1:8099/api/integrations/<id>/config \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"permitir_certificado_auto_assinado": true}'
```

> Com um certificado público válido (uma instância a sério, atrás de um
> proxy TLS), **não** ligue esta opção — deixe a verificação estrita.

### A.5 Testar e importar

```bash
curl -s -X POST http://127.0.0.1:8099/api/integrations/<id>/test   -H "Authorization: Bearer $TOKEN"
#   -> "Ligação estabelecida com o QRadar <versão> (build <n>)."
curl -s -X POST http://127.0.0.1:8099/api/integrations/<id>/import -H "Authorization: Bearer $TOKEN"
#   -> importados N offenses; reimportar não duplica (idempotência por (fonte, id)).
```

O que o conector faz, contra a API real (`app/integrations/siem_connectors.py`):
`GET /api/system/about` (cabeçalho `SEC` = token, `Version: 20.0`) para o teste; e
`GET /api/siem/offenses?filter=status=OPEN` (com `Range: items=0-N`) para importar
as *offenses* abertas. São os mesmos caminhos do produto real — o simulador
existe precisamente por os imitar.

---

## Parte B — NetScout (Arbor Sightline)

O NetScout **não tem edição comunitária**: é software comercial de appliance,
sem OVA público. Só há duas formas honestas de o ligar:

1. **Apontar a uma instância real** a que se tenha acesso (uma appliance
   Sightline na organização, ou um ambiente de avaliação cedido pelo fornecedor).
   A configuração é a do QRadar, com as variáveis próprias:
   ```bash
   SHEISA_NETSCOUT_API_URL=https://<host-do-netscout>
   SHEISA_NETSCOUT_API_TOKEN=<api-token-do-sightline>
   ```
   O conector autentica com o cabeçalho `X-Arbux-APIToken` e lê
   `GET /api/sp/v7/alerts` — a API REST v7 do Sightline. Se a appliance usar
   certificado auto-assinado, ligue-o pela rota de configuração (Parte A.4).

2. **Manter o simulador** enquanto não houver instância, deixando **honestamente
   registado** que esta integração foi verificada contra o simulador da API, não
   contra o produto. É o que a monografia deve afirmar até haver acesso real.

---

## O que já está pronto do lado do SHEISA

- Os conectores falam a API real de cada produto (não há caminho "de mentira"
  que devolva sucesso sem resposta do servidor).
- As credenciais vêm de variáveis de ambiente; nunca da base de dados.
- A rota `PATCH /integrations/{id}/config` define o URL base e a aceitação de
  certificado auto-assinado — o único ajuste que uma appliance real exige e que
  o simulador não exigia.
- `test` e `import` funcionam contra qualquer URL: trocar o simulador pela
  instância real é mudar as variáveis de ambiente e (se auto-assinado) ligar a
  opção do certificado. **Nada de código.**

Quando a integração real estiver verificada, actualizar
[`INTEGRACOES.md`](INTEGRACOES.md) e o catálogo (`CONNECTOR_CATALOG` em
`integration_service.py`) para deixar de dizer "verificável contra o simulador" e
passar a "verificada contra instância real", com a data.
