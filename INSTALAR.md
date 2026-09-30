# SHEISA — instalação na máquina do cliente

Instruções para pôr a plataforma a funcionar do zero, numa máquina **Windows
10/11**. Há um instalador de um só comando; a via manual fica no fim.

---

## Antes de começar

| Requisito | Porquê |
|---|---|
| Windows 10/11 com **PowerShell** | os scripts de instalação |
| **Ligação à internet** | descarregar dependências, o Suricata e o catálogo MITRE |
| Conta com direitos de **administrador** | o Docker, o Suricata e a firewall exigem-nos |
| ~8 GB de disco livres | Docker, imagens, dependências |
| **Git** instalado | para obter o código (ou copie a pasta do projecto) |

O instalador tenta instalar sozinho o que faltar (Docker Desktop, Python,
Node.js), desde que o Windows tenha o **winget** (vem no Windows 10 1809+ e no
Windows 11). Se não tiver winget, instale primeiro esses três à mão.

---

## Instalação — um só comando

1. Obter o código (ou copiar a pasta do projecto para a máquina):

   ```powershell
   git clone https://github.com/Bauirxx/sheisaproject.git
   cd sheisaproject
   ```

2. Correr o instalador (numa PowerShell — pede elevação de administrador
   sozinho, aceite o pedido do Windows):

   ```powershell
   powershell -ExecutionPolicy Bypass -File instalar.ps1
   ```

O instalador faz tudo por etapas, com o progresso no ecrã:

1. verifica e instala as dependências (Docker, Python, Node);
2. gera a configuração (`.env`) com segredos próprios;
3. levanta a base de dados e os serviços em Docker (inclui os simuladores
   QRadar e NetScout);
4. prepara o backend (Python, migrações, dados iniciais, MITRE ATT&CK) e **liga
   as integrações** — QRadar e NetScout ficam ACTIVA, com alertas importados,
   logo a seguir à instalação;
5. prepara a interface (Node);
6. instala o Suricata nativo (captura real de rede) e abre a porta na firewall;
7. arranca a plataforma.

No fim, mostra os endereços e a **palavra-passe de administração** — que só é
mostrada **uma única vez**. Guarde-a nesse momento.

> **Se instalou o Docker agora, pela primeira vez:** o Windows pode pedir para
> reiniciar. Reinicie, abra o **Docker Desktop** uma vez (espere a baleia ficar
> "Engine running"), e volte a correr `instalar.ps1` — ele retoma de onde parou.

---

## Usar a plataforma

Depois de instalada, abra no navegador:

| | |
|---|---|
| **Interface** | http://127.0.0.1:5500 |
| Documentação da API | http://127.0.0.1:8099/api/docs |
| Portal externo (comunicar sem conta) | http://127.0.0.1:5500/comunicar |
| Caixa de correio do laboratório | http://127.0.0.1:8025 |

Entre com **`admin@sheisa.local`** e a palavra-passe que o instalador mostrou.

### Gerir a plataforma no dia-a-dia

Um só comando controla o sistema inteiro (base de dados, API, interface e
sensor):

```powershell
.\sheisa.ps1 iniciar     # arranca tudo e liga as integracoes (QRadar/NetScout)
.\sheisa.ps1 estado      # mostra o que está a correr
.\sheisa.ps1 parar       # pára a API, a interface e o sensor
.\sheisa.ps1 reiniciar
.\sheisa.ps1 conectar    # (re)liga as integracoes QRadar/NetScout, se preciso
```

O `iniciar` já liga as integrações de importação (QRadar e NetScout) contra os
simuladores — ficam ACTIVA sozinhas. As de envio (Wazuh, Suricata, API genérica)
ligam-se quando começam a mandar eventos: o sensor Suricata é iniciado pelo
próprio `iniciar` (com administrador).

> Para o sensor Suricata arrancar/parar, corra o `sheisa.ps1` **como
> administrador** (o WinDivert exige-o). O resto funciona sem.

---

## Ligar a sistemas externos (opcional)

- **Correio real (Gmail):** ver o bloco Gmail em `.env.example` e a secção do
  correio em [`docs/INTEGRACOES.md`](docs/INTEGRACOES.md).
- **QRadar / NetScout reais:** ver
  [`docs/QRADAR-NETSCOUT-INSTANCIAS-REAIS.md`](docs/QRADAR-NETSCOUT-INSTANCIAS-REAIS.md).
- **Sensores Suricata noutras máquinas:** ver
  [`lab/windows-sensor/`](lab/windows-sensor/) (Windows) e
  [`lab/sensor-remoto/`](lab/sensor-remoto/) (Linux).

---

## Instalação manual (alternativa, ou noutro sistema)

Os passos detalhados, um a um, estão no [`README.md`](README.md), secção
"Arranque rápido → Manual". Usam-se quando o instalador automático não se aplica
(por exemplo, num servidor Linux) ou quando se quer controlar cada passo.

---

## Resolução de problemas

| Sintoma | O que fazer |
|---|---|
| `instalar.ps1` diz que o Docker não arrancou | Reinicie o Windows, abra o Docker Desktop uma vez, volte a correr o instalador. |
| A página não abre (`ERR_CONNECTION_REFUSED`) | `.\sheisa.ps1 estado` para ver o que falta; `.\sheisa.ps1 iniciar` para arrancar. |
| O sensor Suricata não captura | Corra `.\sheisa.ps1 iniciar` **como administrador**. |
| Esqueci a palavra-passe de administração | Reponha-a por outra conta de administração, ou ver `docs/`. Não fica guardada em lado nenhum por desenho. |

O instalador é **idempotente**: volte a correr `instalar.ps1` a qualquer momento
— ele salta o que já está feito e completa o que falta.
