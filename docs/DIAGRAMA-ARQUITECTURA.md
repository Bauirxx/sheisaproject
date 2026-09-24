# SHEISA — Diagrama de Arquitectura (explicação detalhada)

Este documento explica, peça a peça e ligação a ligação, o diagrama de
componentes do SHEISA — a plataforma de gestão e resposta a incidentes
cibernéticos, componente prática da monografia sobre o INCM.

O diagrama é um **diagrama de componentes** (estilo C4): mostra os blocos que
compõem o sistema, as tecnologias de cada um, e como comunicam entre si. Não
mostra ecrãs nem código; mostra a estrutura.

---

## 1. Como ler as cores e as setas

### Cores dos blocos

| Cor | Significado |
|-----|-------------|
| **Azul** | Componentes construídos como parte do SHEISA |
| **Verde** | Bases de dados PostgreSQL |
| **Cinzento** | Sistemas do laboratório, externos ao SHEISA (ferramentas de segurança e o alvo) |
| **Amarelo** | Uma pessoa (actor): o Analista |

### As setas (relações)

Cada seta tem um verbo que diz o **sentido** e a **natureza** da comunicação:

- **Uses / Usa** — uma pessoa interage com um sistema.
- **Consumes / Consome** — um componente chama outro para obter dados ou serviços.
- **Reads / Lê** — vai buscar dados a uma fonte, sem os alterar.
- **Sends / Envia** — empurra dados para outro componente.
- **Manages / Gere** — controla ou configura outro sistema.
- **Receives / Recebe** — recolhe dados que lhe chegam de outro.
- **Monitors / Monitoriza** — vigia continuamente um alvo.

O sentido da seta importa: quem **inicia** a comunicação é o lado de onde a seta
parte.

---

## 2. Os blocos, um a um

### 2.1 Analista *(amarelo — pessoa)*

O utilizador final: um analista de segurança do SOC/CSIRT. É quem faz a triagem
dos alertas, decide o que é incidente, conduz a resposta e encerra os casos.
Todo o sistema existe para o servir.

### 2.2 SHEISA Frontend *(azul)*

A interface. Uma **aplicação de página única (SPA)** feita em React + TypeScript,
servida pelo Vite. É só apresentação e interação: não tem base de dados nem
lógica de negócio própria — tudo o que mostra vem da API. Está inteiramente em
português.

### 2.3 SHEISA API *(azul) — o centro de tudo*

O coração da plataforma. Uma **API REST** em FastAPI (Python) que concentra toda
a lógica de negócio: autenticação e permissões, ingestão de alertas, triagem,
correlação, gestão de incidentes, evidências, playbooks, recomendações,
auditoria e comunicações. **Todos os outros componentes falam com a API, ou a
API fala com eles.** É o único ponto que escreve na base de dados principal.

### 2.4 SHEISA Database *(verde)*

A base de dados principal, **PostgreSQL 16**. Guarda tudo o que é permanente:
eventos, alertas, incidentes, observações, indicadores de compromisso (IOC),
evidências, utilizadores, registo de auditoria (imutável, só de acréscimo), etc.

### 2.5 SHEISA Test Database *(verde)*

Uma base de dados PostgreSQL **efémera e separada**, usada exclusivamente para
correr a bateria de testes automáticos. Não guarda nada de produção: existe para
que os testes não toquem nos dados reais. Aparece no diagrama para deixar claro
que testes e produção estão isolados.

### 2.6 SHEISA Mailpit *(azul) — servidor de email*

O servidor de email. No diagrama aparece o **Mailpit**, que é a versão de
**desenvolvimento** (permite ver e testar emails enviados e recebidos sem tocar
em correio real). A API envia por aqui as notificações e recolhe por aqui as
comunicações externas (o portal de participação de incidentes, ao estilo do
RTIR).

> **Nota de honestidade (princípio do projecto).** O Mailpit é apenas de
> desenvolvimento. Em produção, o email é um servidor real (Gmail). O diagrama
> mostra o ambiente de desenvolvimento — não se deve apresentar o Mailpit como a
> solução final de produção.

### 2.7 Suricata Sensor *(cinzento — laboratório)*

Um **IDS (sistema de deteção de intrusões) de rede**: o Suricata. Fica na
fronteira da rede do laboratório e inspeciona o tráfego que passa. Quando vê algo
que corresponde a uma regra (por exemplo, um varrimento nmap ou uma tentativa de
ler `/etc/passwd`), gera um alerta. É uma ferramenta externa — o SHEISA não a
construiu, integra-a.

### 2.8 Suricata Integrator *(azul)*

O **elo de ligação** entre o Suricata e o SHEISA: um script Python. Lê os alertas
que o Suricata escreve (ficheiro `eve.json`), traduz cada um para o formato que a
API entende, e envia-os. É este componente que torna o Suricata "compreensível"
para a plataforma.

### 2.9 Wazuh Manager *(cinzento — laboratório)*

O **gestor do Wazuh**, uma solução de monitorização de segurança baseada em
agentes. Enquanto o Suricata vê a **rede**, o Wazuh vê o que se passa **dentro**
das máquinas. O gestor centraliza o que os agentes reportam. A API integra-se com
ele.

### 2.10 Wazuh Agent *(cinzento — laboratório)*

O **agente do Wazuh** instalado no servidor-alvo. Vigia o sistema por dentro:
ficheiros alterados, processos, logins, comandos. Reporta ao Wazuh Manager.

### 2.11 Lab Target Web Server *(cinzento — a "vítima")*

Um **servidor web Nginx** que serve de **alvo dos ataques** no laboratório. É a
máquina que se ataca (a partir de uma máquina Kali) para gerar deteções reais.
Está a ser vigiada em simultâneo pelo Suricata (por fora, na rede) e pelo Wazuh
(por dentro, pelo agente).

---

## 3. As ligações, uma a uma

Seguindo as setas do diagrama:

1. **Analista → *Uses* → Frontend.**
   O analista abre e usa a interface no navegador.

2. **Frontend → *Consumes* → API.**
   A interface não tem dados próprios: pede tudo à API por HTTP. Cada ecrã
   corresponde a uma ou mais chamadas à API.

3. **API → *Reads* → SHEISA Database.**
   A API lê (e escreve) os dados permanentes na base de dados principal.

4. **API → *Sends* → Mailpit.**
   A API envia emails (notificações, avisos de recepção de comunicações) através
   do servidor de email.

5. **API → *Manages* → Wazuh Manager.**
   A API integra-se com o Wazuh — consulta e coordena a monitorização.

6. **Wazuh Manager → *Receives* → (do) Wazuh Agent.**
   O gestor recebe do agente o que este observa dentro do servidor-alvo.

7. **Wazuh Agent → *Monitors* → Lab Target Web Server.**
   O agente vigia o alvo por dentro.

8. **Suricata Integrator → *Reads* → Suricata Sensor.**
   O integrador lê os alertas produzidos pelo sensor Suricata.

9. **Suricata Integrator → *Sends* → API.**
   Depois de traduzir os alertas, o integrador envia-os para a API (endpoint de
   ingestão).

10. **Suricata Sensor → *Monitors* → Lab Target Web Server.**
    O sensor vigia o mesmo alvo, mas pela rede.

---

## 4. As duas fontes de deteção (o ponto-chave)

O laboratório vigia o **mesmo alvo por dois caminhos independentes e paralelos**.
Isto é intencional e é o que dá robustez à demonstração:

- **Caminho de rede (Suricata):**
  `Alvo → Suricata Sensor → Suricata Integrator → API`
  Deteta ataques pelo tráfego (varrimentos, exploração, pedidos maliciosos).

- **Caminho de sistema (Wazuh):**
  `Alvo → Wazuh Agent → Wazuh Manager → API`
  Deteta ataques pelo que acontece dentro da máquina (ficheiros, processos,
  acessos).

Um mesmo ataque pode ser visto pelos dois em simultâneo — o que aproxima o
laboratório de um SOC real, onde os alertas chegam de múltiplas ferramentas e
precisam de ser correlacionados.

---

## 5. O fluxo completo, de ponta a ponta

Juntando tudo, é assim que um ataque percorre o sistema:

> **1.** Uma máquina Kali ataca o **Servidor-Alvo**.
> **2.** O **Suricata** (rede) e o **Wazuh** (sistema) detetam o ataque.
> **3.** Os **integradores** traduzem os alertas para o formato do SHEISA.
> **4.** A **API** recebe os alertas, guarda-os na **base de dados** e aplica
> triagem e correlação.
> **5.** O **Analista** vê os alertas no **Frontend**, decide o que é incidente,
> conduz a resposta e encerra o caso.
> **6.** Ao longo do processo, a API envia **emails** de notificação e pode
> receber comunicações externas de incidentes.

Tudo isto sem dados fabricados: os alertas vêm de ataques reais, detetados por
ferramentas reais, e passam por caminhos reais até ao analista.
