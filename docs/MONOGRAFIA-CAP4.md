# Capítulo IV — Concepção e desenvolvimento do protótipo

> **Transcrição do capítulo da monografia**, versionada em 2026-09-15.
>
> É o documento académico: descreve o protótipo tal como vai ser defendido.
> Onde a plataforma construída for além do que aqui está — e vai, em vários
> pontos — o excesso é evolução, não contradição. Ver `docs/BRIEFING.md` para a
> especificação técnica alargada, e `docs/ESTADO.md` para o estado do código.
>
> **§4.14 é o cenário de demonstração** e é a secção que governa
> `app/services/demo_service.py`.

---

## 4.1 Introdução

Neste capítulo é apresentada a componente prática do trabalho, correspondente à
concepção de um protótipo de uma ferramenta digital para gestão de incidentes
cibernéticos no Instituto Nacional das Comunicações de Moçambique (INCM),
baseada nos princípios do *Request Tracker for Incident Response* (RTIR).

A proposta surge da necessidade de melhorar a organização, centralização,
acompanhamento e documentação dos incidentes de segurança da informação. O
protótipo foi concebido considerando o ambiente tecnológico existente no INCM e
a utilização de ferramentas de monitorização e detecção, nomeadamente o IBM
QRadar, NetScout e Suricata.

A ferramenta proposta não pretende substituir as soluções de monitorização
existentes, mas funcionar como uma **plataforma central de gestão e
acompanhamento dos incidentes**, permitindo transformar os alertas gerados pelas
ferramentas de segurança em processos organizados de resposta a incidentes.

## 4.2 Situação actual

Com base nas informações obtidas durante o estudo de caso, verificou-se que o
INCM dispõe de ferramentas destinadas à monitorização e detecção de eventos de
segurança, como **QRadar, NetScout e Suricata**.

Entretanto, foi identificada a necessidade de uma solução estruturada
especificamente para a **gestão do ciclo de vida dos incidentes**, incluindo o
registo, classificação, atribuição, acompanhamento, resolução e documentação dos
incidentes.

Um dos aspectos identificados durante a recolha de informações foi a
**inexistência de uma plataforma RTIR implementada no ambiente estudado**. Desta
forma, o protótipo proposto procura responder a essa lacuna através da concepção
de uma plataforma inspirada no modelo RTIR e adaptada às necessidades
identificadas no INCM.

> **Importante.** Como algumas informações do INCM não foram disponibilizadas, o
> trabalho deve distinguir claramente entre **informações obtidas durante a
> entrevista** e **funcionalidades propostas no protótipo**. Não apresentar
> funcionalidades propostas como se já existissem no INCM.

## 4.3 Proposta da solução

A solução proposta consiste numa **ferramenta digital de gestão de incidentes
cibernéticos**, inspirada no funcionamento do RTIR.

O sistema terá como principal finalidade **centralizar e organizar o processo de
resposta aos incidentes de segurança**, desde a identificação do evento até ao
encerramento do incidente.

A solução poderá receber informações provenientes das ferramentas de segurança
existentes:

- **QRadar** — correlação e análise de eventos de segurança;
- **NetScout** — monitorização e análise do tráfego de rede;
- **Suricata** — detecção de actividades suspeitas e possíveis intrusões;
- **Utilizador/analista** — registo manual de incidentes.

Essas informações serão encaminhadas para a plataforma, onde poderão ser
transformadas em **tickets de incidentes**.

## 4.4 O que o sistema faz

```
Detecção → Registo → Classificação → Priorização → Atribuição →
Investigação → Resposta → Resolução → Encerramento → Relatório
```

**Exemplo.** O Suricata detecta uma actividade suspeita. A informação chega à
plataforma e o sistema cria um incidente:

```
INC-000125 — Possível tentativa de intrusão
```

O analista recebe o incidente e verifica: origem do alerta; endereço IP; data e
hora; tipo de ameaça; activo afectado; ferramenta que gerou o alerta; nível de
severidade.

Depois, classifica o incidente, por exemplo:

```
Categoria:   Intrusão
Severidade:  Alta
Prioridade:  Alta
Estado:      Aberto
Responsável: Analista SOC
```

Durante a investigação, o analista pode adicionar comentários, evidências e
acções realizadas. Depois de resolver o problema, altera o estado para
**Resolvido** e posteriormente **Encerrado**. Todo o histórico permanece
registado na plataforma.

## 4.5 Principais módulos do sistema

1. **Autenticação e controlo de acesso** — acesso por credenciais, com perfis:
   Administrador, Analista de segurança, Gestor, Operador.
2. **Dashboard** — total de incidentes, novos, em investigação, críticos,
   resolvidos, encerrados, por categoria e por severidade.
3. **Gestão de incidentes** (módulo principal) — criar, visualizar, editar,
   classificar, atribuir responsável, alterar prioridade, alterar estado,
   adicionar comentários, anexar evidências, acompanhar histórico, resolver e
   encerrar.
4. **Gestão de alertas** — recebe ou regista os alertas das ferramentas de
   segurança; o analista pode converter o alerta num incidente.
5. **Gestão de utilizadores** — criar, alterar, desactivar, atribuir perfis,
   definir permissões.
6. **Gestão de evidências** — ficheiros de log, capturas de ecrã, relatórios,
   informações sobre IP, eventos de segurança.
7. **Histórico/auditoria** — regista as operações realizadas pelos
   utilizadores, para saber **quem fez o quê e quando**.
8. **Relatórios** — incidentes por período, severidade, categoria e origem;
   tempo médio de resolução; resolvidos; pendentes.

Exemplo de dashboard:

| Indicador        | Quantidade |
|------------------|------------|
| Incidentes novos | 12         |
| Em investigação  | 8          |
| Alta severidade  | 5          |
| Críticos         | 2          |
| Resolvidos       | 15         |
| Encerrados       | 30         |

Exemplo de alerta:

```
Fonte:      Suricata
Tipo:       Intrusion Detection
IP origem:  192.168.X.X
IP destino: 192.168.X.X
Data:       08/09/2026
Severidade: Alta
```

Exemplo de histórico:

```
14:30 — Incidente criado
14:35 — Incidente atribuído ao Analista X
15:10 — Severidade alterada para Alta
16:20 — Evidência adicionada
17:00 — Incidente resolvido
```

## 4.6 Fluxo de funcionamento

```
              FERRAMENTAS DE SEGURANÇA
        ┌──────────────┼──────────────┐
     QRadar        NetScout        Suricata
        └──────────────┼──────────────┘
                       ▼
            ┌─────────────────┐
            │   Plataforma    │
            │   de Gestão de  │
            │   Incidentes    │
            └────────┬────────┘
                     ▼
                  REGISTO
                     ▼
               CLASSIFICAÇÃO
                     ▼
                PRIORIZAÇÃO
                     ▼
                 ATRIBUIÇÃO
                     ▼
                INVESTIGAÇÃO
                     ▼
                  RESPOSTA
                     ▼
                 RESOLUÇÃO
                     ▼
                ENCERRAMENTO
                     ▼
                  RELATÓRIO
```

## 4.7 Requisitos funcionais

| ID | Requisito | Descrição |
|---|---|---|
| RF01 | Autenticar utilizadores | O sistema deve permitir o acesso através de credenciais. |
| RF02 | Gerir utilizadores | O administrador deve poder criar, editar e desactivar utilizadores. |
| RF03 | Gerir perfis | O sistema deve permitir definir diferentes níveis de acesso. |
| RF04 | Registar incidentes | O sistema deve permitir o registo manual de incidentes. |
| RF05 | Receber alertas | O sistema deve permitir o recebimento/registo de alertas provenientes das ferramentas de segurança. |
| RF06 | Criar tickets | O sistema deve criar um ticket para cada incidente registado. |
| RF07 | Classificar incidentes | O sistema deve permitir classificar os incidentes por categoria. |
| RF08 | Definir severidade | O sistema deve permitir definir a severidade do incidente. |
| RF09 | Definir prioridade | O sistema deve permitir estabelecer a prioridade do incidente. |
| RF10 | Atribuir incidentes | O sistema deve permitir atribuir um incidente a um analista responsável. |
| RF11 | Alterar estado | O sistema deve permitir alterar o estado do incidente. |
| RF12 | Adicionar comentários | O analista deve poder adicionar observações durante a investigação. |
| RF13 | Anexar evidências | O sistema deve permitir associar evidências ao incidente. |
| RF14 | Manter histórico | O sistema deve manter o histórico das alterações realizadas. |
| RF15 | Pesquisar incidentes | O sistema deve permitir pesquisar incidentes. |
| RF16 | Filtrar incidentes | O sistema deve permitir filtrar incidentes por estado, severidade, categoria e período. |
| RF17 | Encerrar incidentes | O sistema deve permitir marcar um incidente como resolvido e posteriormente encerrado. |
| RF18 | Gerar relatórios | O sistema deve permitir gerar relatórios sobre os incidentes. |
| RF19 | Apresentar dashboard | O sistema deve apresentar indicadores estatísticos sobre os incidentes. |
| RF20 | Registar auditoria | O sistema deve registar as operações realizadas pelos utilizadores. |

## 4.8 Requisitos não funcionais

| ID | Requisito | Descrição |
|---|---|---|
| RNF01 | Segurança | O sistema deve proteger os dados contra acessos não autorizados. |
| RNF02 | Autenticação | O acesso aos módulos deve depender das credenciais do utilizador. |
| RNF03 | Autorização | Cada utilizador deve possuir permissões de acordo com o seu perfil. |
| RNF04 | Confidencialidade | As informações dos incidentes devem ser acessíveis apenas aos utilizadores autorizados. |
| RNF05 | Integridade | O sistema deve garantir que os dados dos incidentes não sejam alterados indevidamente. |
| RNF06 | Disponibilidade | O sistema deve estar disponível para os utilizadores autorizados durante o período de funcionamento. |
| RNF07 | Desempenho | As operações principais devem ser executadas num tempo de resposta aceitável. |
| RNF08 | Usabilidade | A interface deve ser simples e intuitiva para os analistas. |
| RNF09 | Escalabilidade | A solução deve permitir o aumento do número de incidentes e utilizadores sem alteração significativa da arquitectura. |
| RNF10 | Manutenibilidade | O sistema deve possuir uma estrutura que facilite futuras alterações e manutenção. |
| RNF11 | Auditoria | As operações realizadas devem ser registadas para permitir rastreabilidade. |
| RNF12 | Backup | A base de dados deve possuir mecanismos de cópia de segurança. |
| RNF13 | Compatibilidade | A aplicação deve funcionar nos principais navegadores utilizados na organização. |
| RNF14 | Fiabilidade | O sistema deve minimizar a perda ou corrupção dos dados registados. |

## 4.9 Estados dos incidentes

```
NOVO → ABERTO → EM INVESTIGAÇÃO → EM RESPOSTA → RESOLVIDO → ENCERRADO
```

Também pode existir `ABERTO → SUSPENSO`, quando o incidente precisa de aguardar
informação ou intervenção.

- **Novo** — incidente acabou de ser registado.
- **Aberto** — incidente foi validado e necessita de tratamento.
- **Em investigação** — analista está a investigar a causa.
- **Em resposta** — estão a ser executadas medidas de contenção/correcção.
- **Resolvido** — a situação foi tratada.
- **Encerrado** — o incidente foi formalmente concluído e documentado.

## 4.10 Base de dados proposta

PostgreSQL. Estrutura inicial proposta: `UTILIZADORES`, `INCIDENTES`, `ALERTAS`,
`EVIDENCIAS`, `COMENTARIOS`, `AUDITORIA`.

```
UTILIZADORES          INCIDENTES              ALERTAS
id_utilizador         id_incidente            id_alerta
nome                  titulo                  fonte
email                 descricao               tipo
senha                 categoria               descricao
perfil                severidade              ip_origem
estado                prioridade              ip_destino
                      estado                  data_alerta
                      data_criacao            severidade
                      data_actualizacao       id_incidente
                      responsavel

EVIDENCIAS            COMENTARIOS             AUDITORIA
id_evidencia          id_comentario           id_auditoria
id_incidente          id_incidente            id_utilizador
nome                  id_utilizador           accao
tipo                  comentario              data
localizacao           data                    descricao
data_upload
```

## 4.11 Arquitectura técnica

```
QRadar → NetScout → Suricata
              ▼
   ┌───────────────────────────┐
   │        API / Backend      │
   │   Gestão de Incidentes    │
   │   Gestão de Alertas       │
   │   Utilizadores            │
   │   Evidências              │
   │   Auditoria               │
   └─────────────┬─────────────┘
                 ▼
   ┌───────────────────────────┐
   │         PostgreSQL        │
   │  Incidentes │ Alertas     │
   │  Utilizadores │ Evidências│
   │  Histórico                │
   └───────────────────────────┘
                 ▲
         ┌───────┴────────┐
         │  Interface Web │
         └───────┬────────┘
                 ▲
         ┌───────┴────────┐
         │  Analista SOC  │
         └────────────────┘
```

## 4.12 Tecnologias para o protótipo

| Componente | Tecnologia |
|---|---|
| Frontend | HTML, CSS, JavaScript/React |
| Backend | Python + Flask/FastAPI |
| Base de dados | PostgreSQL |
| API | REST API |
| Autenticação | JWT/sessão segura |
| Segurança | HTTPS |
| Monitorização | QRadar, NetScout e Suricata |
| Gestão de incidentes | Modelo inspirado no RTIR |

## 4.13 Telas do protótipo a apresentar

- **Tela 1 — Login**: utilizador, senha, botão entrar.
- **Tela 2 — Dashboard**: total de incidentes, críticos, alta prioridade, em
  investigação, resolvidos, encerrados.
- **Tela 3 — Lista de incidentes**: ID, título, severidade, estado.
- **Tela 4 — Registar incidente**: título, descrição, categoria, severidade,
  prioridade, fonte, activo afectado, responsável.
- **Tela 5 — Detalhes do incidente**: informações, histórico, comentários,
  evidências, responsável, estado, data de criação, origem do alerta.
- **Tela 6 — Relatórios**: gráficos de incidentes por severidade, por
  categoria, por período e tempo de resolução.

## 4.14 Exemplo de cenário para demonstrar o protótipo

> **Esta é a secção que governa o cenário de demonstração da plataforma**
> (`app/services/demo_service.py`, comando `python -m scripts.manage demo`).
>
> São **10 passos**, não 19. O `docs/ESTADO.md` chegou a referir "os 19 passos
> do §33", por citar um briefing anterior com outra numeração; a numeração
> autoritativa para a defesa é esta.

**Cenário:** o Suricata detecta uma actividade suspeita na rede.

| Passo | Acção |
|---|---|
| 1 | O alerta é identificado. |
| 2 | O analista regista/converte o alerta num incidente. |
| 3 | O sistema gera automaticamente o identificador `INC-0001`. |
| 4 | O analista classifica o incidente. |
| 5 | Define a severidade como **Alta**. |
| 6 | Atribui o incidente ao responsável. |
| 7 | O analista adiciona comentários e evidências. |
| 8 | O incidente passa para **Em Investigação**. |
| 9 | Depois da resposta, passa para **Resolvido**. |
| 10 | Após a validação, passa para **Encerrado**. |

Dessa maneira demonstra-se claramente **como o protótipo resolve a lacuna
identificada no INCM**.
