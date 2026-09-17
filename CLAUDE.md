# SHEISA — instruções para o assistente

Plataforma de gestão e resposta a incidentes cibernéticos (SOC/CSIRT), componente
prática de uma monografia sobre o INCM (Moçambique). Não é um protótipo visual:
tem de ser real, funcional, testável e defensável numa defesa académica.

**Antes de trabalhar, leia [`docs/CONTINUAR.md`](docs/CONTINUAR.md)** — estado
actual, o que fazer a seguir, e catorze armadilhas concretas que já custaram horas
cada. Poupa mais tempo do que ocupa.

## O princípio, que não se negocia

> **Se não está implementado, não apresentar como implementado.**

Sem mocks, sem dados falsos, sem respostas fixas, sem integrações decorativas,
sem estatísticas inventadas. Dados de demonstração são permitidos mas têm de
estar marcados *e* passar pelos caminhos reais. Uma constante exposta na
interface mas não usada pelo código é decorativa, logo proibida.

## Regras de trabalho

- **Tudo em português**, incluindo comentários, nomes de variáveis e mensagens de
  erro. A interface é para utilizadores moçambicanos.
- **Compilar não é verificar.** O ciclo é: construir → verificar tipos →
  confrontar com a API a correr → só então registar. O terceiro passo é o que
  apanha os defeitos, e é o que se tende a saltar. Cinco das últimas seis
  operações a ganhar interface nunca tinham sido chamadas por ecrã nenhum, e uma
  devolvia 500 em todos os pedidos válidos sem que nada o revelasse.
- **Testes de regressão verificam-se por reversão**: desfaça a correcção e
  confirme que o teste falha. Um teste que passa nas duas situações não testa
  nada.
- **Nada de asserções ambíguas.** `assert codigo in (200, 403)` não afirma nada;
  descubra qual é o valor certo e afirme-o.
- **Antes de citar um número** (contagem de testes, cobertura, rotas, versões),
  meça-o. Os documentos deste repositório já estiveram errados sobre a versão do
  Python, o número de domínios e a cobertura de três módulos.
- **Confronte cada classe CSS com `frontend/src/estilos/`.** O TypeScript não as
  valida, e já foram inventadas quatro que não existiam.
- **Segredos só em variáveis de ambiente.** `.env` está no `.gitignore` e nunca
  foi versionado; só o `.env.example` com marcadores vai para o repositório.

## Comandos

```bash
docker compose up -d db db-test                      # PostgreSQL 16
cd backend && ./scripts/api.sh start                 # API em :8099
cd frontend && npm run dev                           # interface em :5500

cd backend
./.venv/Scripts/python.exe -m pytest -q              # suite
./.venv/Scripts/python.exe -m ruff check .           # tem de passar limpo
./.venv/Scripts/python.exe scripts/verificar_contrato.py <palavra-passe>
cd frontend && npm run verificar                     # tsc + eslint + relógio
```

`verificar_contrato.py` confronta os tipos do frontend com respostas reais da API
— corra-o depois de mexer em esquemas. O TypeScript garante coerência interna,
não correspondência com o servidor.

## Documentos

| | |
|---|---|
| [`docs/CONTINUAR.md`](docs/CONTINUAR.md) | **começar aqui**: estado, próximos passos, armadilhas |
| [`docs/ESTADO.md`](docs/ESTADO.md) | registo completo de decisões e defeitos corrigidos |
| [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md) | o que se aproveitou de RTIR/TheHive/Wazuh e o que se fez de outra maneira |
| [`docs/MONOGRAFIA-CAP4.md`](docs/MONOGRAFIA-CAP4.md) | o que vai ser defendido; **§4.14 é o cenário de demonstração** |
| [`docs/BRIEFING.md`](docs/BRIEFING.md) | especificação técnica |
| [`README.md`](README.md) | instalação de raiz |

A numeração `§4`, `§12`… citada nos comentários do código vem de um briefing
anterior que não está versionado e **não corresponde** a nenhum dos documentos
acima. Cada citação vem acompanhada da frase que explica a regra, e essa frase é
autossuficiente — não tente resolver a referência.

## Notas do repositório

- O trabalho vive em `main`, sincronizado com `github.com/Bauirxx/sheisaproject`.
- A pasta `sheisaproject/` na raiz é um clone residual de uma tentativa de push
  antiga, contém apenas `.git` e está no `.gitignore`. Ignore-a.
