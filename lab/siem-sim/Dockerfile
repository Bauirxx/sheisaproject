# Simulador de laboratório das APIs do QRadar/NetScout. Sem dependências: só a
# biblioteca-padrão do Python, pelo que não há `pip install` nem camada de build.
FROM python:3.13-slim

WORKDIR /app
COPY servidor.py .

# O vendor, o token e a porta vêm do ambiente (definidos no docker-compose).
CMD ["python", "servidor.py"]
