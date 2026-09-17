# Imagen unica para los dos procesos de la Fase 1: la API de ingestion y el
# normalizador de streaming. Comparten el mismo codigo e imagen; lo que
# cambia es el comando (ver docker-compose.yml). Dos imagenes separadas para
# un prototipo solo duplicarian el build sin aportar aislamiento real.
FROM python:3.11-slim AS base

WORKDIR /app

# Dependencias del sistema para scikit-learn/faiss-cpu (compilacion nativa
# minima) sin arrastrar un toolchain completo.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
COPY src/ ./src/

# La instalacion via pyproject (editable no hace falta en produccion) trae el
# paquete `cybersentinel` completo; nats-py se instala aparte porque es un
# extra opcional (streaming) que la imagen de la API tambien necesita para
# poder correr el servicio normalizador con el mismo Dockerfile.
RUN pip install --no-cache-dir . && \
    pip install --no-cache-dir "nats-py>=2.6"

COPY config/ ./config/

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "cybersentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
