FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY shared /app/shared
COPY services /app/services
COPY demo /app/demo
COPY scripts /app/scripts

ENV PYTHONPATH=/app/shared/shared_config:/app/shared/shared_logging:/app/shared/shared_models:/app/services/api:/app/services/database:/app/services/scanner:/app/services/evidence:/app/services/normalization:/app/services/policy:/app/services/drift:/app/services/worker:/app/services/deduplication:/app/services/cbom:/app/services/container_scanner
ENV PYTHONUNBUFFERED=1
ENV CRYPTOSCAN_ROOT=/app

CMD ["python", "-m", "worker.main"]
