# CryptoScan service image — api, worker and monitor share one image.
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python -m pip install --no-cache-dir -e shared/shared_config -e shared/shared_logging \
    -e shared/shared_models -e services/database -e services/scanner -e services/evidence \
    -e services/normalization -e services/policy -e services/drift -e services/worker \
    -e services/api -e services/payment_crypto

ENV PYTHONPATH=/app/shared/shared_config:/app/shared/shared_logging:/app/shared/shared_models:/app/services/api:/app/services/database:/app/services/scanner:/app/services/evidence:/app/services/normalization:/app/services/policy:/app/services/drift:/app/services/worker:/app/services/deduplication:/app/services/cbom:/app/services/container_scanner:/app/services/network_scanner:/app/services/cloud_scanner:/app/services/graph_engine:/app/services/business_context:/app/services/quantum:/app/services/remediation:/app/services/reporting:/app/services/ot_scanner:/app/services/vendor_intel:/app/services/agility:/app/services/payment_crypto:/app/services/universal_platform:/app/services/universal_crypto:/app/services/universal_vendor:/app/services/runtime

# unprivileged runtime user
RUN useradd --system --uid 10001 cryptoscan && mkdir -p /app/backups && chown -R cryptoscan /app
USER cryptoscan

EXPOSE 8000
