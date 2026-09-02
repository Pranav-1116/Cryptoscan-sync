FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        libpq-dev \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cryptoscan

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY shared /app/shared
COPY services /app/services
COPY demo /app/demo
COPY scripts /app/scripts

RUN mkdir -p /tmp/cryptoscan-workspaces \
    && chown -R cryptoscan:cryptoscan /app /tmp/cryptoscan-workspaces

ENV PYTHONPATH=/app/shared/shared_config:/app/shared/shared_logging:/app/shared/shared_models:/app/services/api:/app/services/database:/app/services/scanner:/app/services/evidence:/app/services/normalization:/app/services/policy:/app/services/drift:/app/services/worker:/app/services/deduplication:/app/services/cbom:/app/services/container_scanner:/app/services/network_scanner:/app/services/cloud_scanner:/app/services/graph_engine:/app/services/business_context:/app/services/quantum:/app/services/sector_profiles:/app/services/remediation:/app/services/reporting:/app/services/ot_scanner:/app/services/vendor_intel:/app/services/agility:/app/services/payment_crypto:/app/services/universal_platform:/app/services/universal_crypto:/app/services/universal_vendor:/app/services/runtime
ENV PYTHONUNBUFFERED=1
ENV CRYPTOSCAN_ROOT=/app

USER cryptoscan

CMD ["python", "-m", "worker.main"]
