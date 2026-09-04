FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CRYPTOSCAN_ROOT=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        libpq-dev \
        openssl \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cryptoscan

# ── python dependencies (cached layer) ───────────────────────────────
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ── application source ───────────────────────────────────────────────
COPY shared   /app/shared
COPY services /app/services
COPY demo     /app/demo
COPY scripts  /app/scripts
COPY config   /app/config

# Register EVERY service + shared package on sys.path via a .pth file
# (see .docker/api/Dockerfile for rationale — auto-picks up new services).
RUN set -eux; \
    SITE_DIR="$(python -c 'import site,sys; print([p for p in site.getsitepackages() if p.startswith(sys.prefix)][0])')"; \
    { for d in /app/shared/*/ /app/services/*/; do echo "$d"; done; } \
        | sort -u > "$SITE_DIR/cryptoscan.pth"; \
    cat "$SITE_DIR/cryptoscan.pth"

RUN mkdir -p /tmp/cryptoscan-workspaces \
    && chown -R cryptoscan:cryptoscan /app /tmp/cryptoscan-workspaces

USER cryptoscan

CMD ["python", "-m", "worker.main"]
