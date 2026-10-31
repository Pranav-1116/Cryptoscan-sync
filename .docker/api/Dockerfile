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
COPY requirements.txt requirements.lock.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt -c /app/requirements.lock.txt

# ── application source ───────────────────────────────────────────────
COPY shared   /app/shared
COPY services /app/services
COPY scripts  /app/scripts
COPY config   /app/config
COPY .env.example /app/.env.example

# Register EVERY service + shared package on sys.path via a .pth file.
# This replaces a long, error-prone hardcoded PYTHONPATH: any new
# services/<name>/ package directory is picked up automatically.
RUN set -eux; \
    SITE_DIR="$(python -c 'import site,sys; print([p for p in site.getsitepackages() if p.startswith(sys.prefix)][0])')"; \
    { for d in /app/shared/*/ /app/services/*/; do echo "$d"; done; } \
        | sort -u > "$SITE_DIR/cryptoscan.pth"; \
    cat "$SITE_DIR/cryptoscan.pth"

# Scanner workspace: the live/universal scanners clone/extract scan targets
# here. It must exist and be writable by the unprivileged user, and it is an
# allow-listed source root for the target-validation (SSRF/traversal) guard.
RUN mkdir -p /tmp/cryptoscan-workspaces \
    && chown -R cryptoscan:cryptoscan /app /tmp/cryptoscan-workspaces

USER cryptoscan
EXPOSE 8010

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=8 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=3).status==200 else 1)"

# Forwarded headers are resolved ONCE, in the application
# (api.security.client_ip), against an explicit proxy boundary described by
# TRUSTED_PROXY_COUNT + TRUSTED_PROXY_CIDRS. uvicorn's --proxy-headers would
# rewrite the ASGI client address from X-Forwarded-For for ANY peer, which
# silently defeats that boundary: the CIDR check would then read the
# client-supplied value instead of the socket peer. Leave it off; configure
# TRUSTED_PROXY_* in the deployment instead.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8010"]
