# Scanner image: legacy standalone CLI plus the fixed-input parser adapter.
# Production workers override the entrypoint to python -I -m scanner.isolated
# and require an operator-built/preloaded immutable digest; no automatic pull.
# See docs/dev/scanner-isolation.md for runtime and workspace prerequisites.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CRYPTOSCAN_ROOT=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cryptoscan

COPY requirements.txt requirements.lock.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt -c /app/requirements.lock.txt

COPY shared   /app/shared
COPY services /app/services

# Register service + shared packages on sys.path via a .pth file.
RUN set -eux; \
    SITE_DIR="$(python -c 'import site,sys; print([p for p in site.getsitepackages() if p.startswith(sys.prefix)][0])')"; \
    { for d in /app/shared/*/ /app/services/*/; do echo "$d"; done; } \
        | sort -u > "$SITE_DIR/cryptoscan.pth"

RUN chown -R cryptoscan:cryptoscan /app
USER cryptoscan

ENTRYPOINT ["python", "-m", "scanner.main"]
