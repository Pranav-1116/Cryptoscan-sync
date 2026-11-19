# Cryptava container image — for Kubernetes DaemonSets and sidecars.
# Build from services/cryptava:  docker build -f packaging/container/Dockerfile -t cryptava:1.0.0 .
FROM python:3.12-alpine
LABEL org.opencontainers.image.title="cryptava" \
      org.opencontainers.image.description="CryptoScan host agent: HBOM, SBOM, CBOM, NBOM, VBOM, TechBOM" \
      org.opencontainers.image.version="1.0.0"
COPY cryptava /opt/cryptava/cryptava
COPY packaging/container/entrypoint.sh /usr/local/bin/cryptava-entrypoint
# dmidecode: DIMM detail where the firmware tables are reachable (a privileged DaemonSet
# with /sys/firmware mounted); without it HBOM still reports memory from /proc/meminfo.
RUN apk add --no-cache dmidecode \
 && chmod 0755 /usr/local/bin/cryptava-entrypoint \
 && printf '#!/bin/sh\nexport PYTHONPATH=/opt/cryptava\nexec python3 -m cryptava "$@"\n' > /usr/local/bin/cryptava \
 && chmod 0755 /usr/local/bin/cryptava
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 CRYPTAVA_STATE_DIR=/var/lib/cryptava
ENTRYPOINT ["/usr/local/bin/cryptava-entrypoint"]
