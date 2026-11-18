#!/bin/sh
# sandbox-collect entrypoint: install the two libs the collector needs
# (docker SDK for the daemon socket, psycopg for the ledger version probe),
# then collect. One pass by default; when COLLECT_INTERVAL_SECONDS is set the
# collector behaves like a real bank agent and re-observes on that cadence.
set -e
pip install -q docker 'psycopg[binary]'
if [ -n "${COLLECT_INTERVAL_SECONDS:-}" ]; then
  echo "[collect] agent mode — one pass every ${COLLECT_INTERVAL_SECONDS}s"
  while :; do
    python /collect/collect_estate.py || echo "[collect] pass failed; next in ${COLLECT_INTERVAL_SECONDS}s"
    sleep "${COLLECT_INTERVAL_SECONDS}"
  done
fi
exec python /collect/collect_estate.py
