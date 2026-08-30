#!/bin/bash
# Runs once on the REPLICA's first boot: clone the primary via pg_basebackup.
# -R writes primary_conninfo + standby.signal so the container comes up streaming.
set -euo pipefail

until pg_isready -h "${PRIMARY_HOST:?}" -U "${POSTGRES_USER:-cryptoscan}" -q; do
  echo "waiting for primary ${PRIMARY_HOST} …"; sleep 2
done

PGPASSWORD="${REPL_PASSWORD:?}" pg_basebackup \
  -h "${PRIMARY_HOST}" -U replicator -D /var/lib/postgresql/data \
  -Fp -Xs -P -R
chmod 700 /var/lib/postgresql/data
echo "clone complete — replica will start streaming from ${PRIMARY_HOST}"
