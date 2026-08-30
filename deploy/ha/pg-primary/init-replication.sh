#!/bin/bash
# Runs once on the PRIMARY's first boot: replication role with least privilege.
set -euo pipefail
psql -U "${POSTGRES_USER:-cryptoscan}" -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '${REPL_PASSWORD:?set REPL_PASSWORD}';"
