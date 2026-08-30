#!/usr/bin/env bash
# Promote the streaming replica to primary after losing the primary host.
# Usage: ./promote-replica.sh [compose-project-dir]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml" -f "$DIR/docker-compose.replication.yml")

echo "1/4 confirming the primary is really gone (split-brain guard)…"
if "${COMPOSE[@]}" exec -T postgres pg_isready -U cryptoscan -q; then
  echo "primary still answers — refusing to promote (two primaries = split brain)" >&2
  exit 1
fi

echo "2/4 checking replica lag before promotion…"
"${COMPOSE[@]}" exec -T postgres-replica psql -U cryptoscan -d cryptoscan -tAc \
  "SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 'caught-up' ELSE 'lagging ' || pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::text END"

echo "3/4 promoting…"
"${COMPOSE[@]}" exec -T postgres-replica pg_ctl promote -D /var/lib/postgresql/data \
  || "${COMPOSE[@]}" exec -T postgres-replica psql -U cryptoscan -d cryptoscan -c "SELECT pg_promote()"

echo "4/4 pointing services at the promoted node…"
echo "  stop the dead primary container:  ${COMPOSE[*]} stop postgres"
echo "  repoint DATABASE_URL to postgres-replica and restart api/worker/monitor"
echo "  verify: curl -fsS http://localhost:8080/api/v1/readyz"
echo "DONE — file the drill result with the audit evidence."
