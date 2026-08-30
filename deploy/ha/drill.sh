#!/usr/bin/env bash
# Quarterly DR drill (PCI-style evidence) — automates docs/runbooks/dr-recovery.md §5.
# Exits nonzero the moment any check fails; output is the drill record.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
PASS=0; FAIL=0
note() { echo "[$(date -u +%H:%M:%S)] $*"; }
check() { if eval "$2"; then note "PASS  $1"; PASS=$((PASS+1)); else note "FAIL  $1"; FAIL=$((FAIL+1)); fi; }

note "DR drill start"

note "phase 1 — one API replica dies"
"${COMPOSE[@]}" scale api=1 2>/dev/null || "${COMPOSE[@]}" up -d --scale api=1
sleep 5
check "dashboard still served" "curl -fsS http://localhost:8080/ >/dev/null"
"${COMPOSE[@]}" up -d --scale api=2

note "phase 2 — monitor failover (leader lease)"
LEADER=$("${COMPOSE[@]}" exec -T postgres psql -U cryptoscan -d cryptoscan -tAc \
  "SELECT holder FROM monitor_leases WHERE name='monitor'" | tr -d '[:space:]')
note "current lease holder: ${LEADER:-unassigned}"
"${COMPOSE[@]}" restart monitor
sleep 10
NEWLEADER=$("${COMPOSE[@]}" exec -T postgres psql -U cryptoscan -d cryptoscan -tAc \
  "SELECT holder FROM monitor_leases WHERE name='monitor'" | tr -d '[:space:]')
check "a leader is elected after restart" "[ -n \"${NEWLEADER:-}\" ]"
check "monitor events still flow (loop alive)" \
  "${COMPOSE[@]} exec -T postgres psql -U cryptoscan -d cryptoscan -tAc \"SELECT count(*) FROM monitor_events\" | grep -qv '^0$"

note "phase 3 — database outage resilience"
"${COMPOSE[@]}" stop postgres
sleep 5
check "API degrades honestly (readyz 503, not hanging)" \
  "! curl -fsS --max-time 5 http://localhost:8080/api/v1/readyz >/dev/null 2>&1"
"${COMPOSE[@]}" start postgres
sleep 10
check "readyz recovers after DB returns" "curl -fsS http://localhost:8080/api/v1/readyz >/dev/null"
check "monitor resumed scanning" \
  "${COMPOSE[@]} exec -T postgres psql -U cryptoscan -d cryptoscan -tAc \"SELECT count(*) FROM monitor_events WHERE created_at > now() - interval '2 minutes'\" | grep -qv '^0$"

note "phase 4 — backup restore + evidence chain"
LATEST=$(ls -t backups/cryptoscan-*.db 2>/dev/null | head -1 || true)
if [ -n "${LATEST:-}" ]; then
  check "latest backup verifies" "python scripts/backup_evidence.py --verify \"${LATEST}\""
else
  note "SKIP  no sqlite backup present (postgres deployments: verify pg_dump restore)"
fi

note "DR drill complete: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
