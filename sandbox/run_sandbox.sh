#!/usr/bin/env bash
# One-command banking sandbox: stack up, estate up, database seeded.
#
# Notes for operators:
#  * Seeding runs inside a throwaway Python container (sandbox-seed), so the
#    host does NOT need sqlalchemy/psycopg installed.
#  * `down` only removes the SANDBOX services; the main CryptoScan stack and
#    its volumes (postgres_data, redis_data, neo4j_data) are never touched.
#    `down --all` additionally stops the main stack but STILL never deletes
#    volumes — a full destructive teardown is intentionally not offered.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.yml -f sandbox/docker-compose.sandbox.yml)
SBX_SERVICES="internet-banking mobile-api swift-gateway legacy-branch hsm-sim core-banking-db payments-bastion certgen bank-redis-seed sandbox-seed"

wait_healthy() {
  local container="$1" max="${2:-40}"
  echo "waiting for ${container} to report healthy..."
  for _ in $(seq 1 "$max"); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo missing)
    [ "$status" = "healthy" ] && return 0
    sleep 2
  done
  echo "WARNING: $container never reported healthy (last=$status); continuing" >&2
  return 0
}

# the seed/migrate container talks to Postgres by name — start it first, or
# alembic fails with 'could not translate host name "postgres"'
db_up() {
  "${COMPOSE[@]}" up -d postgres
  wait_healthy cryptoscan-postgres 60
}

case "${1:-up}" in
  up)
    # Wave 1 — data plane only. The seed talks straight to Postgres and even
    # creates the schema itself, so a sick API can never block the sandbox.
    "${COMPOSE[@]}" up -d postgres redis
    wait_healthy cryptoscan-postgres 60
    "${COMPOSE[@]}" up -d ${SBX_SERVICES%% sandbox-seed}   # fake estate, no API dependency
    "${COMPOSE[@]}" run --rm sandbox-seed

    # Wave 2 — app plane. api/worker/frontend need each other healthy; if the
    # API is mid-migration (fresh volumes) or broken, this warns but never
    # aborts the sandbox bring-up.
    "${COMPOSE[@]}" up -d api
    if wait_healthy cryptoscan-api 90 && [ "$(docker inspect -f '{{.State.Health.Status}}' cryptoscan-api 2>/dev/null)" = "healthy" ]; then
      "${COMPOSE[@]}" up -d worker estate-daemon monitor frontend nginx 2>/dev/null || true
    else
      echo "WARNING: cryptoscan-api is not healthy — console will 502. Inspect with:" >&2
      echo "  docker logs cryptoscan-api --tail 80" >&2
    fi
    echo
    echo "sandbox ready. One-click sweep target (Scanners -> Network):"
    echo "  10.210.0.0/29      (covers .0-.7: all TLS + the database; bastion is .8)"
    echo "Live-scan targets (paste into the Network page):"
    echo "  TLS:  10.210.0.2:443  10.210.0.3:443  10.210.0.4:443"
    echo "        10.210.0.5:443 (legacy)  10.210.0.6:8443 (hsm-sim)"
    echo "  DB:   10.210.0.7:5432 (starttls=postgresql)"
    echo "  SSH:  10.210.0.8:22 (payments-bastion, legacy KEX)"
    echo "  DNS also works: internet-banking.bank.sandbox, ..."
    echo "  console: http://127.0.0.1:3003   (run '$0 targets' to reprint)"
    ;;
  seed)   db_up; "${COMPOSE[@]}" run --rm sandbox-seed ;;
  reset)  db_up; "${COMPOSE[@]}" run --rm -e SEED_ARGS="--reset" sandbox-seed ;;
  migrate)
    # Applies the DB migrations without seeding — the repair path for the
    # API's 'Database migration status is missing' startup failure.
    db_up
    "${COMPOSE[@]}" run --rm -e SEED_MODE="migrate-only" sandbox-seed
    echo "schema migrated. Now: docker compose restart cryptoscan-api (or rerun: $0 up)"
    ;;
  db-rebuild)
    # Destructive but scoped: drops ONLY the CryptoScan public schema (which
    # currently holds just sandbox rows + unstamped create_all tables), then
    # re-migrates and reseeds. Needed once to repair the state left by the
    # pre-alembic seeder. Bank stack volumes are untouched.
    read -r -p "This drops the 'public' schema of the cryptoscan DB and rebuilds it. Type REBUILD to continue: " answer
    if [ "$answer" != "REBUILD" ]; then echo "aborted"; exit 1; fi
    docker exec cryptoscan-postgres psql -U "${POSTGRES_USER:-cryptoscan}" -d "${POSTGRES_DB:-cryptoscan}" \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO public;"
    "${COMPOSE[@]}" run --rm sandbox-seed
    echo "DB rebuilt, migrated and seeded. Restarting API..."
    docker compose -f docker-compose.yml restart api 2>/dev/null || true
    ;;
  estate) "${COMPOSE[@]}" up -d ${SBX_SERVICES%% sandbox-seed} ;;
  console)
    # Bring up the web console: api must be healthy first (frontend depends on
    # it), then frontend (:3003) and the nginx gateway (:8088).
    "${COMPOSE[@]}" up -d api
    for _ in $(seq 1 45); do
      [ "$(docker inspect -f '{{.State.Health.Status}}' cryptoscan-api 2>/dev/null)" = "healthy" ] && break
      sleep 2
    done
    "${COMPOSE[@]}" up -d frontend nginx
    echo "console:  http://127.0.0.1:${FRONTEND_PORT:-3003}"
    echo "gateway:  http://127.0.0.1:${NGINX_PORT:-8088}"
    ;;down)
    # Sandbox-only teardown: stop/remove just the fake-estate containers plus
    # the sandbox_certs volume. Never interacts with the main stack's
    # containers or named volumes.
    "${COMPOSE[@]}" stop ${SBX_SERVICES} 2>/dev/null || true
    "${COMPOSE[@]}" rm -f ${SBX_SERVICES} 2>/dev/null || true
    docker volume rm "$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')_sandbox_certs" 2>/dev/null || true
    # Detach the API (it rides this LAN for live scans), then drop the fake
    # bank LAN itself so the next `up` recreates it cleanly.
    docker network disconnect cryptoscan-sandbox-net cryptoscan-api 2>/dev/null || true
    docker network rm cryptoscan-sandbox-net 2>/dev/null || true
    echo "sandbox estate removed; main stack untouched"
    ;;
  status) "${COMPOSE[@]}" ps ;;
  agent)
    # Continuous bank-agent mode: the collector re-observes the estate every
    # COLLECT_INTERVAL_SECONDS (default 300). Needs the console credentials in
    # .env once:
    #   CRYPTOSCAN_USERNAME=admin
    #   CRYPTOSCAN_PASSWORD=...
    #   COLLECT_INTERVAL_SECONDS=300
    if ! grep -q "^COLLECT_INTERVAL_SECONDS=" .env 2>/dev/null; then
      echo "COLLECT_INTERVAL_SECONDS=300" >> .env
      echo "added COLLECT_INTERVAL_SECONDS=300 to .env"
    fi
    if ! grep -q "^CRYPTOSCAN_USERNAME=" .env 2>/dev/null; then
      echo "add CRYPTOSCAN_USERNAME + CRYPTOSCAN_PASSWORD to .env first (your console login)" >&2
      exit 1
    fi
    "${COMPOSE[@]}" up -d sandbox-collect
    echo "agent running — observations stream in on the interval; BOMs re-project from the newest"
    ;;
  collect)
    # The living-bank collector: one pass over the estate through real
    # channels, pushed to the ingestion API; every BOM re-projects from it.
    # Needs the console login once per run (prompted if not in env).
    # docker compose reads .env itself; only ask for what .env does not hold
    for key in CRYPTOSCAN_USERNAME CRYPTOSCAN_PASSWORD; do
      if [ -z "${!key:-}" ] && [ -f .env ]; then
        val="$(grep -E "^${key}=" .env | tail -1 | cut -d= -f2-)"
        [ -n "$val" ] && export "$key=$val"
      fi
    done
    if [ -z "${CRYPTOSCAN_USERNAME:-}" ]; then read -r -p "console username: " CRYPTOSCAN_USERNAME; export CRYPTOSCAN_USERNAME; fi
    if [ -z "${CRYPTOSCAN_PASSWORD:-}" ]; then read -r -s -p "console password: " CRYPTOSCAN_PASSWORD; echo; export CRYPTOSCAN_PASSWORD; fi
    "${COMPOSE[@]}" run --rm -e CRYPTOSCAN_USERNAME -e CRYPTOSCAN_PASSWORD sandbox-collect
    ;;
  agents)
    # Cryptava: the real host agent beside the sandbox bank servers.
    #   agents                         start the four built-in agents (swift-gateway,
    #                                  internet-banking, core-banking-db, payments-bastion);
    #                                  they enrol themselves as mrdn-sbx-dc1-...
    #   agents add <host> <id> <token> put an agent on <host> with the agent id + one-time
    #                                  token from the console (Discovery -> Cryptava agents
    #                                  -> Add a server -> "Sandbox bank server")
    #   agents remove <host>           stop and delete the agent beside <host>
    #   agents list | status | stop
    # Every agent shares its host's processes + network, reads the host's files through
    # /proc/1/root, gets the host's CMDB record (sandbox/cryptava/<host>.json) and pushes a
    # SIGNED observation every 5 minutes. Enrolment survives in named volumes.
    AGENTS="cryptava-swift-gateway cryptava-internet-banking cryptava-core-banking-db cryptava-payments-bastion"
    SBX_HOSTS="internet-banking mobile-api swift-gateway legacy-branch hsm-sim core-banking-db payments-bastion"
    # host -> container | hostname | ip | business system | owner
    host_info() {
      case "$1" in
        internet-banking) echo "cryptoscan-sbx-internet-banking|internet-banking|10.210.0.2|Internet Banking|Digital Channels" ;;
        mobile-api)       echo "cryptoscan-sbx-mobile-api|mobile-api|10.210.0.3|Mobile Banking API|Digital Channels" ;;
        swift-gateway)    echo "cryptoscan-sbx-swift-gateway|swift-gateway|10.210.0.4|SWIFT Gateway|Payments Operations" ;;
        legacy-branch)    echo "cryptoscan-sbx-legacy-branch|legacy-branch|10.210.0.5|Branch Banking|Branch Technology" ;;
        hsm-sim)          echo "cryptoscan-sbx-hsm-sim|hsm-sim|10.210.0.6|Payment HSM|Payments Security" ;;
        core-banking-db)  echo "cryptoscan-sbx-core-db|core-db|10.210.0.7|Core Banking|Core Banking Platform" ;;
        payments-bastion) echo "cryptoscan-sbx-payments-bastion|payments-bastion|10.210.0.8|SWIFT Gateway|Payments Operations" ;;
        *) return 1 ;;
      esac
    }
    case "${2:-}" in
      stop)
        "${COMPOSE[@]}" --profile agents stop $AGENTS
        for c in $(docker ps -q --filter label=cryptoscan.cryptava.added=1); do docker stop "$c" >/dev/null; done
        exit 0 ;;
      list|status)
        names=$(docker ps -a --format '{{.Names}}' --filter name=cryptoscan-cryptava- | sort)
        [ -n "$names" ] || { echo "no Cryptava agents yet — '$0 agents' or '$0 agents add <host> <id> <token>'"; exit 0; }
        for c in $names; do
          state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
          echo "== $c ($state)"
          if [ "${2}" = "status" ] && [ "$state" = "running" ]; then
            docker exec "$c" sh -c 'PYTHONPATH=/opt/cryptava python3 -m cryptava status' 2>/dev/null | head -40 || true
          fi
        done
        exit 0 ;;
      remove)
        host="${3:-}"; host_info "$host" >/dev/null || { echo "usage: $0 agents remove <host>   hosts: $SBX_HOSTS" >&2; exit 2; }
        docker rm -f "cryptoscan-cryptava-$host" >/dev/null 2>&1 && echo "removed the agent beside $host" || echo "no agent beside $host"
        echo "(its enrolment stays in the console until you retire it there)"
        exit 0 ;;
      add)
        host="${3:-}" agent_id="${4:-}" token="${5:-}"
        info=$(host_info "$host") || { echo "usage: $0 agents add <host> <agent-id> <token>   hosts: $SBX_HOSTS" >&2; exit 2; }
        [ -n "$agent_id" ] && [ -n "$token" ] || { echo "usage: $0 agents add <host> <agent-id> <token>  (both from the console: Add a server)" >&2; exit 2; }
        IFS='|' read -r target hname ip system owner <<EOF_INFO
$info
EOF_INFO
        docker inspect -f '{{.State.Running}}' "$target" 2>/dev/null | grep -q true \
          || { echo "$host ($target) is not running — start the sandbox first: $0 up" >&2; exit 1; }
        agent="cryptoscan-cryptava-$host"
        if docker inspect "$agent" >/dev/null 2>&1; then
          echo "an agent already runs beside $host ($agent). Remove it first:  $0 agents remove $host" >&2; exit 1
        fi
        volume="cryptoscan_cryptava_added_${host//-/_}"
        docker volume rm -f "$volume" >/dev/null 2>&1 || true   # a one-time token means a fresh identity
        docker run -d --name "$agent" \
          --label cryptoscan.cryptava.added=1 --label "cryptoscan.cryptava.host=$host" \
          --network "container:$target" --pid "container:$target" \
          --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH --restart unless-stopped \
          -e PYTHONPATH=/opt/cryptava -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 \
          -e CRYPTAVA_SERVER=http://api:8010 \
          -e "CRYPTAVA_ESTATE=${SANDBOX_ESTATE:-meridian-bank}" -e CRYPTAVA_SCOPE=sandbox-lan \
          -e CRYPTAVA_ROOT=/proc/1/root -e CRYPTAVA_INTERVAL=300 -e CRYPTAVA_JITTER=30 \
          -e 'CRYPTAVA_TAGS={"environment": "production-sandbox", "datacenter": "dc1", "owner": "Meridian Bank"}' \
          -e "CRYPTAVA_HOSTNAME=$hname" -e "CRYPTAVA_FQDN=$hname.bank.sandbox" -e "CRYPTAVA_PRIMARY_IP=$ip" \
          -e "CRYPTAVA_SYSTEM={\"name\": \"$system\", \"owner\": \"$owner\"}" \
          -e "CRYPTAVA_AGENT_ID=$agent_id" -e "CRYPTAVA_ENROLLMENT_TOKEN=$token" \
          -v "$PWD/services/cryptava:/opt/cryptava:ro" \
          -v "$volume:/var/lib/cryptava" \
          -v "$PWD/sandbox/cryptava/$host.json:/etc/cryptava/asset-record.json:ro" \
          --entrypoint /bin/sh python:3.12-alpine /opt/cryptava/packaging/container/entrypoint.sh >/dev/null
        echo "Cryptava agent started beside $host ($ip) as $agent"
        ok=0
        for _ in $(seq 1 45); do
          logs=$(docker logs "$agent" 2>&1 || true)
          if printf '%s' "$logs" | grep -q '"enrolled": true'; then ok=1; break; fi
          if printf '%s' "$logs" | grep -Eiq 'cryptava: .*(error|refused|invalid|expired|denied|401|403|404|409)'; then break; fi
          sleep 2
        done
        docker logs "$agent" 2>&1 | grep -v '"api_key"' | tail -8 | sed 's/^/   /'
        if [ "$ok" = "1" ]; then
          echo "Enrolled. It reports within a minute: console -> Discovery -> Cryptava agents."
          echo "Follow it:  docker logs -f $agent"
          exit 0
        fi
        docker stop "$agent" >/dev/null 2>&1 || true
        echo "Enrolment did not succeed (see the log above). A token works once and expires —" >&2
        echo "in the console open the agent, click 'new token', then:  $0 agents remove $host  and run add again." >&2
        exit 1 ;;
      "") ;;
      *) echo "usage: $0 agents [add <host> <id> <token> | remove <host> | list | status | stop]" >&2; exit 2 ;;
    esac
    if [ -z "${CRYPTOSCAN_USERNAME:-}" ]; then read -r -p "console username: " CRYPTOSCAN_USERNAME; export CRYPTOSCAN_USERNAME; fi
    if [ -z "${CRYPTOSCAN_PASSWORD:-}" ]; then read -r -s -p "console password: " CRYPTOSCAN_PASSWORD; echo; export CRYPTOSCAN_PASSWORD; fi
    "${COMPOSE[@]}" --profile agents up -d $AGENTS
    echo "Cryptava agents started. Follow one:  docker logs -f cryptoscan-cryptava-swift-gateway"
    echo "Fleet view: console -> Discovery -> Cryptava agents (/cryptava).  Status:  $0 agents status"
    echo "Add the other bank servers from the console (Add a server -> Sandbox bank server):  mobile-api, legacy-branch, hsm-sim"
    ;;
  targets)
    # Paste-ready target list for the console's Network page / API calls.
    cat <<'EOF'
Meridian Bank sandbox estate — live scan targets
Authorized scope (declared automatically by the seeder):  10.210.0.0/24

One-click discovery sweep (Scanners page → Network → active):
  10.210.0.0/29     covers .0–.7 — all TLS endpoints + the database
                    (never sweep the whole /24 from the UI: dead addresses
                    each cost an ARP timeout and the wizard gives up at 60s)
  10.210.0.8/32     the SSH bastion, swept as a single host

TLS endpoints (host:port, one per line):
10.210.0.2:443      internet-banking   TLS 1.2/1.3, ECDHE only (strong)
10.210.0.3:443      mobile-api         TLS 1.2/1.3 (strong)
10.210.0.4:443      swift-gateway      TLS 1.2/1.3, RSA-3072 cert
10.210.0.5:443      legacy-branch      TLS 1.0/1.1 enabled, RSA-1024, expiring (weak on purpose)
10.210.0.6:8443     hsm-sim            TLS payment-HSM simulator
10.210.0.7:5432     core-banking-db    PostgreSQL STARTTLS (set starttls=postgresql or auto)

SSH endpoint:
10.210.0.8:22       payments-bastion   legacy KEX/host-key algs (sha1, ssh-rsa, CBC)

DNS aliases (same targets, by name):
internet-banking.bank.sandbox  mobile-api.bank.sandbox  swift-gateway.bank.sandbox
legacy-branch.bank.sandbox     hsm-sim.bank.sandbox:8443  core-banking-db.bank.sandbox
payments-bastion.bank.sandbox
EOF
    ;;
  *) echo "usage: $0 [up|seed|reset|migrate|db-rebuild|estate|console|targets|collect|agent|agents|down|status]" >&2; exit 2 ;;
esac
