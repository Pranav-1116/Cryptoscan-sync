# Air-Gap Installation Runbook

Install and operate CryptoScan on a host (or network segment) with **no
outbound internet access**. Every step below uses only artifacts that ship
in this repository; nothing here calls a CDN, package index, or external
API at runtime.

**Audience:** platform/security administrators.
**Scope:** single-host Docker Compose deployment (the `k8s/` manifests
follow the same principles; substitute your registry mirroring process).

---

## 0. What makes CryptoScan air-gap capable

| Property | Where |
|---|---|
| No CDN/network font/script loads in the UI | the dashboard is served by the local `nginx` image (`services/dashboard/`) |
| All live external probing is **off by default** | `CRYPTOSCAN_TLS_LIVE=0` (network scanner), `CRYPTOSCAN_CLOUD_LIVE=0` (cloud scanners) — unset means disabled |
| No telemetry or phone-home code | Neo4j usage reporting is disabled in `docker-compose.prod.yml` (`NEO4J_server_usage__report_enabled: "false"`) |
| Scans of local checkouts need no network | `scripts/trigger_scan.py <local-path> --inline` runs the whole pipeline in-process |
| Evidence integrity is verifiable offline | `scripts/verify_evidence.py <scan_id>` re-computes content + chain hashes locally |

The platform scans *code and images you give it*; it does not need the
internet to do so.

---

## 1. Prepare artifacts on a connected host

You need one machine with internet access (or an internal mirror). It does
not need access to your production data.

```bash
# 1.1 — the source tree at the exact commit you qualified
git clone <your-mirror>/CryproScan.git && cd CryproScan
git checkout <qualified-commit>

# 1.2 — record the exact dependency set (already committed if you used `make lock`)
make lock          # writes requirements.lock.txt (49 pins)

# 1.3 — pull the base services AND build the five app images
# (postgres / redis / neo4j must travel too — the gap has no registry)
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull postgres redis neo4j
docker compose -f docker-compose.yml -f docker-compose.prod.yml build

# 1.4 — export every image the stack uses + the source
docker save $(docker compose -f docker-compose.yml -f docker-compose.prod.yml images -q) \
            -o cryptoscan-images.tar
git archive --format=tar.gz -o cryptoscan-source.tar.gz HEAD
```

Optional, if you will ever rebuild images inside the gap:

```bash
mkdir wheels
python3 -m pip download -r requirements.lock.txt -d wheels/
tar czf cryptoscan-wheels.tar.gz wheels/
```

> ** integrity step:** record SHA-256 sums of everything you transfer and
> verify them on the target host before loading.
> ```
> sha256sum cryptoscan-*.tar* > artifacts.sha256
> ```

## 2. Transfer

Move `cryptoscan-images.tar`, `cryptoscan-source.tar.gz`, `artifacts.sha256`
(one writable medium or approved file transfer) to the air-gapped host.

## 3. Install on the air-gapped host

Prerequisites: Docker Engine + Docker Compose v2.24+ (the prod overlay uses
`!reset`), 8 GB RAM recommended.

```bash
# 3.1 — verify integrity
sha256sum -c artifacts.sha256

# 3.2 — unpack source (compose files, scripts, infra/, .docker/)
tar xzf cryptoscan-source.tar.gz -C /opt/cryptoscan && cd /opt/cryptoscan

# 3.3 — load images
docker load -i cryptoscan-images.tar

# 3.4 — configure (never use the demo defaults; the API refuses to boot on them)
cp .env.production.example .env
python3 scripts/hash_admin_password.py    # prints ADMIN_PASSWORD_HASH=...
#   edit .env:
#     SECRET_KEY=<32+ random chars>        POSTGRES_PASSWORD=<strong>
#     NEO4J_PASSWORD=<strong>              ADMIN_PASSWORD_HASH=<from script>
#     ENVIRONMENT=production               COOKIE_SECURE=true
#     CORS_ORIGINS=https://cryptoscan.internal.example
# Leave CRYPTOSCAN_TLS_LIVE and CRYPTOSCAN_CLOUD_LIVE unset — disabled.

# 3.5 — bring up the stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

What happens on boot (all local):

- Postgres, Redis, Neo4j start; `neo4j-init` applies the constraint schema
  from `infra/neo4j/init/` and exits.
- The API's lifespan hook calls `init_db()` — schema/migrations run against
  the local Postgres — then bootstraps the admin account from
  `ADMIN_PASSWORD_HASH`.
- `deploy_prod.sh` exists as a fail-closed wrapper for step 3.4–3.5 if you
  prefer script-driven bring-up.

## 4. Verify the installation

Run every check from inside the gap — none of them need the internet:

```bash
# 4.1 — liveness + readiness
curl -fsS http://localhost/health
curl -fsS http://localhost/api/v1/healthz

# 4.2 — observability is local (Prometheus text format)
curl -fsS http://localhost/metrics | head

# 4.3 — a full scan of a bundled local target, entirely in-process
python3 scripts/trigger_scan.py local://<authorized-source> --inline
#   expect: findings across languages, exit 0

# 4.4 — evidence chain verifies offline
python3 scripts/verify_evidence.py <scan-id-from-4.3>
#   expect: every record PASS

# 4.5 — log in via the dashboard (nginx, no external origins) and confirm:
#   Overview loads stats · Scans lists the 4.3 scan · CBOM export downloads
```

Also confirm no egress is attempted (host firewall/IPS log should stay
quiet apart from your own admin access).

## 5. Operating offline

| Task | How (all offline) |
|---|---|
| Scan code | `trigger_scan.py /path/to/repo --inline`, or the dashboard's *New scan* with a local `local://` target — repos arrive via your approved transfer process |
| Scan container images | `docker save` the image on the connected side, transfer, scan the tar via the container scanner |
| Import scans from another zone | `GET /api/v1/scans/{id}/transfer` → `POST /api/v1/scans/import` (digest-verified; see cross-instance scan transfer docs) |
| Backup | `scripts/backup_evidence.py` — SHA-256 manifest, chain re-verification (`docs/admin-guide/backup-restore.md`) |
| Restore | `scripts/restore_evidence.py` (staging swap + rotation) |
| Drift alerts | configure SMTP to your internal relay, and/or a webhook alerter to an internal endpoint (signed `X-CryptoScan-Signature`, see `services/drift/drift/alerts/webhook_alerter.py`) |
| Update fingerprint DB | transfer the fingerprint bundle via your approved process, then `docs/admin-guide/fingerprint-db-management.md` |

## 6. Upgrades inside the gap

1. On the connected host: checkout the new qualified commit, `make lock`,
   rebuild, `docker save`, checksum, transfer.
2. On the target: `scripts/backup_evidence.py` **first** (this is your
   rollback), then `docker load`, unpack source, `docker compose ... up -d`.
3. The API runs `init_db()` on boot — schema changes apply automatically.
4. Verify with §4. Rollback = restore the backup onto the previous images.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| API container exits immediately | demo secret left in `.env` (fails closed) — check `SECRET_KEY`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`, `ADMIN_PASSWORD_HASH` are all set |
| `unsupported key "!reset"` | Compose < v2.24 — upgrade Docker Compose on the air-gapped host |
| Webhook alerts SKIPPED | no webhook URL configured — SKIPPED is the honest state, nothing is fabricated as sent |
| Cloud/TLS sections empty | expected: live probing is disabled in the gap; findings come from transferred code/images |
| Neo4j graph page empty | populate with `scripts/populate_graph.py` after scans exist; the dependency graph falls back to the local store when Neo4j is unreachable |
