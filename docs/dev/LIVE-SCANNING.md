# 24/7 Live Scanning (Enterprise)

CryptoScan runs a **continuous monitor daemon** that watches your estate around
the clock — not a cron job that scans on a schedule, but a live scanner that
**reacts to change in real time** and re-scans the affected system immediately.

This page covers the daemon, change-watch mode, HA, and the enterprise
operational surfaces. For the full API see `/api/v1/monitor/*` (OpenAPI docs).

---

## 1. What runs 24/7

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  monitor daemon             │  tick  │  worker.monitor.engine       │
│  scripts/run_monitor.py     │ ─────► │  ┌────────────────────────┐  │
│  - leader lease (HA)        │        │  │ 1. change-watch probes │  │
│  - SIGTERM graceful stop    │        │  │    (git HEAD, image id)│  │
│  - crash-proof tick         │        │  │ 2. due-target selection│  │
│  - fresh DB session per tick│        │  │ 3. live scanners       │  │
└─────────────┬───────────────┘        │  │ 4. events + alerts     │  │
              │ monitor_events (DB)    │  └────────────────────────┘  │
              ▼                        └──────────────┬───────────────┘
   API event tailer (2s) ──► SSE /api/v1/events/stream ──► Live events
```

**Deployment:** `docker compose up -d` starts a `monitor` service (Postgres +
Redis). Dev mode: `make monitor` (daemon) / `make monitor-once` (single sweep).

**HA:** run N daemon replicas — a database-backed leader lease (`monitor_leases`,
migration 0031) means exactly one scans; if the leader dies the lease expires
and a standby takes over within `MONITOR_LEASE_TTL_SECONDS` (default 60 s). No
human promotion step. Graceful shutdown releases the lease instantly (no TTL
wait) — the API's liveness signal flips immediately.

## 2. Change-watch mode (realtime rescan-on-change)

Interval scanning answers *"is anything wrong right now?"*. Change watching
answers *"did anything change since the last look?"* — and when the answer is
yes, the engine rescans **immediately**, without waiting for the next window.

Enable per target with `config.watch = true` (REPO and CONTAINER types only):

```bash
curl -X POST $API/api/v1/monitor/targets -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "name": "core-payments",
    "target_type": "REPO",
    "config": {
      "repo": "https://github.com/org/core-payments.git",
      "branch": "main",
      "watch": true
    },
    "interval_seconds": 3600
  }'
```

How it behaves (verified live in the sandbox):

| Tick | Probe | Verdict | Effect |
|---|---|---|---|
| 1st observation | git HEAD stored | `UNKNOWN` (baseline) | fingerprint stored, **no alert** |
| later, HEAD unchanged | same SHA | `UNCHANGED` | scan only when interval due |
| HEAD changed | new SHA | `CHANGED` | **immediate rescan** + `CHANGE_DETECTED` event |
| probe fails (network/git down) | — | `UNKNOWN` | `WATCH_PROBE_FAILED` event (deduped per error), fingerprint **kept**, scheduled scans continue |

Probes are cheap and side-effect free:

- **REPO** — `git ls-remote <url> <branch>` (one round-trip, no clone).
- **CONTAINER** — `docker image inspect --format '{{.Id}}' <ref>`; without a
  docker CLI this reports `WATCH_UNSUPPORTED` honestly (scheduled scans continue).

Every verdict lands in `monitor_events`, is federated to the SSE stream
(`/api/v1/events/stream`) by the API tailer, and `CHANGE_DETECTED` events are
exposed as Prometheus counters (`cryptoscan_monitor_changes_detected`).

## 3. Operational surfaces

**Liveness** — `GET /api/v1/monitor/status` → `overview.daemon_health`:

```json
{ "alive": true, "holder": "host:4006", "expires_at": "…", "detail": "lease held", "script": "scripts/run_monitor.py" }
```

No lease / expired lease ⇒ `alive: false` — the API never assumes the daemon
is running.

**Metrics** — `GET /metrics` (Prometheus):
`cryptoscan_monitor_targets_total`, `cryptoscan_monitor_targets_by_status{status=…}`,
`cryptoscan_monitor_targets_watch_enabled`, `cryptoscan_monitor_events_total`,
`cryptoscan_monitor_changes_detected`.

**Alerts** — new issues fire `ALERT` once per issue (steady-state noise stays
quiet) and fan out to CEF/UDP (SIEM), signed webhook (HMAC), and email —
see `worker.monitor.alerting` and `ALERT_CEF_HOST` / `ALERT_WEBHOOK_URL` /
`SMTP_HOST` + `ALERT_EMAIL_TO`.

**Failure handling** — a failing target backs off exponentially
(interval × 2^failures, capped 24 h) and is marked `DEGRADED`/`FAILING`; a
target that cannot run at all reports `BLOCKED` with the exact reason. The
tick never raises — a bad target is data, not a crash.

## 4. Configuration (env / .env)

| Variable | Default | Meaning |
|---|---|---|
| `MONITOR_TICK_SECONDS` | 30 | daemon tick cadence (realtime feel: 15–30 s) |
| `MONITOR_LEASE_TTL_SECONDS` | 60 | leader-lease TTL (HA failover bound) |
| `MONITOR_JITTER_FRACTION` | 0.1 | random spread on `next_scan_at` (0 = off) — avoids fleet thundering |
| `MONITOR_WATCH_ENABLED` | true | master switch for change-watch probes |
| `MONITOR_WATCH_PROBE_TIMEOUT_SECONDS` | 10 | per-probe timeout (git ls-remote / docker inspect) |
| `MONITOR_CONCURRENCY` | 2 | parallel target scans per tick (per-target DB sessions). **Clamped to 1 on SQLite** (single writer) — use Postgres for parallel fleet scans |

## 5. Ops runbook

```bash
docker compose up -d                      # starts api, worker, monitor, …
docker compose scale monitor=3            # HA: 3 replicas, one leader scans
curl $API/api/v1/monitor/status           # daemon_health.alive + targets
curl $API/api/v1/monitor/events?limit=50  # event feed (system of record)
curl -X POST $API/api/v1/monitor/targets/{id}/scan-now   # force one target now
curl $API/metrics | grep cryptoscan_monitor              # fleet metrics
```

Dev:

```bash
make monitor            # daemon (Ctrl+C stops; SIGTERM releases the lease)
make monitor-once       # single sweep (cron mode)
```

## 6. What is and isn't realtime

## 5. Target types

| Type | What it watches | Watch probe? | Default interval |
|---|---|---|---|
| `NETWORK` | TLS endpoints (cert posture, weak TLS, cert **expiry**) + optional IPsec/IKE + DNSSEC targets | no (interval) | 15 min |
| `CLOUD` | AWS/Azure/GCP crypto config | no (interval) | 6 h |
| `REPO` | source repo (git HEAD) | ✅ `git ls-remote` | daily |
| `CONTAINER` | image (local digest) | ✅ `docker inspect` | daily |
| `PAYMENT` | HSM audit / transaction feeds | no (interval) | hourly |
| `OT` | passive OT/ICS captures (new capture files) | ✅ capture-dir fingerprint | 15 min |
| `VENDOR` | vendor crypto posture (score + issues) | no (interval) | weekly |

`OT` targets point at a directory of passive captures (`{"path": "/var/log/ot",
"watch": true}`) — any new or modified capture (`*.log/.otlog/.pcap.txt/.jsonl/
.ndjson`) triggers an immediate passive re-scan. `VENDOR` targets score a vendor
(`{"name": "Acme HSM", "algorithms": ["DES"], "sensitive": ["PCI"]}`) through
the shared registry + quantum classifier; weak crypto surfaces as
`VENDOR_RISK`/`VENDOR_ISSUE` alerts.

## 6. Realtime event sources (SSE `/api/v1/events/stream`)

| Event | Triggered by | Live in |
|---|---|---|
| `monitor.change_detected` | watch probe found a change | monitor daemon |
| `monitor.scan_ok/degraded/alert` | every monitor target outcome | monitor daemon |
| `monitor.report_generated/skipped` | due compliance report schedules | monitor daemon (report sweep) |
| `scan.completed` | pipeline finishes a scan | worker pipeline |
| `drift.event` | new drift detected vs baseline | pipeline stage |
| `runtime.finding` | runtime agent ingests weak findings | API ingest |

## 7. Scheduled reports now actually run

`report_schedules` are executed **by the monitor daemon on every tick**: due
schedules render against the latest completed scan, snapshot, email, advance
`next_run_at`, and emit a `monitor.report_generated` / `monitor.report_skipped`
event. No completed scan yet → honest `SKIPPED_NO_SCAN` (stays due, runs the
moment a scan exists). Gate with `MONITOR_RUN_REPORTS` (default true).

## 8. Configuration (env / .env)

| Variable | Default | Meaning |
|---|---|---|
| `MONITOR_TICK_SECONDS` | 30 | daemon tick cadence (realtime feel: 15–30 s) |
| `MONITOR_LEASE_TTL_SECONDS` | 60 | leader-lease TTL (HA failover bound) |
| `MONITOR_JITTER_FRACTION` | 0.1 | random spread on `next_scan_at` (0 = off) — avoids fleet thundering |
| `MONITOR_WATCH_ENABLED` | true | master switch for change-watch probes |
| `MONITOR_WATCH_PROBE_TIMEOUT_SECONDS` | 10 | per-probe timeout (git ls-remote / docker inspect / dir walk) |
| `MONITOR_CONCURRENCY` | 2 | parallel target scans per tick (per-target DB sessions). **Clamped to 1 on SQLite** (single writer) — use Postgres for parallel fleet scans |
| `MONITOR_RUN_REPORTS` | true | execute due compliance report schedules each tick |

## 9. Ops runbook

```bash
docker compose up -d                      # starts api, worker, monitor, …
docker compose scale monitor=3            # HA: 3 replicas, one leader scans
curl $API/api/v1/monitor/status           # daemon_health.alive + targets
curl $API/api/v1/monitor/events?limit=50  # event feed (system of record)
curl -X POST $API/api/v1/monitor/targets/{id}/scan-now   # force one target now
curl $API/metrics | grep cryptoscan_monitor              # fleet metrics
```

Dev:

```bash
make monitor            # daemon (Ctrl+C stops; SIGTERM releases the lease)
make monitor-once       # single sweep (cron mode)
```

## 10. What is and isn't realtime

| Signal | Latency | Source |
|---|---|---|
| git push / image change / new OT capture → rescan | ≤ 1 tick (`MONITOR_TICK_SECONDS`) | watch probe |
| CHANGE_DETECTED → SSE Live events | ≤ 1 tick + tailer (2 s) | DB tailer → bus |
| drift detected vs baseline → SSE | immediate (pipeline) | `drift.event` |
| runtime agent weak finding → SSE | immediate (ingest) | `runtime.finding` |
| due compliance report → generated/emailed | ≤ 1 tick | report sweep |
| new TLS endpoint issue / cert expiry → SIEM alert | ≤ interval (default 15 min) | network runner + alert sinks |
| cloud account drift | ≤ 6 h interval (no cheap fingerprint probe yet) | cloud runner |

Registry digest watch without a local docker CLI is reported unsupported
(honest), and cloud/network/vendor types have no fingerprint probe yet — they
are interval-scanned. That is the documented boundary of the realtime layer.

---

## 11. Enterprise crypto surface — network + cloud coverage

A full-part audit of the crypto attack surface, and what scans it today.
Everything below is wired into the same monitor/cloud flows as the rest —
no parallel watchers.

### 11.1 Network coverage

| Layer | Scanner | Status |
|---|---|---|
| TLS | certificates, ciphers, versions, renegotiation, revocation (live OCSP/CRL) | ✅ |
| SSH | host keys, TOFU drift, KEXINIT algorithm offer | ✅ |
| STARTTLS | smtp / imap / pop3 / ftp / ldap / postgresql | ✅ |
| **IPsec / IKE VPN** | `network_scanner.probing.ipsec_probe` — one IKEv2 `SA_INIT` (UDP 500/4500), parses accepted SA proposals, flags weak transforms | ✅ **new** |
| **DNSSEC posture** | `network_scanner.discovery.dnssec_checker` — signing status (DNSKEY/DS), weak algorithms & RSA key sizes, open zone transfer (AXFR over TCP) | ✅ **new** |
| Subnet sweep | `subnet_discoverer` now sweeps the enterprise crypto port set: 443, 8443, 25, 465, 587, 143, 993, 110, 995, 21, 990, 636, 989, 22, 3269 | ✅ **widened** |
| Discovery | DNS / Kubernetes / service-mesh discovery, passive Envoy + Istio logs, cert inventory + expiry alerts | ✅ |

**IPsec probe semantics** — active opt-in only (never probed implicitly by TLS
scans): one UDP packet, no handshake, no key exchange. Classifies per proposal:

- `WEAK_IKE_ENCRYPTION:<name>` — DES / 3DES
- `WEAK_IKE_MAC:<name>` — HMAC-MD5 / HMAC-SHA1
- `WEAK_IKE_DH_GROUP:<name>` — MODP < 2048 (groups 1, 2, 5)
- `IKE_NO_PFS` — no DH-group transform in the proposal

**DNSSEC checker semantics** — raw-socket DNS (stdlib only); resolver from
config → `CRYPTOSCAN_DNS_RESOLVER` → `/etc/resolv.conf` (never a hardcoded
third-party resolver); `host:port` supported. Statuses `SIGNED` / `UNSIGNED` /
`NO_ZONE` / `UNKNOWN` / `ERROR`; issues `UNSIGNED_ZONE`,
`WEAK_DNSSEC_ALGORITHM:<algo>`, `WEAK_DNSSEC_KEY_SIZE:<bits>`,
`ZONE_TRANSFER_EXPOSED`.

**CLI**

```bash
python -m network_scanner.main --ipsec vpn-gw.example.com --ike-ports 500,4500
python -m network_scanner.main --dnssec example.com --resolver 10.0.0.53:53
python -m network_scanner.main --discover 10.0.0.0/24 --scan   # widened port set
```

### 11.2 Monitor configuration (NETWORK targets)

```json
{ "endpoints": ["api.example.com:443"],
  "ipsec": ["vpn-gw.example.com"],            // optional IKE probe hosts
  "ike_ports": "500,4500",                    // optional UDP ports
  "dnssec": ["example.com"],                  // optional zones
  "dns_resolver": "10.0.0.53:53",             // optional resolver for --dnssec
  "check_zone_transfer": true,                // default true; disable for loud public resolvers
  "expiry_alert_days": 30 }
```

Weak IKE / unsigned zones / open transfers surface as
`WEAK_*:<endpoint>` / `UNSIGNED_ZONE` / `ZONE_TRANSFER_EXPOSED` issues in the
same degraded→alert path as TLS issues.

### 11.3 Cloud coverage (live `CRYPTOSCAN_CLOUD_LIVE=1`)

| Provider | Services scanned | Added |
|---|---|---|
| AWS | kms, s3, rds, elbv2, acm, cloudfront, secretsmanager, lambda, apigateway, ec2/ebs, ssm, dynamodb, sqs, sns, opensearch, eks, redshift, **route53 (DNSSEC signing + KSK KMS), ecr (encryption + scan-on-push), efs (at-rest + KMS), cloudhsmv2 (cluster state)** | +4 |
| Azure | keyvault (+keys), storage, sql (TDE), app_gateway, frontdoor, cosmosdb, redis, servicebus, **app_service (min TLS / HTTPS-only / client certs), dns (DNSSEC), acr (CMK + quarantine/trust), vpn_gateway (IKE version + IPsec policies per connection), managed_hsm (purge/soft-delete/security domain)** | +5 |
| GCP | cloud_kms, gcs, cloud_sql, load_balancer, secret_manager, pubsub, gke, **cloud_dns (DNSSEC state + key algorithms), memorystore (transit encryption + auth), cloud_run (CMEK + revocation action)** | +3 |
| IaC | terraform, cloudformation, kubernetes, arm | ✅ |

Each provider flow keeps the reliability contract: paginated listing with
recorded truncation, throttling retries, per-service error telemetry, and
fail-open only when the SDK/credentials are absent (recorded, never silent).
New scanners follow the injected-client pattern so unit tests run without
cloud SDKs (see `services/cloud_scanner/tests/test_cloud_enterprise_scanners.py`).

### 11.4 Honest boundaries

- IPsec probing requires the responder to answer `SA_INIT`; silent gateways
  report `NO_RESPONSE` (never a fabricated weak finding).
- Zone-transfer checks can be turned off (`check_zone_transfer: false`) where
  the resolver policy forbids AXFR probes.
- Cloud live scans need real credentials; without them the provider is
  recorded as an error in telemetry, not silently skipped.

### 11.5 Global network discovery (enterprise pipeline)

`config.scope` on a NETWORK target runs the full global-discovery pipeline
each tick — target expansion → active/vendor/passive discovery → asset
registry → protocol detection → dependency graph → TLS + certificate
intelligence → PQC network readiness → migration simulation → blast radius →
geographic exposure:

```json
{ "scope": ["10.0.0.0/24", "*.corp.example.com", "10.1.2.3-10.1.2.9"],
  "scan_mode": "SAFE",            // SAFE|STANDARD|DEEP|AGGRESSIVE (default SAFE)
  "authorization_scope": "",      // REQUIRED for DEEP/AGGRESSIVE
  "plugins": ["snmp", "cisco"] }  // vendor plugins to run (default snmp,cisco)
```

Scope specifiers: CIDR / IPv4-IPv6 ranges / single IPs / hostnames / domains /
`*.sub.example.com` subdomain wildcards / internal DNS zones / DC-branch-VPN-
MPLS-SD-WAN networks / cloud VPC-VNet / Kubernetes clusters (structured dicts:
`{"kind": "data_center", "name": "Dubai-DC", "networks": ["10.10.0.0/16"]}`).

Discovery findings (weak TLS, PSK-only tunnels, PQC migration blockers,
probe errors) surface as issues in the same degraded→alert path. The monitor
summary gains `scope.assets` / `scope.observations` /
`scope.pqc_migration_required`.

The same pipeline runs on demand from the CLI:

```bash
python -m network_scanner.main --scope 10.0.0.0/24 --scope '*.corp.example.com' \
    --mode safe --plugin snmp --plugin cisco -o discovery.json
```

SAFE is the enterprise default: low concurrency, no UDP handshake-init
probes (IKE/WireGuard/OpenVPN/DTLS), no credentialed access. DEEP/AGGRESSIVE
raise unless an authorization scope is supplied. Credentials are vault
references only — scan records never contain router passwords, SNMP
communities, API tokens or private keys (enforced by the scrub contract and
its tests).
