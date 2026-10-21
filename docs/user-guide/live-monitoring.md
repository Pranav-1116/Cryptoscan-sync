# Live monitoring (24/7)

CryptoScan runs as a continuous monitor, not just an on-demand scanner: a
daemon keeps a **watch list** of targets and re-scans each on its interval
through the same live scanners the manual flows use.

```
scripts/run_monitor.py            # daemon, runs until stopped
scripts/run_monitor.py --once     # single sweep (cron mode)
```

## What can be watched

| Type | Scans with | Needs | Default interval |
|---|---|---|---|
| `NETWORK` | live TLS probe (versions, ciphers, certs, policy issues) | nothing but reachability | 15 min |
| `CLOUD` | `CloudScanner.scan_live` (KMS/S3/RDS/ALB/ACM …) | provider credentials in the environment + account config | 6 h |
| `REPO` | the full scan pipeline (queued as a job) | worker running | daily |
| `CONTAINER` | container image scan (packages, CVEs, secrets) | image reference reachable/available | daily |

Certificates found by network probes feed the shared certificate inventory —
identical data to `POST /network-scans`.

## Managing the watch list

API (`/api/v1/monitor/*`) or the dashboard's **Live monitor** view (5 s
auto-refresh):

```bash
curl -X POST $API/api/v1/monitor/targets -H "Authorization: Bearer $T" \\
  -H 'Content-Type: application/json' -d '{
    "name": "Payments edge",
    "target_type": "NETWORK",
    "config": {"endpoints": ["api.bank.example:443", "mtls.bank.example:8443"]},
    "interval_seconds": 900}'
```

**Telecom estates** (`target_type: "TELECOM"`, default 15 min): the daemon
re-probes the registered 3GPP NF estate through the same engine as
`POST /telecom/scan` — verdicts, events and the snapshot refresh continuously
instead of only on manual scans. Optional config: `{"carrier": "de-telekom"}`
(one operator's NFs), `{"nf_ids": ["amf-01", "sepp-01"]}`, `{"timeout": 3.0}`.
With no registered estate the target shows BLOCKED with the fix — never a
fabricated pass.

**Docker:** the `api` and `monitor` services share a `telecom_data` volume
(`CRYPTOSCAN_SNAPSHOT_DIR=/var/lib/cryptoscan/telecom`), so daemon-written
passes appear in the API (and on SSE via the snapshot tailer) without a
restart. Provision the estate by placing `config/telecom_registry.json`
next to `docker-compose.yml` (override the host path with
`TELECOM_REGISTRY_HOST_PATH`); an absent file means TELECOM targets show
BLOCKED with the fix — never a fabricated pass.

`PATCH …/{id}` pauses/resumes or changes the interval, `DELETE` removes,
`POST …/{id}/scan-now` runs one target immediately (synchronous live probe),
`GET /monitor/status` is the live picture (counts by status/type, what needs
attention, recent events), `GET /monitor/events` is the full feed.

## 24/7 behavior (what the loop guarantees)

- **The tick never dies.** Per-target failures are recorded, not raised; the
  daemon opens a fresh DB session every tick so a dropped connection heals.
- **Backoff.** Each failure doubles the retry delay (interval × 2^failures,
  capped at 24 h) — a dead endpoint cannot hammer the network every 30 s.
  One failure → `DEGRADED`; two consecutive → `FAILING`.
- **Alert once, not every cycle.** An `ALERT` event fires only when a scan
  shows an issue the previous summary didn't have. If the issue clears and
  returns, it alerts again.
- **BLOCKED is honest.** A target that cannot be scanned (cloud without
  credentials, empty config, unknown type) is reported `BLOCKED` with the
  exact reason — never silently skipped or faked as clean.
- **Every outcome is an event** (`SCAN_OK`, `SCAN_DEGRADED`, `SCAN_FAILED`,
  `BLOCKED`, `ALERT`) on `monitor_events`, with the target's rolling summary
  on the target row.

## Bank-style deployment

`/etc/systemd/system/cryptoscan-monitor.service`:

```ini
[Unit]
Description=CryptoScan live monitor
After=network-online.target postgresql.service

[Service]
User=cryptoscan
WorkingDirectory=/opt/cryptoscan
Environment=DATABASE_URL=postgresql://cryptoscan:***@localhost/cryptoscan
EnvironmentFile=/etc/cryptoscan/monitor.env
ExecStart=/opt/cryptoscan/.venv/bin/python scripts/run_monitor.py --tick-seconds 30
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`Restart=always` covers process death; the loop itself already survives
target failures and DB blips. Pair with the existing alerting
(drift webhooks, expiry dispatch) for paging, and `GET /monitor/status` for a
SOC wallboard (the dashboard view polls it every 5 s).

**Honest scope:** the monitor re-scans on intervals and records live
state — it is not a packet-capture IDS. For passive traffic observation of
production TLS handshakes, deploy the runtime TLS tap
(`services/runtime/README.md`) and ingest via `/runtime` findings.

## Repository monitor authority

Repository monitor jobs now persist `MONITOR_REPOSITORY` provenance and pin the
owned enabled repository configuration. The worker rechecks that configuration,
active estate and descriptor before collection; the literal actor name `monitor`
is not a human-user privilege bypass. Legacy unpinned work must be approved and
resubmitted. Recovery of a queue delivery does not rerun an already RUNNING job.
See [execution/replay upgrade](../runbooks/execution-and-replay-upgrade.md).

Event history for the selected estate uses opaque retained replay cursors, not a
global numeric offset. Primary/process changes require explicit resynchronization;
see [the realtime guide](realtime.md).
