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

| Signal | Latency | Source |
|---|---|---|
| git push / image change → rescan | ≤ 1 tick (`MONITOR_TICK_SECONDS`) | watch probe |
| CHANGE_DETECTED → SSE Live events | ≤ 1 tick + tailer (2 s) | DB tailer → bus |
| new TLS endpoint issue → SIEM alert | ≤ interval (default 15 min) | network runner + alert sinks |
| cloud account drift | ≤ 6 h interval (change-watch n/a — no cheap probe yet) | cloud runner |

Registry digest watch without a local docker CLI is reported unsupported
(honest), and cloud/network types have no fingerprint probe yet — they are
interval-scanned. That is the documented boundary of the realtime layer.
