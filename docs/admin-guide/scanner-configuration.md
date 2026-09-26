# Scanner configuration (worker environment)

All flags are read by the scanner library inside the **worker** process (and by the CLI). Set them in the
worker's environment (`docker-compose.yml` → `worker.environment`, systemd unit, or Helm values).

| Variable | Default | Effect | Production guidance |
|---|---|---|---|
| `CRYPTOSCAN_SCAN_PROCESSES` | `1` | per-file process pool inside one scan (`auto` = cores) | `CRYPTOSCAN_SCAN_PROCESSES × worker max_workers ≤ cores`; 2 cores gave 1.82× on a 3 MLOC tree (`docs/scale/`) |
| `CRYPTOSCAN_EXCLUDE_TESTS` | unset (tests scanned, tagged `code_origin=test`) | `1` drops test directories entirely | leave unset: inventory keeps everything, triage views filter on `code_origin` |
| `SCANNER_EXCLUDE_DIRS` | — | comma list of extra directories to skip (additive to defaults) | vendored SDK dumps, generated protobuf trees |
| `CRYPTOSCAN_CASCADE` | `1` | dependency & cascade analysis after every scan (providers, waves, libraries, shared keys, weak sizes, systems) — [CASCADE-ANALYSIS.md](../accuracy/CASCADE-ANALYSIS.md) | keep on; adds ≈ 2 s per 1 000 files; report persisted in `Scan.statistics.cascade`, served by `GET /api/v1/scans/{id}/cascade` |
| `CRYPTOSCAN_RUNTIME_LOGS` | unset | `1` also scans `.log/.trc/.audit/.syslog` as runtime evidence (ICSF SMF-82, RACDCERT, payShield, JSSE, openssl, nginx, sshd, AT-TLS) — [RUNTIME-EVIDENCE.md](../runtime/RUNTIME-EVIDENCE.md) | off for source repos; on for the dedicated log-drop repository/share |
| `CRYPTOSCAN_KEY_INVENTORY` | unset | `1` also ingests HSM / KMS / keystore / certificate exports (content-sniffed `.txt/.lst/.out/.json/.csv/.rpt/.prt/.list/.dump`) — [KEY-INVENTORY.md](../accuracy/KEY-INVENTORY.md) | off for source repos; on for the key-export drop |
| `JOB_LEASE_TTL_SECONDS` / `JOB_MAX_REDELIVERIES` / `JOB_RUNNING_TIMEOUT_MINUTES` / `JOB_QUEUED_TIMEOUT_MINUTES` | 60 / 3 / 240 / 30 | at-least-once queue and reaper — [runbooks/job-queue.md](../runbooks/job-queue.md) | defaults; drill with `scripts/queue_kill9_drill.py` |

## Recommended layout for a bank estate

Three kinds of scan targets, each its own repository/share and worker profile:

1. **Source repositories** (the normal case): defaults. Add `cryptoscan-systems.yml` at each repo root
   (or in a monorepo) mapping paths to CMDB ids so the cascade rolls up to business systems.
2. **Evidence drop — runtime logs**: a share or repo where the bank lands ICSF / RACF / payShield /
   web-server / sshd logs. Worker profile with `CRYPTOSCAN_RUNTIME_LOGS=1`. Reconcile with
   `scripts/ingest_runtime_logs.py <drop> --source <repo>`.
3. **Evidence drop — key & certificate exports**: KGUP/CSFKDSL listings, TR-31 exports, `cmu`/`nfkminfo`
   output, cloud KMS JSON, `keytool -list -v`, RACDCERT LIST, certificate CSVs. Worker profile with
   `CRYPTOSCAN_KEY_INVENTORY=1`. Reconcile with `scripts/ingest_key_inventory.py <drop> --source <repo>`.

Findings from 2 and 3 carry `source.type = RUNTIME_LOG` / `KEY_INVENTORY` and flow through the same
evidence chain, CBOM, policy and alerting as code findings.

## Sizing reminders

* Scan throughput ≈ 18.5 kLOC/s per core on real repositories; a 10 MLOC monorepo ≈ 2.3 min on 4 cores.
* API ≈ 180 authenticated DB-backed requests/s per uvicorn worker (`docs/load-soak.md`).
* Archives up to 200 MB are opened; runtime logs above 200 MB and inventories above 100 MB are skipped with a warning.
