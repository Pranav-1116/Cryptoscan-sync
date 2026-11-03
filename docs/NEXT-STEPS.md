# What to do next (reconciled 2026-09-27)

**2026-10-21 priority update:** persisted queue authority and SSH receipts are
implemented; do not plan them as wholly absent. Next qualify coordinated legacy
resubmission, crash/unknown-side-effect recovery, original request provenance,
positive regional grants and distributed budgets. Redis TLS/ACL/Sentinel is
locally exercised for realtime/current-run clients; other consumers and deployed
CA/partition/load/restore evidence remain open. Start with the
[upgrade runbook](runbooks/execution-and-replay-upgrade.md) and
[qualification checklist](bank-environment/45-redis-tls-sentinel-qualification.md).

The current deployment decision is owned by the root
[`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) and the generated
`docs/readiness-evidence/bank-readiness.{json,md}`. The accuracy page
[`accuracy/BANK-READINESS.md`](accuracy/BANK-READINESS.md) remains detector and
synthetic-estate evidence; its figures are not a production approval.

The work below is ordered by the evidence or engineering change that closes a
real gate. Historical percentages are intentionally not repeated here.

Everything below is ordered by what raises the pilot number the most for the least effort.

> **2026-10-16 reconciliation note:** the engineering-side §4/§5 gap closures of
> rounds 50–79 (isolation bounds, identity spine, snapshot diffing, per-record
> verification surfaces, notification delivery, independent health probes) are
> recorded in [`audit_reports/00_ROUND_STATUS.md`](../audit_reports/00_ROUND_STATUS.md)
> and [`PRODUCT-VISION-AND-GAPS.md`](../PRODUCT-VISION-AND-GAPS.md); the items
> below remain the bank-feedback and discovery work that no source session can
> close on its own.
Items marked **[target host]** cannot be executed in the development sandbox (no Docker, Redis,
PostgreSQL binaries, no IdP, no outbound access beyond github/npm/pypi) and need a bank-side or
company-side machine.

---

## 1. First bank feedback loop (the only thing that turns 95 % into a bank's number)

1. Run the triage workbook on the bank's first repo set (payments switch, mobile channel, ICSF COBOL):
   `python scripts/bank_triage.py workbook --repo <path> --out review.xlsx`
2. Have the bank's crypto owner mark each row TP / FP / MISS and fill the candidate-miss sheet.
3. Score it back: `python scripts/bank_triage.py score review.xlsx` → precision / recall + corpus skeletons.
4. Turn every confirmed MISS into a corpus file + rule (same loop used for waves 1–15), re-run
   `scripts/accuracy_benchmark.py` (must stay 100 %) and the blind-wave protocol.
5. Record the bank's first-pass numbers in `docs/accuracy/EXTERNAL-VALIDATION.md` (round 24+).

Success criterion: first-pass precision ≥ 0.95 and recall ≥ 0.95 on the bank's own code, not ours.

## 2. Discovery — remaining known gaps (sandbox-buildable)

| Gap | Where it shows up | Plan |
|---|---|---|
| HLASM ICSF macros other than CALL/LINK verbs (e.g. `CSFxxx` macro forms, `ICSF` ROUTINES via `SVC`) | bank assembler libraries | extend `hlasm_parser` rule table; corpus files first |
| R8 / DexGuard string-encrypted DEX | production Android apps | fall back to class-reference-only findings (algorithm UNKNOWN, api known) with a `reason=string_encryption_suspected` flag when the string table has < N printable crypto literals but the crypto classes are present |
| Swift generics with no mangled CryptoKit names | iOS apps | add `__swift5_typeref` / `__objc_classname` section scanning for `CryptoKit`, `CommonCrypto` module refs |
| Real IPA validation | — | obtain 3–5 open-source iOS builds (need egress or a hand-copied file) and record a round in EXTERNAL-VALIDATION |
| Runtime logs — bank samples | ICSF SMF-82, RACDCERT, payShield audit | parsers are fixture-only; first real log drop → recheck field layouts (SMF-82 subtypes 18/31/40/44 record lengths in particular) |
| Cross-file hop beyond constants | Java/.NET config-driven algorithm names (`application.yml`, `web.config`, Spring `@Value`) | resolve `@Value("${crypto.alg}")` and `.properties` keys with MEDIUM confidence; corpus first |
| Legacy 4GL/TAL/SAS positives are corpus-only | Progress ABL, PowerBuilder, TAL, SAS | same as item 1 — needs bank code |

Rule of the house: no new rule without a corpus file, benchmark stays 100 %, blind wave before merge,
CRC/FNV/djb2/xxHash/murmur/adler never reported, comments never count.

## 2a. Key inventory — first real drops

- Parse the first real KGUP / CSFKDSL listing, payShield key export, Luna `cmu` output and cloud KMS
  dump from a bank; adjust field layouts (parsers are keyword-based on purpose).
- Add: Futurex / Atalla / Marvell listings, Venafi API JSON, Windows CNG `certutil -store`, macOS keychain,
  Kubernetes TLS secrets metadata, OpenSSH `authorized_keys`/host keys (algorithm + bits).
- Database encryption state: `SELECT` scripts for Oracle TDE, SQL Server TDE / Always Encrypted,
  PostgreSQL pgcrypto usage, MongoDB CSFLE — ingested the same way (bank runs the query, drops the CSV).

## 2b. Cascade analysis — deepen (sandbox-buildable)

- Call-level edges for Java/C#/Python where a file imports a provider: confirm the provider's crypto method
  is actually invoked (cuts over-approximation of blast radius).
- Follow JCL `EXEC PGM=`, CICS `LINK/XCTL PROGRAM(...)`, IMS PSB and Spring/CDI bean names as edges.
- Push the `systems` roll-up (now produced from `cryptoscan-systems.yml`) into the API's system graph
  (`api/graph_builder.py`, `/reachability/blast-radius`) so it appears in the UI with SLAs and owners.
- Certificate ↔ service cascade from runtime evidence (RACDCERT labels, keyrings, nginx `ssl_certificate`).

## 3. Pipeline — evidence still missing

- **[target host]** `REDIS_URL=… python scripts/queue_kill9_drill.py` against real Redis; attach the JSON to `docs/readiness-evidence/` and rerun `scripts/bank_readiness.py` (the `--fake` self-check passed here).
- **[target host]** 7-day soak with PostgreSQL + Redis, 2+ workers, one real 5–10 MLOC monorepo; watch API RSS (158 → 181 MB over 120 k requests here — confirm it plateaus) and queue depth.
- Multi-worker (not multi-process) throughput evidence: two `worker` containers on one queue, same 3 MLOC synthetic tree (`scripts/scale_evidence.py`), expect ~1.8× as with the in-process pool.
- API: run `scripts/load_test.py --identity api-keys` behind 2–4 uvicorn workers + PostgreSQL to confirm the ~180 rps/worker figure scales linearly; then set the documented sizing.
- Fix the pre-existing sandbox failure `services/api/tests/unit/test_artifact_tenancy_api.py` (5 failures independent of this branch) or confirm it passes on PostgreSQL.

## 4. Bank operating requirements (all **[target host]** or company actions)

1. HA drill with `deploy/ha/`: kill the active API and the active worker during a scan; expect zero lost jobs (queue drill) and < 30 s API unavailability. Record in `docs/runbooks/`.
2. SSO/SAML GA: integration test against the bank's IdP (ADFS / Entra / Ping); group→role mapping, SLO, clock-skew and signed-assertion negative tests.
3. ITSM / SIEM connectors: ServiceNow incident on policy breach, Splunk/QRadar CEF export of findings + audit chain; smoke against a sandbox tenant.
4. Air-gap **update** drill: build bundle on connected host → verify signature → apply on disconnected host → DB migration → rollback. Install and logical backup/restore drills already ran once; the update drill
   has not. PITR was never a platform capability — a `pg_dump` artifact cannot be
   replayed to a point — so a real PITR drill needs the bank to operate the
   physical base backup and WAL archive first.
5. Product's own SBOM + SOC 2 / pen-test scheduling — company action.

## 5. Housekeeping

- Do **not** push CI/CD workflow changes from this branch (standing instruction).
- Keep the generated `docs/readiness-evidence/bank-readiness.{json,md}` and the
  scoped accuracy documents consistent; use root `PRODUCTION-READINESS.md` as
  the current decision, not historical percentage documents.
- Sandbox restarts wipe `.venv` and unpushed work — commit and push after every green step.

## Quick commands

```bash
export PYTHONPATH="$(for d in shared/*/ services/*/; do printf '%s%s:' "$PWD/" "$d"; done)"
.venv/bin/python scripts/accuracy_benchmark.py 2>/dev/null | grep -v "\[debug" | grep OVERALL   # must be 748/748
cd services/scanner && PYTHONPATH=.:../../shared/shared_models ../../.venv/bin/python -m pytest tests -q
.venv/bin/python scripts/queue_kill9_drill.py --fake
.venv/bin/python scripts/load_test.py --identity api-keys --rps-per-user 8 --users 20 --duration 30
```
