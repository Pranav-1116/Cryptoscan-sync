# Execution controls — scoped engineering evidence (2026-10-21)

**Decision: ENGINEERING PASS FOR TESTED CONTRACTS; FULL P0 ACCEPTANCE INCOMPLETE.**

Source: working branch `arena/bb4b80dd-cryproscan`, increment atop `4a20b72b`;
publication commit is recorded on PR 34. This report does not replace the
[root readiness gate](../../PRODUCTION-READINESS.md) or its retained historical
FAIL/SKIP results. No deployed bank, Docker runtime or PostgreSQL cluster was
qualified in this sandbox.

## Results and ordering

| Run | Result | Scope/ordering |
|---|---|---|
| Broad regression | **1323 passed, 17 skipped, 8 deselected, 140 warnings; 387.95 s** | Worker/database suites plus governance, queue, supply-chain, admission, trigger-write and SSH contracts; preceded final session-incarnation/database-clock refinements |
| Final changed-path acceptance | **295 passed, 1 skipped, 65 warnings; 81.36 s** | Current source after those refinements: controls, auth lifecycle, production hardening, replay Redis security, queued authority, scan admission, trigger failure, direct/SSH admission, source isolation/staging, pool/reaper behavior, user repository, migration/index parity and production DB gate |
| Final scoped docs/schema check | **11 Markdown files, 298 relative links, 1 heading anchor, 3 embedded Bash blocks; no errors** | 857 paths / 947 operations / 104 groups; schema route equality and generator idempotence PASS; Ruff F/E9 and whitespace PASS; not runtime qualification |

Counts overlap; **do not add them**. Warnings include existing Pydantic/Starlette
and Alembic deprecations. The broad run also records blocked outbound socket
attempts in legacy integration fixtures; those were hermetic failure-path tests,
not successful live GitHub/customer scans. Skips/deselections are not PASS.

## Tested contracts

- Actual HTTP session/API-key authentication plus selected-estate middleware,
  real SQL approval/policy/outbox records and publication boundaries.
- No positive grant, overlap, expiry, revocation, changed policy, current role,
  membership, credential/session revocation or wrong execution/evidence
  destination means no controlled execution. Forged queue descriptors cannot
  mutate a victim job or select a foreign owner/target/options.
- Session records bind the original user UUID. Replacement usernames cannot
  inherit an existing session; migration leaves old session incarnation NULL,
  requiring fresh login rather than guessed backfill. API keys bind original
  ID and verifier/policy digest, not reusable display name.
- SQL-shared estate/provider reservations and approval launch allowance;
  eight independent SQLite sessions contend for one slot/request without
  overbooking. A fast worker wall clock cannot reset the server-clock window.
- Durable estate scheduling turns, FIFO within estate, five-second capacity/
  fairness backoff and no FAILED stamp for a deferred queued job.
- Shared global stop and estate policy changes reject new/live checkpoints
  without releasing in-flight reservations. Same-region incident history remains
  accessible; private history is refused from a mismatched declared destination.
- Durable attempt fence/deadline, UNKNOWN state after ambiguous/missing completion,
  no RUNNING restart, once-only audited operator settlement, late-worker refusal
  and no retry of an unsettled job. A truthy collector without matching committed
  completed job/scan receipt is not success.
- Outbox transport failure and published-but-acknowledgment-lost simulation;
  replay can duplicate publication, but QUEUED-only SQL claim refuses a second
  execution. No SQL/Redis transaction or exactly-once effect claim.
- Local descriptor-relative staging rejects symlinks, directory links, hardlinks,
  FIFO, file/total/entry/depth overrun and source path-component links; refused
  input is removed without deleting pre-existing destination/source data.
- Strict workspace cleanup does not swallow removal failure. Real Python child
  process is killed after a denied launcher poll in the local timing test;
  **this is not a Docker container termination test**.
- Existing launcher command/protocol/no-secret/no-inline-fallback guards;
  controlled protocol rejects unusable absolute deadlines and caps the child
  watchdog by remaining approval time. Runtime responses/collectors in contract
  tests are doubles, not image attestation or escape-resistance evidence.
- Unsupported API/monitor paths refuse before collection; unreviewed WebSockets
  close with 1008. SQL ownership register explicitly reports unreviewed stores,
  never automatic legacy-NULL declassification.
- `0101 → 0102 → 0101` migration round-trip, legacy RUNNING/NULL-owner preservation,
  no implicit grants, no session-user-ID backfill, model/migration index parity.

## Reproducing the final acceptance run

Use an isolated development/test database environment, not bank production data.
The following assumes pytest and repository dependencies are already installed;
replace `python` with the deployment's approved test interpreter as appropriate.

```bash
export ENVIRONMENT=test
unset CRYPTOSCAN_EXECUTION_CONTROLS
export DATABASE_URL="sqlite:///$(mktemp -d)/controls-tests.db"
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):services/api/tests/unit"
python -m pytest -q \
  services/api/tests/unit/test_execution_controls.py \
  services/api/tests/unit/test_queue_authority_contract.py \
  services/api/tests/unit/test_auth_account_lifecycle.py \
  services/api/tests/unit/test_auth_lifecycle.py \
  services/api/tests/unit/test_multiuser_auth.py \
  services/api/tests/unit/test_production_hardening.py \
  services/api/tests/unit/test_replay_redis_security.py \
  services/api/tests/unit/test_scan_admission.py \
  services/api/tests/unit/test_trigger_write_failures.py \
  services/api/tests/unit/test_direct_scanner_admission.py \
  services/api/tests/unit/test_ssh_receipt_contract.py \
  services/worker/tests/unit/test_controlled_source.py \
  services/worker/tests/unit/test_static_scan_isolation.py \
  services/worker/tests/unit/test_worker_pool.py \
  services/worker/tests/unit/test_job_path_hardening.py \
  services/database/tests/unit/test_user_repository.py \
  services/database/tests/unit/test_execution_control_migration.py \
  services/database/tests/unit/test_execution_budget_concurrency.py \
  services/database/tests/unit/test_model_migration_index_parity.py \
  services/database/tests/unit/test_production_database_gate.py
```

## Acceptance not supplied by these tests

**Local source is the only controlled adapter.** There is no newly provisioned
approved Docker image/daemon, real container escape/egress/credential test, real
PostgreSQL multi-replica contention, Redis crash/partition recovery, restore or
regional failback run, physical residency attestation, full ownership/retention
review, hard emergency-stop SLO or customer approval artifact. Unqualified
remote/network/cloud/container/binary/import/report/monitor/realtime/export/
notification consumers are refused in the production profile, not declared done.
Standalone development collector scripts are not approved production entry points.

See the [upgrade and remaining acceptance matrix](../runbooks/controlled-execution-upgrade.md)
and [API examples](../api-reference/controlled-execution.md). **Do not close the
entire 2.1–2.6 backlog or claim bank production readiness from this report.**
