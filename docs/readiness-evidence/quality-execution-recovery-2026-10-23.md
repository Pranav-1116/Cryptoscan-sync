# Engineering evidence — interruption, duplicate delivery and durable UNKNOWN

**Date:** 2026-10-23 UTC

**Branch:** `arena/bb4b80dd-cryproscan`

**Original validation status:** bounded working-tree implementation and local validation; no new published commit at that capture, signed release, production drill or customer acceptance. See the publication follow-up below.

[Implementation ledger](../product-improvement/IMPLEMENTATION-STATUS.md#6-fourth-increment--interruption-duplicate-delivery-and-durable-unknown) · [Operator queue/reconciliation procedure](../runbooks/job-queue.md)

## Publication follow-up

The original capture below was a working-tree-only validation. On the user's
subsequent request, this fourth increment is bundled with the [fifth parser-runtime
increment](quality-parser-runtime-2026-10-23.md) for publication to the same PR
branch using `[skip ci]`. Original counts, failures, source hashes and scope below
remain unchanged. The later record documents index/branch reconciliation without
working-file changes; Git history/PR comment identify the containing publication.

## 1. Scope and source provenance

This is the fourth quality-only increment, following the previously published coverage/package-identity/authority corrections. The earlier three dated engineering records remain unchanged. Their published source/test claims are historical, not reruns of this increment.

The supplied checkout already contained accumulated changes at task start; the local Git base was `d70bdf3`. At the original validation capture this increment had not reset, staged, committed, pushed or rewritten that accumulated work. Historical documentation identifies prior published implementation `2fd8fc8f` and subsequent documentation commits; those are not presented as the newly tested source identity. The content hashes below identify this increment's actual tested files. Before-change copies and hashes were retained outside the repository for incremental review.

Five implementation files change: worker pool, executor, consumer, reaper, and API dependency factory. Three new test modules add **35 cases**. No new collector/service/route, architecture/profile, native binary, dependency lock, schema migration or workflow edit is introduced by this increment. Current schema head remains 0105.

Existing exact-estate authority/CAS, bounded execution, immutable historical evidence, independent exact-condition verification and the six distinct BOM contracts are retained. Local thread availability is not an execution reservation; Redis delivery is not execution authority; UNKNOWN is not proof of external stop.

## 2. Baseline and actual adverse reproductions

The selected existing execution/queue/job-path/pool/budget suites passed **88 tests**, 4 warnings, **23.16 s**, exit 0 before changing implementation.

The first new two-module set had **11 failed / 13 passed**, 4 warnings, **9.84 s**, exit 1. The 13 initially passing cases are compatibility/invariant checks, not newly reproduced defects.

| Reproduced boundary | Before | Bounded correction |
|---|---|---|
| Interruption during execution | KeyboardInterrupt, SystemExit and CancelledError escaped a Future but left pool active/failed/completed accounting inconsistent; saturation could remain true | End local accounting in `finally` while preserving interruption propagation; do not release durable reservations |
| Interruption during submission | A separate three-case set reproduced **3 failures / 6 deselected**, 0.21 s: an interrupt after semaphore acquisition leaked a local slot | Release that slot on BaseException and re-raise; a job never submitted is not counted as executed |
| Failure to persist interrupted outcome | An OSError during best-effort `finish_attempt(False)` replaced the original KeyboardInterrupt/SystemExit/RuntimeError | Emit safe failure category, preserve original interruption and leave SQL deadline recovery responsible for unresolved state |
| Non-durable publication acknowledged | `enqueue` put work into a memory queue after Redis failure even when memory fallback was disabled; outbox could mark it PUBLISHED | Raise when fallback is disabled; outbox returns/remains PENDING and retries. Explicit development fallback remains available |
| Dead-letter exhaustion | A duplicate delivery could change a healthy controlled RUNNING attempt to UNKNOWN or fail a still-QUEUED controlled job | Controlled dead-letter notifications do not mutate SQL job/attempt state. Durable deadline/outbox recovery owns those transitions; legacy behavior is retained |
| Cold restarted worker | Initial three process checks had **2 failed / 1 passed**, 4 warnings, **6.44 s**: RBAC-first import reached eager role normalization before RBAC initialization completed | Defer the dependency factory's role normalization to dependency execution. No role caching or authorization-matrix change |

The submission and cold-process red runs were separate later reproductions, not a single all-35-case pre-change run. A focused retry of the cold claimed case confirmed the ImportError before fixing the cycle. Do not add these overlapping runs into an aggregate failure rate.

After the first corrections the original two-module set passed **24 tests**, 4 warnings, **8.02 s**. After the cold-import correction, the three process cases passed, 4 warnings, **14.25 s**. The final expanded runs below include the submission fix and all additional cases.

## 3. What the new tests actually exercise

### A. Real process loss and persisted SQL recovery

`test_execution_process_recovery.py` starts an independent child executor against **file-backed SQLite**, using a copied real admitted job, approval, durable human session, policy and budget state. The parent synchronizes on a pipe marker, uses actual **SIGKILL**, waits for the child to exit, and runs recovery in another independent process.

The three interruption points are:

1. **Before claim:** the job stays QUEUED, no attempt exists, and capacity remains unreserved.
2. **After committed claim:** the job/attempt remain RUNNING until deadline recovery, then become UNKNOWN; both reservations remain held.
3. **After a committed request checkpoint:** the same UNKNOWN/retained-reservation contract applies.

A separate live child process also tries duplicate delivery while the first process is blocked after claim; it cannot invoke the collector. A controlled dead-letter callback cannot change the healthy SQL state. After SIGKILL and recovery, another process cannot execute the UNKNOWN descriptor. Repeated recovery performs no second transition and does not alter reservations.

**Boundaries:** the collector and daemon preflight are test doubles. Expiry uses an explicitly advanced `now`, not elapsed production deadline time. The SIGKILL is real, but this is not a real parser-container kill, orphan fencing/stop proof, PostgreSQL crash recovery, Redis failover, disk/power-loss test or recovery-latency measurement. Pipes/subprocesses have bounded waits and children are killed/waited in cleanup.

### B. In-process/real-SQL integrity and transaction boundaries

`test_execution_recovery_integrity.py` uses the existing real-session authentication/tenant fixture and SQL, plus explicitly mocked collectors/Redis where stated:

- Ordinary exception and BaseException interruption persist UNKNOWN and retain both reservations where SQL is available.
- If finalization is unavailable, preserve the original error; subsequent committed deadline recovery fences the still-RUNNING attempt UNKNOWN.
- RUNNING, UNKNOWN and resolved controlled state do not change because a duplicate dead-letters.
- A still-QUEUED controlled job retains its SQL outbox recovery path after dead-letter notification; eventual publication still permits one claim only.
- FakeRedis orphan exhaustion invokes the actual dead-letter callback path without fencing a healthy SQL attempt. This is a Redis double, not real Redis durability evidence.
- An actual publish callback delivers then raises at the acknowledgement boundary; PUBLISHING lease recovery or PENDING retry may duplicate delivery, but a second SQL claim is refused.
- Failed required Redis publication does not create a memory-only delivery or falsely acknowledge the outbox.
- A stale worker repository view cannot overwrite a committed UNKNOWN verdict.
- Closing an uncommitted reaper transaction leaves no partial UNKNOWN verdict.
- Injecting failure during the second reservation release rolls back attempt settlement, first release and audit event; a subsequent valid settlement can release both once.
- Existing authenticated exact-estate reconciliation requires permitted resolution, evidence reference and explicit external-stop confirmation. Invalid bodies do not release reservations; duplicate settlement refuses and appends no duplicate event.
- Both CONFIRMED_STOPPED and CONFIRMED_COMPLETED resolve the attempt without manufacturing scan/findings/completed-job results. The old job becomes non-reusable FAILED; new work requires new admission/current approval.

### C. Local concurrency and transport compatibility

`test_interruption_accounting.py` checks interruption during submission and execution, usable local capacity afterward, required durable publication failure for both a failed publish and missing client, safe enqueue log fields, and explicitly permitted development memory fallback.

The enqueue canary check covers only this edited log path. It is not a whole-product exception/log privacy audit.

## 4. Final local validation

| Run | Actual result | Scope / process outcome |
|---|---|---|
| New three-module focused set | **35 passed**, 4 warnings, **24.15 s** | Exit 0; includes 3 actual SIGKILL/fresh-process cases |
| Full default worker collection + selected execution/queue/API/budget/migration regressions | **1,052 passed / 16 skipped / 1 deselected**, 18 warnings, **310.36 s** | Exit 0; includes the 35 new cases |
| Auth/account/RBAC/custom-role/API-key/production-hardening/health-privacy compatibility | **113 passed**, 10 warnings, **28.38 s** | Exit 0; current durable role checks and alias/legacy compatibility retained |
| Python lint | `ruff check services scripts shared` passed | Repository-wide configured lint rules; no baseline suppression added |
| Dependency consistency | `pip check` passed | Installed test environment; no dependency/lock edits |
| Documentation/incremental whitespace | 492 Markdown / 1,817 local links; no missing targets/anchors; 7 increment Markdown / 2 shell examples checked; 12 source/input hashes match | 53 external links not fetched; shell syntax only, no deployment commands run |

The 35 focused checks overlap the broad worker run. These are not all-repository application results and must not be added to earlier published totals. Frontend/build/toolchain suites were not rerun: this increment changes no frontend or native binary build.

### Skips, deselection and warnings retained

- **16 PostgreSQL cases skipped** because no disposable/local PostgreSQL was provisioned: 12 full-chain parity cases; 1 stage-progress lock case; 3 GCC/SNB/UAE estate parity cases. These are **not passed or waived**. Never point optional destructive fixtures at a real/shared bank database.
- **1 live parser-container case deselected** by the existing default `not live` marker. No actual Docker parser qualification is claimed.
- Existing warnings include Pydantic class-config deprecation, network/cloud `register` field shadowing, Starlette/httpx and HTTP-422 deprecations, and Alembic path-separator deprecation.
- Some existing worker pipeline fixtures attempted external socket hosts; the hermetic socket guard blocked those attempts and retained warnings. This run is not a live upstream or zero-egress acceptance test.

No GitHub Actions result, independent security approval, SLA, bank uptime, runtime stop bound or customer go-live acceptance is inferred.

## 5. Reproduction commands and retained artifacts

The test environment used Python 3.11 in `/home/user/recovery-venv`, installed from the existing `requirements.txt` constrained by `requirements.lock.txt`. The exact source/lock hashes below bind the environment inputs; packages were not upgraded in repository files.

Use synthetic test secrets only, never production credentials:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
export SECRET_KEY=test-secret-key-for-sessions-min-32-chars
export GITHUB_WEBHOOK_SECRET=test-webhook-secret-abc123
PYTHON=/home/user/recovery-venv/bin/python

"$PYTHON" -m pytest -q -p no:xdist \
  services/api/tests/unit/test_execution_recovery_integrity.py \
  services/api/tests/unit/test_execution_process_recovery.py \
  services/worker/tests/unit/test_interruption_accounting.py

"$PYTHON" -m pytest -q -p no:xdist \
  services/worker/tests \
  services/database/tests/unit/test_execution_budget_concurrency.py \
  services/database/tests/unit/test_execution_control_migration.py \
  services/api/tests/unit/test_execution_controls.py \
  services/api/tests/unit/test_queue_authority_contract.py \
  services/api/tests/unit/test_execution_recovery_integrity.py \
  services/api/tests/unit/test_execution_process_recovery.py

"$PYTHON" -m pytest -q -p no:xdist \
  services/api/tests/unit/test_auth_account_lifecycle.py \
  services/api/tests/unit/test_auth_lifecycle.py \
  services/api/tests/unit/test_authorization_dependency_failure.py \
  services/api/tests/unit/test_custom_roles.py \
  services/api/tests/unit/test_multiuser_auth.py \
  services/api/tests/unit/test_rbac_roles.py \
  services/api/tests/unit/test_api_keys.py \
  services/api/tests/unit/test_production_hardening.py \
  services/api/tests/unit/test_health_failure_privacy.py
```

Local logs/XML live outside the repository; they are not durable bank evidence or committed attachments:

- `/home/user/recovery-baseline.log`
- `/home/user/recovery-before.log` and `.xml` — original 24-case adverse run
- `/home/user/recovery-submit-before.log` — 3 submission failures
- `/home/user/recovery-process.log` and `.xml` — original cold-process reproduction
- `/home/user/recovery-process-debug.log` — focused cold ImportError confirmation
- `/home/user/recovery-after.log` and `.xml` — first 24-case green run
- `/home/user/recovery-process-fixed.log` and `.xml` — 3 process passes
- `/home/user/recovery-focused-final.log` and `.xml` — final 35-case set
- `/home/user/recovery-regression.log` and `.xml` — broad worker/selected regression run
- `/home/user/recovery-auth.log` and `.xml` — auth compatibility run

## 6. Source identities

The SHA256 inventory below is generated from the final tested source. Existing control/outbox implementations and dependency inputs are included to distinguish changes from retained contracts. No signing/certification is implied.

```text
services/worker/worker/core/pool.py
bf17a60f15e390c99e9b84f2b6f2d4783c962f3682f3d530fde349d2a401bd7b

services/worker/worker/core/job_executor.py
20a7e65cbdb7db342d765a2711df321c343a6d99d6158b9bc9a431d5b5eddbe6

services/worker/worker/core/job_consumer.py
6da5763aa4d31986f4355b8ac2c69c4bf47a5912782fa85ee76718b8dd4ad4d9

services/worker/worker/core/job_reaper.py
f5957d6d6685e82e110e4d8b351d84dfd8af4996713e37cb8746ecae737df0fa

services/api/api/dependencies.py
ad1b2edc921dd0d4ebd1d3f1642aa1711bb27f34029adaae4a208644d1f56214

services/api/tests/unit/test_execution_recovery_integrity.py
c6bd4f5070edde9ede8a7832af49a95efacb02f53d6dc63db78a288195e17173

services/api/tests/unit/test_execution_process_recovery.py
7977ddc308276e929c3f41226f72a99785b2cac5b6ee3419053ad4622f2cd511

services/worker/tests/unit/test_interruption_accounting.py
de054fff115d2a4bc8a68ca7b75edc792bb9a723680aefe8b1263054e6dbf33b

services/database/db/repositories/execution_control.py
5e5e51465e72f3c39139b860a385a752a3989c02498fb1212a3da77d80b5cddd

services/database/db/repositories/execution_outbox.py
faf656335fc01f9d94d7377f14ace96dfbc43e4bf33cf26eb58029c333835ea0

requirements.txt
15c2c7d4ceacf2bde509b4bf5ac635923cc470986d13047a3cdc42a8214c8bb1

requirements.lock.txt
1b935cfe5230ea6f37affaab45044617ce402ecd1037f4c62b22404da4cedf2b

```

## 7. Operator compatibility and remaining acceptance

- Rebuild and review coordinated API/worker/parser/frontend release artifacts before installation; source edits do not change an installed bank image. This is not a native-binary conversion or automatic bank update.
- Expect explicit publication failure with memory fallback disabled; restore the approved Redis service and let the durable outbox retry. Do not flip a production fallback flag, manually acknowledge unsent work or reset SQL states.
- Controlled dead-letter notifications no longer directly fail or fence SQL work. Inspect owning attempts, deadline and existing outbox recovery. A healthy attempt may still be running; a lost worker may leave it RUNNING until deadline recovery. No response-time/stop guarantee is introduced.
- UNKNOWN continues to retain estate/provider capacity until the current authorized human confirms external state under the existing reconciliation contract. Do not equate a free local thread/semaphore with released external work.
- Current SQL CAS/approval/roles and immutable evidence remain authoritative. Independent technical review and actual intended PostgreSQL/TLS Redis/parser/daemon/fence/orphan/restore/capacity/operator exercises are still required, followed by separate bank/customer acceptance.
