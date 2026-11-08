# Operator workflow engineering evidence — 2026-10-21

Scope: implementation increments **4.1–4.4**, on the existing session branch/PR.
This record is **local engineering evidence**, not customer sign-off, a
production release signature, bank capacity qualification or site recovery
acceptance. No external readiness manifest is closed by this work.

## Implemented surfaces

| Increment | Implementation | Important remaining acceptance |
|---|---|---|
| 4.1 | Real React `/operator-decisions`; exact-estate SQL read model; visible coverage/uncertainty/owners; bounded pagination; failed/UNKNOWN jobs, stale approvals, proof freshness and replay-gap reconciliation | Real supported-browser soak, deployment-specific roles/estate register completeness, incident operator review |
| 4.2 | Frozen assigned finding/baseline, independently reviewed predicate, reported action time, later independent completed scan, exact source site or TLS endpoint/SNI/STARTTLS/replacement fingerprint, immutable proof CAS/history, supersession and revocation | Real customer changes/certificate rotation acceptance; deleted/moved source-site predicates and broader certificate trust/client-path coverage are not inferred |
| 4.3 | Bounded worker process/stage and SQL cursor probes; real read-model synthetic workload with paired page-index trials; read-only scoped HTTP runner; 0104 indexes; full periodic SQL reconciliation without unsafe evidence cache | Actual parser/container/cgroup CPU/heap/disk, PostgreSQL contention/storage/retention, provider throttling, Redis contention/fault recovery and real-browser endurance |
| 4.4 | Explicit reference topology, digest-pinned site manifests, external-signature full-package inventory verification, strict controlled-profile pins, secret/CA declarations, server dry-run preflight, dedicated dispatcher build recipe, install/upgrade/airgap/recovery/legacy-runbook | Real image builds/digests, external signing authority, site secrets/CA/runtime provision, witnessed install/upgrade/restore and acceptance by a new site operator |

## Test results (overlapping, do not add)

1. Broad backend/worker regression: **1,113 passed, 4 skipped, 7 warnings,
   354.29 s**. Includes the worker unit suite, remediation, assurance/control and
   release tests. This preceded the final explicit profile/readiness and small
   proof/UI additions; it is not presented as final-code coverage of those changes.
2. **Final changed-code acceptance: 123 passed, 57 warnings, 40.86 s**. Covers
   final operator/condition/revocation/supersession/auth scope, explicit profile,
   production guards, controlled boundary, legacy comparator safety, package
   tampering, loopback HTTP counters/no redirect, worker durable writes, actual
   0104 round trip, migration chain/index parity and capability classification.
3. Full frontend regression: **390 passed across 44 files, 117.36 s**; followed
   by the final UI changes' **26 passed across 4 files, 15.34 s** (operator,
   remediation, app shell and maturity). Final typecheck and Vite production
   build passed (**1.35 s** build). These suites overlap.
4. The UI lifecycle case advances **2,880 fake-timer poll periods** (24 simulated
   hours), verifies state does not append indefinitely and cleanup stops polling.
   It is **not** a real-browser 24-hour wall-clock or JS heap soak.
5. Package tests use **synthetic fixture keys/digests**. They prove signature and
   full-file tamper/refusal behavior; the tool never generates signing keys or
   claims these fixtures are approved registry releases. HTTP tests use a real
   loopback server with synthetic responses, not a bank/provider workload.
6. Alembic head is **0104**. Its round trip preserves an UNKNOWN job's status/
   version and retained assurance rows; it creates/drops only the two new page
   indexes. SQLite migration/index-parity evidence is not PostgreSQL HA evidence.

Warnings include existing Pydantic/deprecated test-client/Alembic configuration
warnings; the broad worker suite also exercises a socket-blocked Git path. No
external bank/provider workload was run and no deployment was changed.

Local logs are retained outside Git in the agent workspace:
`/home/user/operator-final-regression.log`,
`/home/user/operator-final-changed-code.log`,
`/home/user/operator-frontend-final.log`,
`/home/user/operator-ui-final-changes.log` and
`/home/user/operator-deployment-final.log`.

## Repeatable measured workload and retained small reports

```bash
python scripts/operator_workload.py --estates 3 --rows 2000 --iterations 60 \
  --out "$NEW_PRIVATE_REPORT_PATH"
```

Each run creates/removes a disposable SQLite dataset: three synthetic estates,
2,000 tasks and 2,000 jobs each, 90% completed jobs/10% attention statuses, 60
actual inbox reads per phase at page size 25 and offsets 0/25/50/75. Same process,
sequential before/after indexes; no network/scanner/provider calls.

| Report | Median before → after | p95 before → after | Cursor total before → after | SHA256 of exact report bytes |
|---|---:|---:|---:|---|
| [Run 1](operator-workload-mixed-2026-10-21-run1.json) | 6.642 → 5.084 ms | 7.544 → 5.690 ms | 88.584 → 24.277 ms | `5e5b0f88d60d2f62e7f2f1b5c60c13a74a59001a1a03e4e44a24ff5411ced579` |
| [Run 2](operator-workload-mixed-2026-10-21-run2.json) | 6.530 → 5.191 ms | 10.027 → 5.534 ms | 95.288 → 24.592 ms | `6044b6f445c0cfbcdfc20f39e2869b5e4e1f81905788c5f4459b19f412af3bd3` |

Each phase has zero errors and 540 cursor operations. First-512 latency samples
are bounded and truncation is explicit. Query plans for actual-shape task/job
reads use the new estate/page indexes. Shared SQLite allocation was 3,293,184 B
empty → 7,745,536 B seeded → 8,773,632 B indexed. Each estate had 184,890 logical
finding-JSON bytes; this is **not** physical per-estate row/index/blob/WAL storage.
No retention deletion was exercised; generated databases are not committed.

Earlier contended trials are not hidden: with all jobs attention-eligible and
the test suites sharing the host, one median increased 6.525 → 8.483 ms while
cursor time fell 122.890 → 23.054 ms; another median fell 12.325 → 6.627 ms. Those
private diagnostic reports remain `/home/user/operator-workload-final-6000.json`
and `/home/user/operator-workload-repeat-6000.json`. They are different workload
shapes, not pooled into the final results. **There is no universal wall-time or
bank capacity promise.**

## Static/document validation

Changed Python files pass Ruff F/E9 checks and `git diff --check`. Documentation
validation covers **9 changed Markdown files, 111 relative links, 5 Bash blocks**
with no errors. The regenerated REST reference is idempotent and matches
**899 paths / 990 operations / 105 groups**. No CI workflow was modified or
manually dispatched; publication uses the existing session branch and skip-CI
commit convention.

## Upgrade and operator handoff

Read the [install/upgrade/recovery runbook](../runbooks/operator-install-upgrade-recover.md),
[decision workflow](../bank-environment/53-operator-decision-workflow.md),
[condition verification](../bank-environment/54-independent-remediation-verification.md)
and [measurement limits](../bank-environment/55-measured-workloads-and-capacity-limits.md).
Apply migration 0104 under maintenance after backup, rebuild API/worker/frontend
and approved parser as required, validate/sign a real package externally, and
replace producers/workers together. Legacy/unpinned jobs remain history and must
be resubmitted with current approval rather than replay-reset into trust.

This increment does not enable previously refused collectors, downgrade auth,
reclassify old job/ticket labels as independent proof, change main or CI
workflows, supply real release signatures, or certify physical residency,
customer accuracy, bank throughput, HA/RPO/RTO or an actual supported-browser
matrix.
