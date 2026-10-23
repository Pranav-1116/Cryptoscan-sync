# Readiness evidence directory

## Current reading versus immutable evidence

**Current 2026-10-23 review: eleventh bounded increment from `c48f667e`.** Dated records in this directory retain
their original commands, commits, results and hashes. They are not rewritten as
fresh execution by a documentation update. In particular,
[launch engineering](launch-engineering-2026-10-22.md) records migration **0104**
at its original 5.x run; the subsequent current chain ends at **0106**. The
[operator engineering record](operator-engineering-2026-10-21.md) likewise keeps
its original 0104 measurements. Follow the current
[operator upgrade/recovery runbook](../runbooks/operator-install-upgrade-recover.md)
for today's migration requirements.

The [current source/CI status](../CURRENT-IMPLEMENTATION-STATUS.md) separates
configured lanes, retained historical observations, local docs checks and the
user-reported remaining workflow failure. No historical green result overrides
an outstanding current failure or supplies external/customer approval.

This directory is the default output location for the current bank-readiness
gate. Artifacts must be retained with their commands, UTC timestamps, commit,
environment, provider/database logs and operator/customer attestation where
applicable.

```bash
python scripts/bank_readiness.py --run-engineering \
  --out docs/readiness-evidence/bank-readiness.json
```

The JSON and Markdown reports are generated outputs. A generated report with a
`FAIL` or `SKIP` category is an honest incomplete result; do not edit its
verdict by hand. Use the root `PRODUCTION-READINESS.md` for interpretation.
External artifacts remain outside the repository when they contain sensitive
customer/provider information; pass their controlled paths to the gate.

## Latest bounded engineering evidence

The [eleventh six-BOM/performance/recovery record](quality-six-bom-perf-recovery-2026-10-23.md)
retains248 selected contract passes,19 native PostgreSQL passes, a matched
169→20-query trace improvement, executed SQL/artifact failback and actual Redis
SIGKILL loss. Broader workload, joint site recovery and independent review remain
open; this does not promote readiness or replace older immutable records.

The [tenth shared-read record](quality-shared-private-reads-2026-10-23.md) and
[results/input hashes](quality-shared-private-reads-results-2026-10-23.json) retain
36 new regressions, original-source failures and11 actual built-browser checks.
Only GET-owned state is hardened; caller actions/forms/exports and site acceptance
are not inferred. The prior native database/API results below remain historical.

The [ninth workflow record](quality-workflow-qualification-2026-10-23.md),
[actual PostgreSQL record](quality-postgres-workflow-2026-10-23.md),
[real-browser record](quality-critical-browser-2026-10-23.md) and
[results/input hashes](quality-workflow-results-2026-10-23.json) retain actual local
runs and their exclusions. They do not rewrite generated bank-readiness verdicts,
close unrelated skipped tests, supply external ownership/approval or establish
site/SSO/TLS/HA acceptance. Prior dated increments retain their original results.

## P0/P1 closure envelope

The documented enterprise-bank gaps have an explicit closure contract in
`config/readiness-closure-policy.json`. The gate requires one current,
release-bound, externally controlled and independently reviewed artifact for
every required kind across P0-1 through P1-5; it rejects repository-local
self-attestation, missing files, hash mismatches, stale evidence, nested
`FAIL`/`SKIP` results, missing limitations, and same-person operation/review.
It does not turn a repository file into customer, provider, auditor, legal, or
regulatory evidence.

Use a controlled manifest supplied by the deployment/evidence owner:

```bash
python scripts/readiness_closure_gate.py \
  --manifest /secure/evidence/closure-manifest.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --out /secure/evidence/closure-report.json \
  --strict
```

`closure-manifest.example.json` is a shape example only. Its placeholders must
never be copied into an approval package. For a release approval, also pass
`--require-readiness-closure --readiness-closure-manifest ...` to
`scripts/release_check.py`; pre-release checks leave this external requirement
opt-in so local development does not fabricate approval evidence.

## Controlled-execution engineering record (2026-10-21)

[Scoped execution-controls tests](execution-controls-engineering-2026-10-21.md)
record migration 0102, approvals/provenance, SQL budgets/fairness, stop, hostile
local staging and unknown/outbox recovery. **This is not a bank acceptance or a
new unified-gate PASS**: only local source is supported in the controlled profile;
other consumers and deployment qualification remain explicitly incomplete.


## Evidence assurance 3.1–3.7 engineering record (2026-10-21)

[Scoped assurance tests and open acceptance](assurance-engineering-2026-10-21.md)
cover migration 0103, partial SSH receipts, expected-register denominators,
reviewed six-BOM paths, immutable/byte-bound accuracy review and regressions,
purpose-aware assessments, verified Redis consumers and signed supplier offline
quarantine/profile exercises. **No external closure or bank-readiness PASS is
issued.** Read the [upgrade runbook](../runbooks/evidence-assurance-upgrade.md).

## Existing-product steps 7–10 (2026-10-23)

[Usability, demonstrated test trust, release binding and accountable operations](quality-usability-release-operations-2026-10-23.md)
records local542 frontend/15 browser/92 selected backend/248 broader/19 native
checks, adverse failures and warning debt. Human acceptance, actual staffing,
independent RC review and required release CI remain open; no SLA/readiness claim.

## Bank PQC vendor questionnaire (2026-10-23)

[Executed bank-questionnaire fixes and57-item gap register](bank-vendor-questionnaire-2026-10-23.md)
map all45 original questions plus12 missing controls, with source references and
actual remaining acceptance.648 selected Python/548 frontend tests pass locally;
no bank readiness, corporate certification, new collector or SLA is inferred.
