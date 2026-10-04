# Operational deployment readiness

This document defines the repository-level operational deployment readiness
measure. It is intentionally separate from production qualification.

## Current measure

Run:

```bash
python scripts/operational_deployment_readiness.py \
  --out /tmp/operational-deployment-readiness.json \
  --markdown /tmp/operational-deployment-readiness.md
```

The score is capped at **85/100 repository-control points**, which places a
complete implementation in the requested **80–90% operational deployment
readiness band**. The cap is deliberate: the remaining 15 points are reserved
for evidence that cannot be manufactured by this repository:

- a real PostgreSQL DR/restore exercise with measured RPO/RTO;
- HSM/provider qualification and non-exportability evidence;
- customer-environment integrations and escalation exercises;
- target-environment load/soak evidence;
- compliance attestations and independent security review.

A score of 85 means the deployment controls are implemented and checkable in
the repository. It does **not** mean the product is approved for unattended
production operation. The production qualification result remains
`BLOCKED_UNTIL_EXTERNAL_EVIDENCE` until the controlled evidence gate passes.

## Control groups

The diagnostic checks these repository controls:

1. fail-closed runtime and readiness behavior;
2. PostgreSQL migration ownership and startup ordering;
3. authenticated tenant isolation;
4. production Compose and Kubernetes artifacts;
5. non-root and privilege-reduction settings;
6. health, readiness and metrics surfaces;
7. backup, restore and evidence harnesses;
8. release and go-live controls;
9. centralized authenticated frontend requests;
10. regression tests for production hardening; and
11. deployment, on-call and recovery runbooks.

Each control emits PASS/FAIL and contributes only its stated points. Missing
controls lower the score; unknown external evidence never raises it.

## Rollback planning

The repository now includes a non-destructive rollback-plan generator:

```bash
python scripts/rollback_plan.py \
  --current /secure/releases/v1.4.2 \
  --target /secure/releases/v1.4.1 \
  --out /secure/evidence/rollback-plan.json
```

The target must contain a valid immutable `release-image-lock.json`. The tool
only validates release metadata and writes an operator plan. It does not stop
services, change traffic, run migrations, restore data, or execute a production
rollback. An approved operator must perform and record the deployment action
through the deployment controller, then attach health, readiness, migration,
backup and evidence-chain results.

## Boundaries

No score from this diagnostic may be used as evidence of:

- disaster recovery or restore success;
- HSM/KMS/provider qualification;
- customer integration or field accuracy;
- regulatory or compliance certification;
- production capacity, availability or soak performance; or
- independent security assessment.

Those are intentionally retained as explicit external qualification gaps.
