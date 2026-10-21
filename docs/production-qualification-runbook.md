# Production qualification runbook

## Current execution/replay prerequisites

Before running customer phases, apply the
[coordinated producer/worker and replay-client upgrade](runbooks/execution-and-replay-upgrade.md).
Legacy unpinned work must be resubmitted through admission; a RUNNING recovered
delivery is not automatically re-executed. Check owned SSH job/result retrieval,
failed observations and generic-retry 409 behavior.

The [Redis TLS/ACL/Sentinel lab](bank-environment/45-redis-tls-sentinel-qualification.md)
is a separate destructive disposable exercise, not an automatically satisfied
phase of this coordinator. Its WAIT-barrier promotion fixture does not qualify
normal asynchronous acknowledgements, cross-zone DR or all Redis consumers.
Retain bank-specific TLS/ACL/rotation/load/restore and region evidence separately.

This runbook turns the remaining readiness work into executable phases. It is
an evidence-collection procedure, not a claim that repository code, mocks, or
local Docker automatically qualifies a customer deployment.

The coordinator is:

```bash
python scripts/production_qualification.py \
  --phase preflight \
  --out /secure/cryptoscan-evidence/<run-id>
```

A protected manual GitHub workflow is also available at
`.github/workflows/production-qualification.yml`. It requires a self-hosted
runner labelled `production-qualification` so private database, HSM, carrier,
and cloud systems are never exposed to a GitHub-hosted runner. Store the
qualification password and provider references in the protected GitHub
Environment; do not put them in workflow inputs.

Every phase writes `qualification.json`, `qualification.md`, and the source
artifact digests below the selected output directory. Secrets are supplied by
environment or a protected file and are never intended to be placed in command
arguments or evidence.

## Phase 0 — safe preflight

Run this on the release checkout before touching a customer environment:

```bash
python scripts/production_qualification.py \
  --phase preflight \
  --out /secure/cryptoscan-evidence/<run-id>/preflight
```

This verifies that the production compose files and qualification harnesses
exist, runs the static engineering gate, and records unavailable local tools as
`SKIP`. It does not claim Docker, PostgreSQL, Redis, HSM, customer integration,
or branch protection evidence.

The static gate must have no `FAIL` results. Its current immutable-image,
provider, and customer-sample `SKIP` results remain open until their controlled
artifacts are supplied.

## Phase 1 — deployment and operations

### 1. Bring up a dedicated staging/production-shaped stack

Use a dedicated host or CI environment with real PostgreSQL, Redis/Valkey, and
Neo4j. Do not expose database ports publicly. Configure the production overlay
using a secret manager or protected environment file:

```bash
bash scripts/deploy_prod.sh -d
```

Verify:

```bash
curl -fsS https://<api>/api/v1/healthz
authtoken=... # keep this in the operator shell only
curl -fsS -H "Authorization: Bearer $authtoken" https://<api>/api/v1/readyz
```

`/readyz` must be healthy with production Redis federation ready. A local
SQLite or process-local realtime fallback is not a production result.

### 2. Run the authenticated API surface burn

Store the admin qualification password in a protected file readable only by the
operator:

```bash
chmod 600 /run/secrets/cryptoscan-qualification-password
python scripts/production_qualification.py \
  --phase deployment \
  --api https://<api> \
  --password-file /run/secrets/cryptoscan-qualification-password \
  --out /secure/cryptoscan-evidence/<run-id>/deployment
```

This exercises the live OpenAPI GET/read-only surface and records 5xx and
connection failures. It does not fire destructive operations.

### 3. PostgreSQL replication and restore drill

Provide two real PostgreSQL instances configured as primary/standby and a clean
restore target. The drill requires operator-supplied promotion and restore
commands; it never invents or executes them by default:

```bash
export DR_PRIMARY_DSN='postgresql://...'
export DR_STANDBY_DSN='postgresql://...'
export DR_PROMOTE_COMMAND='ssh <standby> sudo pg_ctlcluster 16 main promote'
export DR_RESTORE_COMMAND='pg_restore --clean --if-exists --dbname "$DR_CLEAN_RESTORE_DSN" <backup>'
export DR_CLEAN_RESTORE_DSN='postgresql://...'

python scripts/production_qualification.py \
  --phase dr \
  --out /secure/cryptoscan-evidence/<run-id>/postgres-dr
```

For a real failover qualification, add `--execute-promotion
--acknowledge-destructive`. Retain provider replication logs, promotion output,
RPO/RTO measurements, restore output, and API/worker recovery probes beside the
JSON report. A drill that only checks connectivity is not a DR pass.

## Phase 2 — external integrations

Run only against systems for which the organization has written authorization:

```bash
python scripts/production_qualification.py \
  --phase integrations \
  --api https://<api> \
  --password-file /run/secrets/cryptoscan-qualification-password \
  --integration github \
  --integration tls \
  --integration neo4j \
  --integration cloud \
  --out /secure/cryptoscan-evidence/<run-id>/integrations
```

Available targets are `github`, `tls`, `smtp`, `neo4j`, `cloud`, and
`container`. Each target must point to a permitted staging/customer resource;
no endpoint should be scanned without authorization. The result must identify
which target, account, region, version, and scope were tested.

For telecom/carrier validation, use a separately authorized carrier/operator
window and retain the target registry, written authorization, probe logs, and
operator-side corroboration. Binary-derived NBOM data must not be presented as
live network observation.

## Phase 3 — load and soak

A short smoke is not a capacity qualification. Run a representative soak with
multiple identities, real PostgreSQL/Redis, worker metrics, queue depth, API
latency, error rate, evidence-chain verification, and resource samples:

```bash
python scripts/production_qualification.py \
  --phase soak \
  --api https://<api> \
  --password-file /run/secrets/cryptoscan-qualification-password \
  --soak-hours 24 \
  --out /secure/cryptoscan-evidence/<run-id>/soak
```

Define pass thresholds before running (for example, zero unexplained 5xx,
zero evidence-chain failures, bounded RSS/file descriptors, queue recovery,
and an agreed p99). Retain raw cycle JSONL, summary, dashboards, and the
threshold approval. Do not convert a local SQLite result into a PostgreSQL
capacity claim.

## Phase 4 — HSM/provider qualification

A SoftHSM or stub proves only adapter wiring. For a production result provide a
real AWS CloudHSM/custom KMS, Azure Managed HSM, GCP provider, or approved
PKCS#11/Luna environment:

```bash
export HSM_PROVIDER=aws
export HSM_KEY_ID='provider-key-reference-only'
python scripts/production_qualification.py \
  --phase hsm \
  --out /secure/cryptoscan-evidence/<run-id>/hsm
```

Retain provider-controlled evidence for non-exportability, signing, rotation,
revocation, outage handling, audit-log correlation, key owner, and region. No
private key, PEM body, token, or secret value belongs in the report.

## Phase 5 — strict release gate

After all external evidence is independently reviewed, assemble the controlled
artifacts and run the unified gate:

```bash
python scripts/bank_readiness.py --strict \
  --engineering <engineering-gate.json> \
  --postgresql-dr <postgres-drill.json> \
  --hsm <hsm-qualification.json> \
  --integrations <burn_in_report.json> \
  --load-soak <soak/summary.json> \
  --compliance <approved-compliance-evidence.json> \
  --readiness-closure <approved-closure-manifest.json> \
  --external-attestations <external-attestations.json>
```

A strict `PASS` is required before describing the deployment as an unattended
regulated-production candidate. Until then, the supported product boundary is
supervised pilot or pre-production.

## Evidence rules

- `PASS` means a real supplied artifact passed the applicable checks; it does
  not mean the repository generated a certification.
- `SKIP` is an open readiness item, not a pass.
- Synthetic estates, unit tests, Docker-only checks, local SMTP sinks, SoftHSM,
  and source inspection cannot become customer validation or regulator proof.
- Every report must be bound to a release commit, environment, scope, operator,
  reviewer, timestamp, limitations, and digest.
- Redact credentials and sensitive local paths from reports and logs.
