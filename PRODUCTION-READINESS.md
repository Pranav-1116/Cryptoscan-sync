# CryptoScan production readiness — current evidence gate

**Current as of:** 2026-09-28 UTC
**Source of truth:** `scripts/bank_readiness.py` → `docs/readiness-evidence/bank-readiness.{json,md}`
**Scope:** repository controls plus customer/provider qualification evidence.

This file replaces the historical percentage-based assessment that used to live
here. Percentages, corpus scores, synthetic bank-shaped estates and unit tests
are useful engineering evidence, but they are not proof of production
qualification. A deployment must not be described as production-ready until
the unified gate contains retained, attributable evidence for every required
category.

## Run the gate

```bash
# Static engineering checks and documentation consistency; external categories
# remain explicit SKIP until their real artifacts are supplied.
python scripts/bank_readiness.py --run-engineering \
  --out docs/readiness-evidence/bank-readiness.json

# Release approval: no SKIP or FAIL is accepted.
python scripts/bank_readiness.py --strict \
  --engineering docs/readiness-evidence/engineering-gate.json \
  --postgresql-dr docs/dr-evidence/postgres-drill.json \
  --hsm docs/hsm-evidence/hsm-qualification.json \
  --integrations burn_in_report.json \
  --production-evidence data/evidence/production-evidence/report.json \
  --compliance docs/compliance-burn.md \
  --load-soak docs/soak-evidence/summary.json \
  --external-attestations /secure/customer-attestations.json
```

Every report records UTC time, commit, branch/dirty state, command, artifact
digest, environment, status and limitations. A digest proves integrity of a
file; it does not prove who ran it. Sign or retain the provider, database and
customer attestations in the controlled evidence store.

### Latest recorded gate

The checked-in report was generated on **2026-09-28 UTC** against commit
`792caa4` by the command above. The engineering subchecks for exception
triage, `X-API-Key` coverage and frontend authorization are **PASS**; immutable
Kubernetes image policy is **FAIL** with three mutable template references;
branch protection and COBOL/PL/I/RPG customer-sample checks are **SKIP**
without provider context or customer paths. PostgreSQL DR, HSM, live
integrations, compliance, load/soak and external-attestation categories remain
**SKIP** until their controlled external artifacts are supplied. See the JSON
report for the complete machine-readable record.

## Required qualification categories

| Category | What qualifies as evidence | Repository status without external evidence |
|---|---|---|
| Engineering | `scripts/engineering_gate.py`: exception inventory, API-key route coverage, frontend authorization scan, immutable image policy, provider branch-protection query, customer-sample hooks; `scripts/pin_release_images.py` renders exact registry digests | Static PASS/FAIL only; no claims about provider enforcement. Checked-in Kubernetes files are templates until a real registry digest is supplied |
| PostgreSQL DR | Two real instances, streaming state, marker replay, controlled promotion, measured RPO/RTO, clean restore, audit/evidence-chain verification, API and worker recovery | **FAIL/SKIP** until `scripts/postgres_drill.py` is run with real DSNs and retained logs |
| HSM/provider | Customer PKCS#11, AWS CloudHSM custom key store, Azure Managed HSM, or GCP provider; non-exportability/signing, rotation, revocation, outage and audit metadata | **FAIL/SKIP** until provider-controlled evidence is supplied; SoftHSM is only a local gate |
| Integrations | Real multi-target TLS, scheduled NBOM/worker, read-only AWS/Azure/GCP, Neo4j, container, GitHub round-trip, carrier/operator telecom and production alert escalation | **FAIL/SKIP** when `burn_in.py` safely skips a dependency |
| Compliance/procurement | Secure-SDLC and vulnerability/patch records, vendor risk, residency/deployment, SLA/escalation, incident notice, backup retention/destruction and external attestations | Repository controls are not SOC 2/ISO/FIPS/customer attestations |
| Load/soak | Target-environment load and realistic multi-day soak with thresholds, database/queue metrics and retained raw output | Short local tests are not a production capacity claim |
| Documentation | Link and status consistency, timestamps, commands, artifact locations and honest PASS/FAIL/SKIP | This report plus the accuracy documents |

## Explicit external boundary

- `docs/accuracy/BANK-READINESS.md` is detector/estate evidence. Its bank
  estates are synthetic and its field-accuracy row is `NO_FIELD_DATA` until a
  bank publishes a reviewed triage workbook.
- `docs/accuracy/DUBAI-BANKS-E2E.md` is a reproducible synthetic run. It did
  not access Dubai bank code, configuration, credentials or key material.
- `scripts/backup_drill.py`, `deploy/ha/drill.sh`, `scripts/burn_in.py`,
  `scripts/compliance_burn.py`, `scripts/load_test.py` and `scripts/soak.py`
  are harnesses. Their existence or a safe SKIP is not evidence that the
  corresponding customer infrastructure passed.
- No repository document may convert source inspection, mocks, SoftHSM,
  Docker-only tests or corpus measurements into a customer certification.

## Current decision

Until the unified gate reports PASS for every required category, the only
honest recommendation is **supervised pilot or pre-production**, with one
instance per bank where that is the supported topology. The gate is designed
to fail rather than silently grant an unattended production approval.

For detailed database history and resolved versus open implementation gaps,
see [`BACKEND-DATABASE-GAPS.md`](BACKEND-DATABASE-GAPS.md). For operational
procedures, see [`docs/ops/production-checklist.md`](docs/ops/production-checklist.md)
and [`docs/production-evidence.md`](docs/production-evidence.md).
