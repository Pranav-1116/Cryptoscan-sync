# CryptoScan production readiness — current evidence gate

**Current as of:** 2026-10-04 UTC
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

The checked-in report was generated on **2026-10-04 UTC** against commit
`e44568e` (evidence commit; the report itself is committed in the follow-up
commit, per the repository's binding convention) with live qualification
artifacts supplied for four evidence categories. **PostgreSQL DR is PASS**
(`docs/readiness-evidence/postgres-dr-drill-2026-10-04.json`: 35/35 checks,
promotion RTO 0.103 s, marker RPO 0 s, full row-count preservation, API
failover HTTP 200, real worker recovery probe, clean pg_dump/psql restore of
every table including the hash-chained audit log). **Integrations is PASS**
(`burn-in-2026-10-04.json`: HMAC-signed GitHub webhook round-trip through the
Redis queue and worker, TLS 1.3 negotiation, SMTP delivery). **Compliance is
PASS** (`compliance-burn-2026-10-04.md`: 11/11 over live HTTP — evidence pack,
JWS attestation sign/verify/tamper-reject, WORM retention, auditor key
separation, capacity forecast). **Load/soak is PASS**
(`load-test-2026-10-04.json`: 7 559 requests, 0 errors, 100 % HTTP 200;
`soak-2026-10-04/`: 3/3 cycles with the evidence chain re-verified each cycle
and flat RSS). The engineering subchecks for exception triage, `X-API-Key`
coverage and frontend authorization are **PASS**; engineering as a whole is
**FAIL** because immutable image policy is unresolved (three mutable template
references; the release registry was unreachable from the qualification
environment, so no digest-pinned manifests could be rendered), the
branch-protection API query was refused for the automation credential
(403 — Administration scope not granted), and the COBOL/PL/I/RPG
customer-sample hooks have no customer corpora. HSM, readiness-closure and
external-attestation categories remain **SKIP** — those require
provider-controlled or customer evidence that a repository session cannot
produce. See the JSON report for the complete machine-readable record.

## Required qualification categories

| Category | What qualifies as evidence | Repository status without external evidence |
|---|---|---|
| Engineering | `scripts/engineering_gate.py`: exception inventory, API-key route coverage, frontend authorization scan, immutable image policy, provider branch-protection query, customer-sample hooks; `scripts/pin_release_images.py` renders exact registry digests | Static PASS/FAIL only; no claims about provider enforcement. Checked-in Kubernetes files are templates until a real registry digest is supplied |
| PostgreSQL DR | Two real instances, streaming state, marker replay, controlled promotion, measured RPO/RTO, clean restore, audit/evidence-chain verification, API and worker recovery | **PASS (2026-10-04, qualification environment)**: real PostgreSQL 16 primary + streaming standby, RTO 0.103 s, RPO 0 s, clean restore verified. Retained artifact: `docs/readiness-evidence/postgres-dr-drill-2026-10-04.json` |
| HSM/provider | Customer PKCS#11, AWS CloudHSM custom key store, Azure Managed HSM, or GCP provider; non-exportability/signing, rotation, revocation, outage and audit metadata | **FAIL/SKIP** until provider-controlled evidence is supplied; SoftHSM is only a local gate |
| Integrations | Real multi-target TLS, scheduled NBOM/worker, read-only AWS/Azure/GCP, Neo4j, container, GitHub round-trip, carrier/operator telecom and production alert escalation | **PASS (2026-10-04, partial scope)**: GitHub signed-webhook round-trip, TLS 1.3, SMTP. Cloud/Neo4j/container probes were not in scope of the qualification environment — see `burn-in-2026-10-04.json` |
| Compliance/procurement | Secure-SDLC and vulnerability/patch records, vendor risk, residency/deployment, SLA/escalation, incident notice, backup retention/destruction and external attestations | Repository controls are not SOC 2/ISO/FIPS/customer attestations. **Live compliance burn is PASS** (`compliance-burn-2026-10-04.md`); external certifications remain outside the repository |
| Load/soak | Target-environment load and realistic multi-day soak with thresholds, database/queue metrics and retained raw output | **PASS (2026-10-04, short-run qualification)**: 7 559-request load run with zero errors plus 3-cycle soak with chain verification. A multi-day production soak is still required for capacity claims |
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

> **Tenant-scope correction.** Tenant resolution now fails closed for unknown,
> ambiguous, suspended, or unavailable tenant context. A failed middleware
> resolution must never continue as an unscoped request, because an unscoped
> ORM query can expose another tenant's scan data. See
> `docs/architecture/multi-tenancy.md` and the tenant-scope regression tests.

## Current decision

Until the unified gate reports PASS for every required category, the only
honest recommendation is **supervised pilot or pre-production**, with one
instance per bank where that is the supported topology. The gate is designed
to fail rather than silently grant an unattended production approval.

**2026-10-04 status of the remaining blockers** (all outside what a source
session can close):

1. **Immutable image digests** — render a release with
   `scripts/pin_release_images.py` once a registry is reachable and supply
   `--release-manifests` to the engineering gate. The release CI workflow
   (`.github/workflows/docker-build.yml`) is written but requires a
   workflow-scoped credential to publish.
2. **Branch protection** — enable required reviews/status checks on `main`
   (needs the GitHub Administration permission the automation credential
   lacks): `gh api -X PUT repos/<org>/<repo>/branches/main/protection` with
   required status checks and ≥1 approving review.
3. **HSM qualification** — provider-controlled evidence via
   `scripts/hsm_qualification.py --provider <real-provider>`.
4. **Customer corpora + external attestations + P0/P1 closure manifest** —
   customer attestation tier; see `config/readiness-closure-policy.json`
   for the full 14-gap register. The drill and load/soak evidence produced
   on 2026-10-04 is directly reusable for the `topology_dr_drill` (P0-4)
   and `target_topology_load_soak` (P1-2) artifact kinds once a continuity
   plan approval and evidence owner sign them.

For the end-to-end plan from this state to production sign-off — every
remaining phase with owners, commands and acceptance criteria — see
[`docs/PRODUCTION-ROADMAP.md`](docs/PRODUCTION-ROADMAP.md).

For detailed database history and resolved versus open implementation gaps,
see [`BACKEND-DATABASE-GAPS.md`](BACKEND-DATABASE-GAPS.md). For operational
procedures, see [`docs/ops/production-checklist.md`](docs/ops/production-checklist.md)
and [`docs/production-evidence.md`](docs/production-evidence.md).
