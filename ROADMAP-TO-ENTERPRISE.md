# What to do next — getting CryptoScan to enterprise grade

**Updated:** 2026-09-28 · Implementation claims below are bounded by the current
engineering gate and retained evidence; external qualification is not inferred.
Companion to [BACKEND-DATABASE-GAPS.md](BACKEND-DATABASE-GAPS.md), which
records what was broken and what was fixed. This one is forward-looking.

---

## Read this part first

You have built more product than you have evidence for. That is the whole
situation in one sentence, and the plan below follows from it.

The code includes PostgreSQL parity paths, a genuine CycloneDX 1.5 CBOM with
signing, real `boto3` integrations, real TLS and SSH handshakes, a JVM
constant-pool bytecode parser, TR-31/ISO 9564/ISO 8583/EMV, and TS 33.501 5G
modules. A historical run recorded 5,712 backend tests green on both SQLite
and PostgreSQL; that count is not presented as a current run here. This is a
credible product, but the current gate remains the decision point.

**And it has never scanned a bank.** Not once. Every estate run in this
repository is synthetic, and `DUBAI-BANKS-E2E.md` says so itself: *"no bank
system was accessed."* 100 files, not an estate. `BANK-READINESS.md` reports
`NO_FIELD_DATA` — no pilot has reviewed a single finding.

So the temptation is to add the next capability. Resist it. The marginal
value of feature number 51 is close to zero while the answer to *"who is using
this?"* is nobody. Everything in Phase 1 below is about converting code you
already have into evidence someone else will accept.

A second, related caution. The recurring failure mode in this codebase has
not been missing features — it has been **features documented as working that
were not**. CI was 0 bytes. The PostgreSQL parity gate had never run. The
external-validation script pointed at a path that did not exist. Tenant
isolation was described as "enforced at the data layer" while the entire scan
surface was readable across tenants. Every one of those was found by *running*
the thing, never by reading it. Whatever you build next, the acceptance
criterion is an execution, not a description.

---

## Implementation status — 2026-09-27

This roadmap is now being executed in risk order rather than by adding more
feature breadth. The first production-hardening slice is implemented:

- **Done in code:** production `/metrics` bearer-token protection, encrypted
  `age` database backups/restores with checksum verification, pinned Kubernetes
  API/worker image tags, and non-blocking OTLP/HTTP trace export.
- **Tests/config updated:** production settings and release/CI guard fixtures
  require `METRICS_TOKEN`; Prometheus uses a mounted bearer-token file; focused
  tests cover metrics auth and OTLP payloads.
- **Still external proof:** bank pilot, third-party penetration test, required
  GitHub CI branch protection, two-node PostgreSQL DR drill, real HSM/CloudHSM,
  field validation, and SOC 2/ISO 27001 cannot be truthfully completed by
  editing this repository alone.

Implemented in the next Phase 3 slice (also covered by focused tests):
worker-owned scheduled network scans now persist `NetworkScanRun` rows for NBOM;
`RequireRole` gates the first high-value frontend mutation controls; and
operator-side GTP-U/IPsec N3/N9 evidence is classified without emitting active
user-plane packets. Remaining slices are exception triage, the long-tail
frontend migration, live worker/NBOM evidence, SoftHSM/real-HSM proof, and
external customer validation.

## Phase 1 — Evidence (weeks 1–8)

Nothing here is a feature. All of it is what a CBUAE- or SAMA-regulated
procurement will ask for, and none of it can be bought late.

### 1.1 Get one pilot bank, on one instance

The single highest-value action available to you. One bank, one deployment,
read-only, scanning **source repositories only** — not the live core-banking
estate.

Why source-only first: it is the part of the product with the strongest
evidence (~25,000 third-party files externally validated across five
languages, zero parser crashes), it needs no production network access, and
it fails safe. A bank's security committee will approve a read-only repo scan
far sooner than anything touching the payment estate.

**Exit criteria**
- A signed pilot agreement with a defined scope and a named security contact.
- The scan runs on their infrastructure, on their schedule, unattended, for
  four weeks without an operator intervening.
- **A human at the bank reviews the findings and tells you which are wrong.**
  This is the deliverable. `GET /api/v1/accuracy/field` stops returning
  `NO_FIELD_DATA`.

That last point is worth more than any feature you could ship this quarter.
Your accuracy number is currently self-scored on a corpus you wrote and tuned
against; one bank's reviewed triage workbook turns it into a real measurement.

### 1.2 Third-party penetration test

Scope it explicitly at, in priority order:

1. **Cross-tenant isolation.** I built the ORM filter, the migrations and the
   tests that check them. That is the weakest form of assurance there is, and
   it is the one control where being wrong is a regulatory incident rather
   than a bug. Give the tester `BACKEND-DATABASE-GAPS.md` §1.1 and ask them to
   break it.
2. **The `x-api-key` path**, which bypasses the global ASGI auth gate
   (`auth_middleware.py:84`) and delegates to per-route dependencies. That is
   safe only while route coverage stays at 100%, and nothing enforces it.
3. The authenticated API surface generally — 733 endpoints.

**Exit criterion:** a report you can hand to a procurement team, and every
finding either fixed or accepted in writing with a reason.

### 1.3 Delete the three claims you cannot defend

Do this before any bank sees a demo. Each one is the kind of thing that, when
caught, costs you trust in everything else you said.

| Claim | Reality | Action |
|---|---|---|
| "eBPF runtime agent" | There is no kernel *crypto* agent anywhere in the repo — `deploy/ebpf/execve_trace.py` traces execve for the AI boundary, not crypto, and the `scanner_id` default is neutral | **Deleted 2026-11-06.** The surfaces now name the `LD_PRELOAD` tracer (ADR-012) and negate the eBPF agent; every eBPF mention on a product surface must match an approved shape or `scripts/tests/test_claim_hygiene.py` fails |
| SOC2 CC9.3/9.4 region failover **PASS** | `scripts/region_drills.py` simulates a region pair with two temp *directories* in one process; the containerised drill is recorded SKIPPED | **Scoped 2026-11-06.** The drill reports print "PASS — same-process code drill (see Scope; not a site qualification)" and the scope travels beside the verdict; the SOC2 mapping stays ⚠️. Enforced by `scripts/tests/test_region_drill_reports.py` + `test_claim_hygiene.py`. The only upgrade path remains a real two-Postgres drill |
| "Precision / Recall / F1 = 100%" | Scored against fixtures written here and tuned against wave by wave | **Held deleted 2026-11-06.** No surface quotes it; `scripts/tests/test_claim_hygiene.py` fails on the claim shape and requires every perfect-score quote to carry its corpus caveat on the same line. External quotes use `docs/accuracy/EXTERNAL-VALIDATION.md` with its blind/corpus scope |

### 1.4 Make the parity and CI gates mandatory

CI exists now (it was four 0-byte files) and includes a PostgreSQL parity job.
Make it **required to merge**, so the production database path cannot silently
stop being exercised again.

---

## Phase 2 — Operational hardening (weeks 4–12, overlaps Phase 1)

A bank's operations team asks different questions from its security team.
These are theirs.

### 2.1 The specific defects still open

Verified still open as of this writing:

| Item | Where | Why it matters |
|---|---|---|
| ~~`/metrics` unauthenticated~~ | **Fixed 2026-09-27:** production requires `METRICS_TOKEN`; Prometheus sends a bearer token | Development/test remains open; production config and focused auth test enforce the boundary |
| ~~Backups unencrypted at rest~~ | **Fixed 2026-09-27:** `db_backup.sh` encrypts PostgreSQL/Neo4j artifacts with `age`; plaintext is refused by default | `db_restore.sh` verifies encrypted bytes before decrypt/restore; a real restore drill remains required |
| ~~`:latest` image tags~~ | **Tag removed 2026-09-27:** Kubernetes API/worker use `v1.0.0` | **Still open:** replace the release tag with the registry-approved immutable digest; the engineering gate currently reports three mutable references |
| ~~OTLP endpoint is dead code~~ | **Fixed 2026-09-27:** bounded background OTLP/HTTP JSON exporter in `TraceStore` | Collector outage is logged and spans are dropped only after the bounded queue fills |
| ~~Exception inventory~~ | **Triaged 2026-09-28:** current engineering gate reports 0 unresolved production or test/harness handlers; intentional best-effort boundaries now emit typed logs | Keep the gate in CI so newly added silent handlers cannot return |

The last one should be triaged, not bulk-fixed: many are legitimate
best-effort paths. The first auth slice now logs principal/tenant lookup
failures, fails closed for production session-store errors, and refuses to
claim logout/session issuance succeeded when the production auth write was not
persisted. Remaining exception triage should continue through write-heavy
routers and event bridges.

### 2.2 Prove the disaster-recovery story

You have the topology (2× API, 2× worker with leader-lease failover, Postgres
streaming replication) and a runbook. You do not have a drill.

Run one against **two real PostgreSQL instances**, time the RTO, verify RPO,
and record it. Until then CC9.3/9.4 stays ⚠️ and an auditor asking "show me
the failover" has nothing to look at.

### 2.3 Restore, not backup

`db_backup.sh` and `db_restore.sh` both work. Schedule a **restore** drill —
monthly, into a scratch instance, with an automated check that the restored
schema matches models. A backup you have never restored is a hypothesis.

---

## Phase 3 — Close the product gaps that are actually load-bearing (weeks 8–20)

Only after Phase 1 is moving. Ordered by what a bank will notice.

### 3.1 Feed the NBOM — repository implementation complete (2026-09-27)

The monitor leader tick now selects enabled API-created `NetworkScanTarget`
rows by their persisted schedule, calls the live `NetworkTlsScanner`, stores
one `NetworkScanRun` with `target_kind="scheduled"`, materializes certificates
and usages, and advances the target only after a successful scan. Due rows are
grouped by tenant so persisted runs and materialized inventory retain tenant
ownership. The manual `/network/run-due` path writes to the same run ledger.
`test_network_sweep.py` proves due selection, persistence, tenant attribution,
rescheduling, failure semantics and monitor tick wiring. NBOM continues to
derive from stored runs; no demo seed is needed.

Remaining proof: run a live multi-target worker against a controlled estate and
record the resulting NBOM/scan-run evidence.

### 3.2 Finish the frontend authorisation migration — first slice complete

`RequireAuth` guards every route and roles are server-verified. `RequireRole`
now gates scan submission in Findings, active-sector changes, and onboarding
mutations/discovery; Onboarding and Sectors no longer read roles directly from
localStorage. Frontend typecheck, production build, 118 tests and all page
smoke tests pass. Remaining work is to migrate the long tail of ad-hoc action
controls and keep the backend as the authoritative enforcement point.

### 3.3 Prove one HSM adapter against real hardware — SoftHSM gate added

`keyassure/hsm_backends.py` has real adapters for AWS KMS, Azure Key Vault /
Managed HSM, GCP KMS and PKCS#11. The runnable
`scripts/softhsm2_pkcs11_check.sh` creates an ephemeral SoftHSM2 token and
round-trips an RSA-2048 object through the real PKCS#11 module when SoftHSM2
and OpenSC are installed. Without those binaries it reports an explicit skip,
or fails when `REQUIRE_SOFTHSM2=1` is set by an operator's CI job. This session
does not add a CI/CD workflow. This is not real-HSM or CloudHSM evidence: a
customer-controlled hardware validation remains open.

### 3.4 Telecom: GTP-U / IPsec on N3 and N9 — repository implementation complete

`telecom_scanner.user_plane.assess_user_plane` now classifies operator-side
N3/N9 evidence for GTP-U/UDP-2152, IPsec presence, IKEv2, AEAD encryption,
SHA-2 integrity and DH-group floors. Cleartext, weak or mis-port evidence is
flagged; missing evidence is honestly `USER_PLANE_UNKNOWN`. Telecom registry
records accept `interface: N3|N9`, the active probe never emits user-plane
packets, and focused tests cover clean, weak, cleartext and no-evidence paths.
Real carrier-side captures or operator ingest remain external evidence.

### 3.5 Extend external validation to the mainframe languages

Java, C#, Go, JS/TS and Python are now validated against real third-party
code. **COBOL, PL/I and RPG remain corpus-only** — `BANK-READINESS.md` flags
this honestly ("no public ICSF code exists"). For an international bank,
mainframe coverage is often the whole point.

If a pilot bank will let you validate against even a small sample of their own
COBOL under NDA, that is worth more than another thousand synthetic fixtures.

---

## Phase 4 — Commercial and compliance (parallel, 6–18 months)

These run on their own clock and gate large deals, so start them early.

- **SOC 2 Type II** — you have a gap analysis
  (`docs/soc2-readiness-gap-analysis.md`) that is now honest about CC9.3/9.4.
  Type II needs an observation window, typically 6–12 months. Starting it is
  mostly a procurement decision.
- **ISO 27001** — commonly requested by GCC banks alongside or instead of SOC 2.
- **Data residency.** A UAE bank will ask where scan results are stored. The
  answer must be "your infrastructure, your region" and must be demonstrable.
  Single-tenant deployment makes this easy — another reason not to rush
  multi-tenant.
- **Support model.** SLAs, escalation, named contacts, patch commitments.
  Banks buy the support model as much as the software.

---

## What *not* to build

Saying this plainly because the pull will be strong:

- **Not multi-tenant SaaS.** The isolation machinery is built (87 of 102
  tables, ORM-enforced), but banks buy single-tenant deployments anyway, and
  single-tenant makes data residency trivial. Turning on
  `CRYPTOSCAN_SAAS_SIGNUP` before Phase 1.2 converts a solved problem into
  your largest risk.
- **Not more scanners.** You have code, container, network, cloud, hardware,
  payment, telecom, OT and runtime. Breadth is not the constraint; evidence is.
- **Not an AI layer.** This product's credibility rests on being
  deterministic — "policy is never decided by AI; unknowns are skipped with
  reasons, never faked" is in your own README and it is a genuine
  differentiator with regulators. Do not trade it for a chat box.
- **Not a rewrite of the BOM generators.** CBOM is 6,504 LOC of working
  CycloneDX 1.5 with OID lookup, canonical JSON and JWS signing. SBOM, HBOM
  and VBOM read real rows. Rewriting them is motion, not progress.

---

## Sequencing, honestly

```
Weeks 1–8    Phase 1  pilot bank · pen test · delete the three claims · CI mandatory
Weeks 4–12   Phase 2  /metrics auth · encrypt backups · pin images · real DR drill
Weeks 8–20   Phase 3  schedule network scans · RequireRole migration · real HSM · GTP-U
Months 1–18  Phase 4  SOC 2 Type II · ISO 27001 · residency · support model
```

Phases 1 and 2 overlap deliberately: the pilot will surface operational
problems, and fixing them with a real customer watching is worth more than
fixing them in the abstract.

## The one metric that matters

Not test count, not endpoint count, not lines of code.

**Number of banks that have run this against their own systems and told you
what it got wrong.**

Today that number is zero. When it is one, you have a product. When it is
three, you have a company. Every phase above is in service of moving that
number, and any work that does not move it should be questioned.

---

## Where you actually stand

To be fair to the work, because the list above is all deficits:

| Area | State |
|---|---|
| Backend | PostgreSQL parity paths exist; historical 5,712-test run is not a current result |
| Auth | Global ASGI gate; 7 of 730 routes unauthenticated (health/metrics only); PBKDF2-SHA256 @ 210k; fails closed in production |
| Tenant isolation | 87 of 102 tables, ORM-enforced, middleware-scoped — built and tested, awaiting adversarial review |
| Scanner accuracy | ~25,000 third-party files validated across 5 languages; zero parser crashes; 5 real defects found and fixed |
| BOMs | CBOM production-grade; SBOM/HBOM/VBOM fed by real rows; NBOM derived from stored scans (preview) |
| Payment | TR-31/X9.143, ISO 9564, ISO 8583, EMV/ARQC — refuses real PIN/key material by design |
| Telecom | SUCI, NEA/NIA, N32, MILENAGE/TUAK, key hierarchy — 61 tests |
| Frontend | Route guards, server-verified RBAC, error boundary; 118 tests; typecheck and build clean |
| CI | Installed and running 5 jobs, including PostgreSQL parity |

**Position to take with a bank:** a credible product for a supervised pilot on
one bank's source repositories, on its own instance, with findings reviewed by
a human before anyone acts on them. Not yet ready for unattended production
scanning of a live core-banking estate.

That position is defensible, and it is the one that gets you the pilot. The
overclaim is what loses it.
