# What to do next — getting CryptoScan to enterprise grade

**Written:** 2026-09-27 · Every claim here was verified by running the code.
Companion to [BACKEND-DATABASE-GAPS.md](BACKEND-DATABASE-GAPS.md), which
records what was broken and what was fixed. This one is forward-looking.

---

## Read this part first

You have built more product than you have evidence for. That is the whole
situation in one sentence, and the plan below follows from it.

The code is real: 5,712 backend tests green on both SQLite and PostgreSQL,
118 frontend tests, a genuine CycloneDX 1.5 CBOM with signing, real `boto3`
across 22 AWS services, real TLS and SSH handshakes, a real JVM constant-pool
bytecode parser, TR-31/ISO 9564/ISO 8583/EMV, and five TS 33.501 5G modules.
That is a credible product.

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
| "eBPF runtime agent" | No kernel code exists anywhere in the repo. The `scanner_id` default is fixed, but `docs/README.md` and `PLATFORM-STATUS.md` still reference "eBPF/mesh agents" | Delete the references, or say "LD_PRELOAD tracer", which is real and works |
| SOC2 CC9.3/9.4 region failover **PASS** | `scripts/region_drills.py:39` simulates a region pair with two temp *directories* in one process; the containerised drill is recorded SKIPPED | Already downgraded in the doc. Either run a real two-Postgres drill or leave it ⚠️ |
| "Precision / Recall / F1 = 100%" | Scored against 842 fixtures written here and tuned against wave by wave | Never quote it externally. Quote the external validation instead |

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
| `/metrics` unauthenticated | `routers/metrics.py` — zero auth dependencies | Leaks estate shape and request patterns to anyone who can reach the port |
| Backups unencrypted at rest | `scripts/db_backup.sh` — no `gpg`/`age` step | A backup of this database is a complete inventory of a bank's cryptographic weaknesses. It is arguably more sensitive than production |
| `:latest` image tags | `k8s/app/20-api-deployment.yaml:23`, `30-worker-deployment.yaml:23` (both carry a `# pin a real tag per release` comment) | No reproducible rollback. During an incident you cannot state what is running |
| OTLP endpoint is dead code | `observability/metrics.py:116,121` — stored, never used | Traces reach a local JSONL only. Either wire it to a collector or remove the parameter so nobody believes it works |
| 134 swallowed exceptions | `except: pass` across services | Each is a failure that will not appear in any log during an incident |

The last one should be triaged, not bulk-fixed: many are legitimate
best-effort paths. Find the ones in **write paths and auth paths** and make
those log.

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

### 3.1 Feed the NBOM

The generator, cascade and DB derivation are built and tested; the
demonstration data was seeded by hand. **Nothing runs a network scan on a
schedule.** Wire the existing network scanner into the job scheduler, write
results to `network_scan_runs`, and the NBOM populates itself.

This is pipeline work, not BOM work, and it is small. It moves NBOM from
preview to beta.

### 3.2 Finish the frontend authorisation migration

`RequireAuth` guards every route and roles are server-verified. But
`RequireRole` exists and **no page uses it yet** — individual controls still
use ad-hoc `canPerformAction()` checks. Those now read verified roles so they
are no longer forgeable, but the migration is unfinished and a reviewer will
notice the inconsistency.

### 3.3 Prove one HSM adapter against real hardware

`keyassure/hsm_backends.py` has real adapters for AWS KMS, Azure Key Vault /
Managed HSM, GCP KMS and PKCS#11. **None has touched a real HSM** — PyKCS11
is not installed and those tests skip.

Stand up SoftHSM2 in CI for the PKCS#11 path, and run the AWS KMS adapter
against a real CloudHSM-backed key once. "Verified key residence" is a strong
claim for a bank; make it true before you make it.

### 3.4 Telecom: GTP-U / IPsec on N3 and N9

The only named gap left in the 5G work. The user-plane interfaces carry
subscriber traffic and have no protection of their own — they need IPsec, and
nothing currently checks whether it is there.

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
| Backend | 5,712 tests green on SQLite **and** PostgreSQL |
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
