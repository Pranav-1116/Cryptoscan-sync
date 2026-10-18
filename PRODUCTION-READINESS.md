# CryptoScan production readiness — current evidence gate

**Current as of:** 2026-10-17 UTC
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

The checked-in report was regenerated on **2026-10-16 UTC** against evidence
commit `176044d1` (the report itself is committed in the follow-up commit, per
the repository's binding convention), on a **clean tree** — `dirty: false`,
branch `arena/bb4b80dd-cryproscan`, environment `development`. It supersedes
the capture at `cba7885b` (round 78), which predated rounds 79–80; the
verdicts did not move, and the engineering subchecks are byte-identical to the
previous capture apart from `captured_at`.

**The four PASS categories rest on the retained 2026-10-04 qualification
artifacts, re-supplied unchanged.** No new qualification run happened on
2026-10-16, so those statuses describe the 2026-10-04 environment, not the
current one — the report records the artifact digest for each so the distinction
is checkable.

**PostgreSQL DR is PASS** (`docs/readiness-evidence/postgres-dr-drill-2026-10-04.json`:
35/35 checks, promotion RTO 0.103 s, marker RPO 0 s, full row-count
preservation, API failover HTTP 200, real worker recovery probe, clean
pg_dump/psql restore of every table including the hash-chained audit log).
**Integrations is PASS** (`burn-in-2026-10-04.json`: HMAC-signed GitHub webhook
round-trip through the Redis queue and worker, TLS 1.3 negotiation, SMTP
delivery) — *partial scope*: cloud, Neo4j and container probes were not in
scope of that qualification environment. **Compliance is PASS**
(`compliance-burn-2026-10-04.md`: 11/11 over live HTTP — evidence pack, JWS
attestation sign/verify/tamper-reject, WORM retention, auditor key separation,
capacity forecast). **Load/soak is PASS** (`load-test-2026-10-04.json`:
7 559 requests, 0 errors, 100 % HTTP 200; `soak-2026-10-04/`: 3/3 cycles with
the evidence chain re-verified each cycle and flat RSS) — a *short-run*
qualification; a multi-day production soak is still required for capacity
claims.

The engineering subchecks for exception triage (0 unresolved handlers),
route authorization (**896 decorated routes, 896 auth-covered-or-exempt, 0
uncovered**), frontend authorization (0 direct role/localStorage references)
and tenant isolation (115 scoped tables, 12 justified platform-scope tables,
1 `platform_scope()` site, 0 violations) are **PASS**; engineering as a whole is
**FAIL** because immutable image policy is unresolved (three mutable template
references; the release registry was unreachable from the qualification
environment, so no digest-pinned manifests could be rendered), the
branch-protection API query was refused for the automation credential
(403 — Administration scope not granted), and the COBOL/PL/I/RPG
customer-sample hooks have no customer corpora ("corpus evidence is not
customer validation"). HSM, readiness-closure and external-attestation
categories remain **SKIP** — those require provider-controlled or customer
evidence that a repository session cannot produce.

**Verdict: FAIL — 6 PASS / 1 FAIL / 3 SKIP of 10 required categories**,
recommendation *"do not approve production; remediation and/or evidence
collection required"*. As of round 80 the accompanying claim that no in-repo
check is failing is verified rather than asserted: the complete backend suite
passes in isolation as well as in aggregate (7,629 / 34 skipped / 0 failed),
where previously one order-dependent worker test failed on any run that did not
execute `services/api/tests/unit/test_auth_lifecycle.py` first in the same
process. See the JSON report for the complete machine-readable record.

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
   `--release-manifests` to the engineering gate. **2026-10-17 clarification:**
   `.github/workflows/docker-build.yml` now validates builds only (`push: false`);
   it does not publish or supply registry digests. The publishing proposal remains
   historical/staged, and real publication/provenance requires separate review,
   authorization and execution.
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

**2026-10-16 engineering-gate discipline.** Rounds 50–81 (per-round ledger:
`audit_reports/00_ROUND_STATUS.md`) continued the full serial gate before every
push — ruff repo-wide, the complete backend suite (7,649 passed / 34 skipped at
round 81), the Vitest frontend suite (334 tests, clean `tsc --noEmit`) — with
`engineering_gate.py` and `bank_readiness.py` evidence regenerated at each push.
Round 81 adds an operator-loop artifact to that discipline:
`scripts/operator_loop_drill.py` drives authorize → scan → evidence → baseline →
drift → owned task → authorized change → rescan → condition-level verification →
pinned report twice against a running API and records every check
(`docs/readiness-evidence/operator-loop-drill-2026-10-16.json`, 123/123 PASS). It
is in-repo evidence on a synthetic corpus-derived estate: it does not substitute
for the customer-pilot (P0-2) or target-topology (P1-2) artifacts above. It found
three defects no unit suite could see, and all three are closed within the round;
the third was recorded as open in the first pass and fixed in the second rather
than patched at the end of an unrelated step — platform-scope journal rows
(`target_id` NULL) were unreachable through `GET /monitor/events`, so the durable
remediation journal could not be read on the endpoint named after it
(`PRODUCT-VISION-AND-GAPS.md` §4.7).
The verdict remains FAIL solely on the credential-blocked categories above;
no in-repo check is failing.

That last claim was NOT true until round 80, and the correction is the point of
the round: one worker test failed on any run that did not happen to execute
`services/api/tests/unit/test_auth_lifecycle.py` first in the same process, and
the aggregate `make test` ordering hid it (7,618✓ reported, 7,617✓ + 1 failed
measured per-service). The failure was not a test artifact — it was a real
refusal path raising `UnboundExecutionError` out of `JobExecutor.execute()`. The
same round fixed the durable-write loss it pointed at (§4.4/§4.8: scans on the
supported SQLite default reported COMPLETED with `cbom_snapshots=0` and
`monitor_events=0`). "No in-repo check is failing" is now verified in isolation
as well as in aggregate: worker 612✓, api 1,743✓, remaining 49 suites + shared
5,274✓.

**2026-10-14 re-verification.** Blockers 1 and 2 were re-attempted with the
current automation credential and remain hard-blocked: the session token is a
GitHub App installation token (empty `X-OAuth-Scopes`) that reports
`admin: true` on this repository but cannot push workflow files (rejected:
*"without `workflows` permission"*) or set branch protection (403
*Resource not accessible by integration*). In the same session the
engineering gate was re-run at the current HEAD: its one in-repo fixable
failure — a tenant-isolation violation where
`GET /compliance/evidence/packs/{id}` bypassed the ORM tenant filter with a
plain PK lookup — was fixed (`filtered_get`) and pinned by an adversarial
cross-tenant test; the audit now reports 114 scoped tables, 0 violations.
The refreshed evidence is in `docs/readiness-evidence/engineering-gate.json`
and `bank-readiness.json`; the verdict stays an honest FAIL on the two
credential/registry-blocked checks.

For the end-to-end plan from this state to production sign-off — every
remaining phase with owners, commands and acceptance criteria — see
[`docs/PRODUCTION-ROADMAP.md`](docs/PRODUCTION-ROADMAP.md).

For detailed database history and resolved versus open implementation gaps,
see [`BACKEND-DATABASE-GAPS.md`](BACKEND-DATABASE-GAPS.md). For operational
procedures, see [`docs/ops/production-checklist.md`](docs/ops/production-checklist.md)
and [`docs/production-evidence.md`](docs/production-evidence.md).

## 2026-10-17 — internal release-automation implementation update

The CI coverage gap has a local implementation, not a new readiness approval:
all 54 service/shared test roots are discovered automatically; frontend tests
run before the build; a final `ci` check rejects failed/cancelled/skipped
prerequisites; scanner safety, actual SQLite/PostgreSQL migration chains, and
non-publishing image builds replace the three empty workflow placeholders.
The migration lanes require executed, unskipped proof, not merely pytest exit 0.
The production-config acceptance fixture was also brought into line with the
current mandatory Redis, host, signing/API-key, metrics and Neo4j fields; it
uses synthetic values, not deployment secrets.

All 56 existing dependency pins were retained and 37 missing test/provider and
transitive pins added; CI installs with the lock as constraints. This is not a
hash-verified lock or an immutable runtime image: the Dockerfile dependency
install and registry signing/provenance remain release work. Secret scanning is
still staged, and no branch-protection change or successful GitHub run has been
observed. Local checks and explicit Docker/PostgreSQL/actionlint limitations are
recorded in [release automation](docs/dev/release-automation.md) and the round
ledger. Earlier dated readiness artifacts are unchanged and must not be read
as qualifying these changes.

## 2026-10-17 — static source-parser isolation implementation update

Both worker source-parser launch paths now enforce container mode in production
and require a preloaded immutable scanner image. Development/test inline mode
is retained and explicitly recorded as not isolated. The Docker command requests
non-root/no-capabilities/no-new-privileges, no network, read-only input/root,
hidden Git clone configuration and memory/CPU/PID/fd/tmpfs limits. The adapter
validates a minimal bounded JSON protocol, checks runtime restrictions, verifies
the source-binding marker, rejects source special files and enforces a separate
whole-parser watchdog. The parent bounds all CLI I/O, rejects invalid/failed
results, performs explicit failure cleanup and persists execution policy.

**This is not closure of hostile-input or production readiness.** Local tests
exercise contracts and harmless subprocesses, not a real Docker boundary. Docker
is unavailable in this sandbox. The stock worker image lacks the CLI and the
production private tmpfs staging is not daemon-visible. An operator-reviewed
runtime, preloaded digest and same-canonical-path shared staging are deployment
prerequisites; production now fails closed without them. No unrestricted host
socket was mounted and no image was built/published/deployed. Clone, parent
language discovery, other collectors and downstream stages remain credentialed
worker operations outside this source-parser boundary. Custom container seccomp
profile qualification, hostile-input/escape/resource tests, credential denial,
daemon-loss/orphan cleanup and multi-architecture positive runtime evidence
remain open. Details: [scanner isolation](docs/dev/scanner-isolation.md).

Earlier readiness gate artifacts have not been regenerated and do not qualify
this implementation. The current production decision remains unchanged.

## 2026-10-17 — notification delivery reliability implementation update

The manual drain now uses durable per-destination receipts (Alembic 0096), not
a 2,000-event JSON registry that suppressed failed/air-gap sends and later
replayed evicted successes. Event/destination/routing/receipt selection is
tenant-exact, including the platform estate. Discovery and the feed filter
before LIMIT; retries retain a minimal immutable envelope. Expiring atomic
claims and token fencing protect ordinary concurrent drains, with no database
transaction held during HTTP. Failed/skipped destinations remain retryable
after persisted backoff, and successful peers are not resent.

The protocol is explicitly **at-least-once**, not exactly-once. Receivers must
honour the stable Idempotency-Key to deduplicate an ACK followed by a sender/DB
failure. Durable receipt/audit failure returns an unconfirmed operation, never
a fabricated success. HMAC now covers the exact transmitted JSON bytes. The UI
shows pending/unknown/unconfirmed states rather than treating an empty drain as
proof of delivery. Fixed-literal SQLAlchemy tenant inserts were corrected with
foreign/dynamic/runtime-override guard tests. A reproduced cached-ORM flush
write/delete loophole is also closed: foreign/platform rows loaded before a
tenant scope cannot bypass exact-owner checks through the identity map; expired
instances and mixed-batch rollback are covered. Cached-read/session-reuse and
all relationship/cascade policies are not thereby certified. Shared notification routing writes have explicit admin/CISO
role enforcement.

Migration 0096 preserves observed successful destination audits and converts
old whole-event registry IDs into **legacy_unknown** tombstones, not delivery
claims. Lost registry/audit history cannot be reconstructed, unknown redrive is
an operator decision, and receipt/scoped-routing-bearing downgrade is refused.
Existing datasets require a reviewed migration/handoff, not create_all or mixed
old/new drains. No deployment migration or external receiver was run here.

This closes an internal reliability implementation gap only. Positive
PostgreSQL runtime/migration evidence, real signed provider acknowledgement /
ingestion / receiver deduplication, crash/lease/load qualification, retention
and unknown-history redrive, SMTP and a scheduled notification worker remain
OPEN. The readiness decision and earlier signed/external evidence categories
are unchanged. See [notification delivery](docs/dev/notification-delivery.md).

## 2026-10-17 — opt-in notification scheduler implementation update

Round 85 closes the **automatic-drain implementation** gap from round 84 with a
separate notification process and optional Compose profile, both off by default.
The operator must explicitly select platform and/or registered active tenant
UUIDs and a matching declared processing region for tenants. There is no
automatic new-tenant enrollment. This is a declared-policy check, not proof of
where infrastructure actually runs or universal residency enforcement.

Each estate gets a fresh session/context. Bounded round-robin ticks advance past
busy/failed scopes, reuse durable per-destination leases/backoff/idempotency and
do not run inside scan workers or the monitor loop. SIGTERM/SIGINT stop future
sends at observed boundaries while finalizing an in-progress ACK; unsent claims
recover by lease expiry. No hard DNS/HTTP deadline or exactly-once guarantee is
introduced. Cursor fairness is process-local, not restart-durable. One-shot
mode supports exactly one estate to prevent repeated cron prefix starvation.

Production requires PostgreSQL and the current migration head. The profile has
no public port, Redis/Neo4j dependency or blanket API-secret inheritance. A
metadata-only tick summary distinguishes blocked/failed/unconfirmed work and
visited-scope pending/legacy-unknown counts; it is not global readiness or
provider ingestion. Transport operational logs no longer repeat raw endpoints/
exception text; HTTP client URL logs are quieted in this dedicated process.
Controlled audit excerpts keep their existing access/retention obligations.

Local SQLite/fake-HTTP and one-shot CLI smoke validation does **not** qualify
PostgreSQL, an actual Compose/image deployment, process supervision, physical
residency, receiver ingestion/deduplication, clock skew/crashes/load or customer
field data. SMTP and unknown-history redrive/retention remain OPEN. No
deployment, migration against a customer dataset or real outward delivery was
performed. Existing external/signed readiness verdicts are unchanged. See
[notification scheduler operations](docs/dev/notification-scheduler.md).

## 2026-10-18 — read-only receipt diagnostics implementation update

Round 86 closes the operator visibility gap: receipt backlog/history can be
inspected without triggering another outward send. Admin/superadmin/CISO reads
require exact tenant_id AND scope_key (platform is platform-only), returning
state/time counts and bounded newest-created keyset pages. A safe SQL projection
omits envelope/details, endpoint, raw error/response, lease token and delivery
key; malformed/wrong-estate/filter cursors fail generically. Cursor contents
are navigation, not authorization; estate predicates remain independent.

The notification center distinguishes pending/expired/time-eligible/unknown
from HTTP acknowledgement and unavailable from an observed zero. Filter/page
changes hide stale rows and ignore old replies. Counts/pages are separate live
observations, not frozen snapshots, global health or scheduler/ingestion proof.
No enqueue, claim, retry, legacy reconciliation or deletion is performed by
inspection. Existing audit-detail access/retention remains a separate surface.

Migration 0097 adds an estate/created_at/id index only. Populated index-only
rollback preserves receipts; the earlier data-bearing downgrade refusal is
unchanged. Standard index construction can lock writes and summary aggregates
still scale with an estate's ledger; these are not online/load qualifications.
No deployment schema was migrated. See
[receipt inspection](docs/dev/notification-inspection.md). SMTP, redrive/retention,
scheduler liveness, real DB/provider/crash/load/customer evidence and earlier
external readiness verdicts remain OPEN/unchanged.

R86 dependency-audit follow-up: npm reports 8 existing development-toolchain
advisories (3 moderate / 2 high / 3 critical). Production-only npm audit reports
zero, not general security approval. Vite/Vitest-related major upgrades and
source-map-js remediation remain an explicit hardening task; no blind force
upgrade was used to manufacture a clean result.
