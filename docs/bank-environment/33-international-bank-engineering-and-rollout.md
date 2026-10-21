# 33 — Prioritized improvements and gated international-bank rollout

[Guide index](README.md) · [Failure register](32-bank-scan-failure-modes-and-qualification.md) ·
[Worked assessment](34-worked-international-bank-assessment.md)

**This is a proposed backlog, not completed engineering.**
The [A01 first API delivery](35-network-admission-and-durable-collection.md) is
now implemented locally, followed by the
[scheduled TLS worker delivery](36-worker-scheduled-tls-admission.md) and
[NETWORK monitor lifecycle isolation](37-network-monitor-lifecycle-isolation.md) and
[bounded phase admission](38-monitor-network-phase-admission.md) and
[explicit bounded TCP monitor discovery](39-bounded-tcp-monitor-discovery.md).
The supporting [exact-estate HTTP history increment](40-exact-estate-http-history.md)
closes the specific job/network-run platform-history gap, not all A02 surfaces.
The subsequent [WebSocket history increment](41-exact-estate-websocket-history.md)
adds binary/event socket authority checkpoints and pre-queue estate filtering,
without certifying every streaming/export interface. The
[estate streams/GraphQL/export delivery](42-estate-streams-graphql-and-exports.md)
now extends those reviewed boundaries and adds retained per-estate pagination.
[Broader qualification](43-a01-a02-qualification-and-open-blockers.md) records
local/standalone-Redis evidence, explicit restrictions and known queued failures.
A01 as a whole and the remaining enterprise items are
still open. The prior ten steps
are locally delivered as recorded in [guide 26](26-bank-negative-tests-and-backend-qualification.md).
Their external qualification and the broader enterprise work below remain
separate. Scope these items to the bank's actual deployment; not every pilot
needs global federation before it can import one approved offline document.

## 1. Source-backed starting point

| Area | What exists in this checkout | What must not be inferred |
|---|---|---|
| Network safety/persistence | Admission/validation and persisted scan paths; documented route differences | All aliases have identical stop/window/budget and NBOM-ledger behavior |
| Static parsing | Production isolation launcher, guards, immutable-image requirement and local tests | Stock Compose provisions the approved runtime or live escape resistance is proven |
| Tenancy/history | ORM guards, async job tenant field, exact-estate derived history and bank-negative tests | Region/legal-entity ABAC or every background/export/cache path is globally qualified |
| Concurrency | Local bounded pool and admission/backpressure | Distributed atomic reservations, fairness or provider-wide quotas |
| Vendor inventory | Vendor/profile/import views and provenance-bearing VBOM | Every vendor has a working adapter, trustworthy signature or complete subprocessor evidence |
| Connectors | Guarded SDK interface and extension structure | The SDK's catalog/docstrings mean all named integrations are implemented and qualified |
| Mainframe crypto | Legacy-language/configuration/key-metadata parsers | Universal live mainframe inventory or general core-banking functional validation |
| Coverage/dependencies | Independent caps/horizons, identity/lifecycle/mode/provenance and immutable history contracts | Complete bank discovery, observed failover or predicted operational loss |
| Production evidence | Local regression and opt-in live qualification scaffolding | PostgreSQL/Neo4j/device/country deployment certification |

Inspected references:
[route map](08-implementation-map-and-limits.md),
[network handler](../../services/api/api/routers/network.py),
[admission](../../services/api/api/security/scan_admission.py),
[parser contract](../dev/scanner-isolation.md),
[job envelope](../../services/worker/worker/core/job_consumer.py),
[pool](../../services/worker/worker/core/pool.py),
[connector SDK](../../services/connector_sdk/connector_sdk/base.py),
[tenancy](../../services/database/db/tenancy.py).

A code review finding is not a live-bank result. This documentation update does
not repair the identified route differences or add a regional control plane.

## 2. Priority definitions

- **P0 — must close or explicitly constrain before the affected production use.**
  A safe offline pilot may avoid an unqualified active path; that is a restriction,
  not proof the path was repaired. Unacceptable safety/disclosure risks block use.
- **P1 — required for controlled expansion and repeatability.** Manual controls
  can sometimes bridge a small pilot, with an owner and expiry.
- **P2 — optimize after safety, identity and coverage are demonstrable.**
  Better dashboards cannot compensate for missing authorization or provenance.

## 3. P0: protect the bank and its evidence

| ID / owner | Improvement | Acceptance evidence |
|---|---|---|
| A01 Platform + network security | One enforceable admission/receipt contract for direct, scheduled and queued scans; no unreviewed bypass | Same target refused across all paths for expired scope, stop, wrong region/window and exhausted budget; successful admitted probes have durable ledger linkage |
| A02 Security + data owners | Explicit inventory sharing policy and regional/legal-entity access architecture; audit legacy platform records | Classified ownership register; defined cross-bank/same-tenant regional denial and export tests; reviewed migration/segregation plan |
| A03 Runtime + infrastructure | Provision and qualify production parser isolation plus separate hostile-input/extraction boundaries | Approved runtime/image/staging, positive scan and no-secret/no-egress/resource/cleanup negatives; no privileged shortcut |
| A04 Identity + execution team | End-to-end job authority, revocation, regional destination and retry context | Interleaved banks, thread reuse, forged queue envelope, revoked queued identity and expired approvals produce no unauthorized execution or disclosure |
| A05 Operations + collector owners | Canary profiles, per-device/provider limits and stop propagation | Measured connection/API/session bounds, bounded in-flight stop and safe fail-closed control-plane outage behavior |
| A06 Evidence + database team | Durable collection receipts and completeness-gated reconciliation | Commit/ack failure and duplicate/out-of-order/partial delivery tests preserve history and prevent false deletion or success |
| A07 Assurance + service owners | Actual integration and operational qualification | Live disposable PostgreSQL/Neo4j evidence where used, representative vendor/runtime tests, approved restore and canary sign-off; not-run items remain open |

At planning commit `f901b775`, the direct `/api/v1/network/scan` handler lacked
admission and the alias/discovery paths lacked probe-ledger writes. The
[A01 first delivery](35-network-admission-and-durable-collection.md) closes those
four API-path differences with bank tests and durable transaction guards. The
[second delivery](36-worker-scheduled-tls-admission.md) extends the contract to
scheduled TLS worker owner batches. The
[third supporting delivery](37-network-monitor-lifecycle-isolation.md) isolates
the separate monitor lifecycle. The
[bounded phase delivery](38-monitor-network-phase-admission.md) now admits and
records TLS/IPsec/explicit-resolver DNSSEC monitor plans. The subsequent
[bounded TCP delivery](39-bounded-tcp-monitor-discovery.md) admits explicit IPv4
CIDR/port monitor sweeps, tightens range grants to exact estate and separates
receipt metadata from crypto observations. Expanding scope/plugins remain refused.
A01 remains partial: other executors, granular grants, real budget enforcement
and deployment qualification are not implied. The current
[guide 08 matrix](08-implementation-map-and-limits.md) records this update.

For A02/A04, do not remove existing guardrails or reinterpret NULL history as
shared to make a test pass. Preserve curated inventory compatibility through an
explicit design rather than a sweeping ownership rewrite.

For A05, connector `mode="passive"` currently expresses a nonmutating SDK mode;
it must not be sold as proof of zero network packets. Distinguish nonmutating
API reads, active network observations and truly passive capture processing.

## 4. P1: make multi-vendor coverage repeatable

| ID / owner | Improvement | Acceptance evidence |
|---|---|---|
| A08 Asset governance | Versioned expected-estate ledger and reconciliation by class/region | Every registered target accounted for, explicit unknown register completeness, unresolved duplicates/owners retained |
| A09 Vendor management + ingestion | Supplier evidence schedules, quarantined import and trust/verification state | Wrong-customer/build, malformed, old, oversized, unsigned and untrusted-signer cases handled explicitly |
| A10 Adapter team + vendor | Product/version-qualified adapters and capability manifests | Golden/negative samples, required API permissions, format/encoding coverage, error/pagination behavior and declared exclusions |
| A11 Application/release team | Extend exact artifact/deployment/listener/hardware bindings to actual bank sources | Measure/import admitted release evidence; unresolved mappings stay missing, not name-inferred |
| A12 Scheduling team | Distributed fair quotas, reservations, checkpointing and bounded retry | Multi-bank/provider saturation tests, no starvation beyond agreed SLO, recovery without replay storms |
| A13 Data architecture | Regional evidence planes and controlled optional federation | Tested routing, storage/backup/support/export handling and policy-denied cross-boundary transfer |
| A14 Detection/crypto team | Measure detector quality and enrich unsupported facts without inventing certainty | Reference corpus by language/product/version; false-positive/negative review, rule versions and regression gates |
| A15 Schema/UI + risk owners | Preserve unknown/not-evaluated vs false/zero across supplier/PQC/coverage views | Missing fields and boolean legacy imports cannot appear as tested assurance; migration and legacy-view tests |

A10 should prioritize the bank's highest-criticality evidence gaps, not the
largest marketing connector count. One vendor may require several adapters for
different product lines and versions. Unsupported methods stay visible.

### A14/A15: practical detector and interpretation improvements

Build bank-approved reference cases for crypto wrappers, dynamically loaded
native providers, generated configuration, legacy dialects and proprietary
metadata formats. Include negative examples: an MD5 nonsecurity checksum is not
the same use case as an authentication primitive; test fixtures are not production
usage; a library packaged in an image is not necessarily invoked. Retain purpose,
origin and evidence rather than applying one algorithm-name severity everywhere.

Preserve original vendor terms when normalizing algorithms, key usage and
capabilities; do not silently equate distinct variants or infer key size from an
ambiguous command name. Separate TLS symmetric suite, key-exchange group and
certificate signature. Record cryptographic-module operating-mode/version scope,
not just a product's certification label. Compare known-answer results by
format/version and make unsupported/dynamic behavior explicit.

Keep advisory applicability separate from detection: exact component/release,
configuration, feed age and vendor support status matter. A stale/no-match feed
is not evidence of no vulnerabilities, and a generic upgrade recommendation
needs vendor compatibility/change review before deployment.

## 5. P2: improve efficiency and response

- Event-driven targeted collection after release/certificate/firmware changes,
  with periodic full reconciliation to recover missed events.
- Differential artifact analysis and local caching with scope-safe keys; retain
  exact provenance and avoid cross-bank content-existence side channels.
- Better owner workflows, vendor disputes and ticket integrations with restricted
  exported fields; ticket closure is not proof of verified remediation.
- Approved offline feed/update automation, freshness visibility and applicability
  review for vulnerabilities and cryptographic policy changes.
- Capacity/query/storage tuning based on measured workloads, not removed caps or
  fabricated native completeness. Preserve unknowns and independent denominators.
- Bank-approved crypto migration planning and test evidence; do not automate
  production key changes, predict payment loss or promise failover success.

## 6. A sensible sequence with stop/go gates

### Gate 0 — charter and permitted design

Inventory critical services, suppliers, countries and data flows. Agree success,
known exclusions and legal/contract permissions. Choose local vs regional planes.
**Stop** if the target owner, evidence destination or collection authority is unknown.

### Gate 1 — offline evidence pilot

Use approved sanitized samples for one service: source/SBOM, supplier package,
public certificate, hardware metadata and legacy extract where relevant. Verify
identity, provenance, quarantine behavior and safe unknowns.
**Stop** if input handling leaks secrets or invents deployment relationships.

### Gate 2 — low-risk authorized live canary

Qualify runtime, admission, credentials, destination checks, persistence, rates
and stop with one representative target. Collect operational metrics.
**Stop** on service degradation, unsafe egress, wrong ownership or missing receipts.

### Gate 3 — one critical-service assessment

Bring its actual vendors and regional dependencies into the register. Reconcile
all required evidence surfaces, including DR and supplier blind spots. Business
owners review modeled exposure separately from continuity testing.
**Stop expansion** if critical gaps lack an accountable risk owner/control.

### Gate 4 — regional scale

Prove quotas, fairness, restart/retry behavior, retention, export boundaries,
backup/restore and operational support. Add adapters by demonstrated need.
**Stop** if local successes cannot be reproduced under expected concurrency.

### Gate 5 — multinational governance and continuous assurance

Federate only permitted summaries. Requalify material changes, monitor freshness,
review vendor renewals and keep evidence/exception ownership current.
Global dashboard adoption is not the final security test; repeat the lower gates
when authority, architecture, methods or versions materially change.

Schedule estimates must follow bank approvals and vendor lead times. An assumed
“90-day full-bank rollout” is not a defensible commitment before those inputs.

## 7. Definition of done for an improvement

Each backlog item needs a design, current/proposed distinction, owner, threat
cases, compatibility/migration plan, executable positive/negative tests, failure
telemetry, rollback/containment procedure, operator runbook and reviewed evidence.

Record unit/double, actual backend, adapter and production-canary evidence
separately. A local green test is an implementation milestone, not the bank's
approval. A manual compensating control needs an expiry and a route to a tested
permanent control.
