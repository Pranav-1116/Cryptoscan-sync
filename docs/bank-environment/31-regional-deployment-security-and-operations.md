# 31 — Regional deployment, security boundaries and operational scale

[Guide index](README.md) · [Program](27-international-bank-scan-program.md) ·
[Engineering backlog](33-international-bank-engineering-and-rollout.md)

**Status:** target operating architecture and qualification requirements. Local
Compose/Kubernetes definitions, RBAC and tenancy are building blocks; they do
not prove every control below is implemented, enabled or bank-qualified.

The current [supported-topology statement](../README.md) is one deployment per
customer. The existence of tenant guards does not approve shared hosted banking
infrastructure or automatic regional federation. Qualify any more complex design
before presenting it as supported.

## 1. Start with data-flow and trust boundaries

Define boundaries for bank, legal entity, jurisdiction, region, supplier,
network zone and environment. They need not map one-to-one. A vendor operating
in one country can process a bank deployment hosted elsewhere.

Where appropriate, prefer separate regional deployment/evidence planes over an
untested shared global database. The choice must be reviewed against the bank's
availability, administration, outsourcing and data-handling requirements.

| Plane | Typical responsibilities | Sensitive boundary |
|---|---|---|
| Zone collector | Approved local reads, bounded staging, execution receipts | Target credentials and local network reach |
| Regional execution/control | Work admission, credentials, worker budgets, stop state | Legal execution authority and supplier permissions |
| Regional evidence | Detailed observations, original supplier documents, lineage | Source/IP, internal topology, identifiers and retention |
| Regional analysis | Six BOMs, scoped histories and service exposure | Derived answers can reveal more than individual facts |
| Optional global governance | Explicitly permitted summaries and gap status | Aggregation and inference can still disclose restricted facts |

This federation is a proposal, not a claim that current deployment manifests
provide automatic region routing, residency enforcement or regional disaster
recovery. Start with bank-controlled isolation where the software is unqualified.

## 2. Treat residency as an end-to-end property

Review raw evidence, source staging, databases, object stores, search indexes,
caches, queues, metrics, logs, traces, crash dumps, backups, support bundles,
email/issue exports and browser downloads. Removing raw source from a central
report does not make the rest of the pipeline automatically export-safe.

Create an approved flow inventory: initiator, destination, identity, purpose,
fields, transport, retention, region and reviewer. Include DNS, time services,
cloud APIs, certificate revocation checks, image pulls, advisory feeds and
telemetry endpoints. “Air-gapped” is false if an enabled dependency still calls
outside the approved boundary.

Country/legal analysis is specific to the entity and data. Frameworks such as
EU GDPR/DORA, UK financial-sector rules, RBI/MAS guidance or US bank obligations
may be relevant, but applicability, contractual duties and current requirements
must be reviewed by the bank's specialists. These guides neither assert that
all data must stay in every country nor provide legal/compliance certification.

## 3. Identity and authorization beyond a single tenant

Required reviews include:

- Bank SSO/MFA, provisioning/deprovisioning, session revocation and break-glass.
- Separation of reader, collector operator, scope approver, relationship writer,
  vendor manager, evidence exporter and platform administrator.
- Country/legal-entity restrictions, supplier visibility, environment and purpose.
- Service/workload identities with bounded lifetime and approved credential stores.
- Explicit approval and audit for cross-boundary disclosures and platform access.

Existing roles alone do not prove all these distinct duties are implemented.
Tenant identity must be derived from authenticated authority; a caller-supplied
country, tenant or supplier field is not authorization.

### Current tenancy distinction that matters

[ORM tenancy](../../services/database/db/tenancy.py) permits ordinary inventory
reads of own plus platform/unattributed rows. Step 10 makes derived run/twin/
graph/watch history exact-estate to prevent shared aggregate disclosure. These
are intentionally different policies.

Before multi-bank use, inventory every `NULL`/platform record and its origin.
Do not put confidential bank observations into shared platform inventory. A
future explicit sharing policy should distinguish curated public reference data
from sensitive observations, with reviewed migration and compatibility tests.
Do not silently relabel historical rows or assume an identifier's absence makes
data public.

If two countries share one tenant today, that fact alone does not enforce
intra-tenant residency or regional access. Design/test additional boundaries or
use separately controlled deployments until such authorization is qualified.

## 4. Carry authority through every asynchronous boundary

The queue, scheduler and worker need authenticated work scope, approval revision,
execution region, target profile, expiry and result destination. Enforce current
revocation/stop policy before execution, not only when the work was submitted.
A queue message must not be able to select a more privileged tenant or worker.

Use per-job database/session and credential contexts. Thread/process pools,
retries and background tasks must not inherit another job's tenant or leave
privileged context active. Include bank/region/scope in cache keys and invalidate
according to policy; never reuse a privileged cached graph for a bank reader.

Test these paths, plus events, WebSockets/SSE, report export, object downloads,
metrics and audit packs. API route isolation alone is not an end-to-end proof.

## 5. Privileged collection needs a smaller attack surface

Separate credential acquisition/clone from parser execution. Source and vendor
artifacts are untrusted even when they came through an approved supplier. Use
fixed executable adapters, bounded inputs, disabled external entity/network
resolution and no automatic build/install hooks. Never execute a command
embedded in a BOM, questionnaire, file name or source comment.

The current [static-parser isolation contract](../dev/scanner-isolation.md)
requires production container mode and an immutable, locally available image;
missing runtime prerequisites fail closed. Stock Compose does not provision a
complete qualified parser runtime. Do not resolve this with privileged mode or
an unrestricted rootful Docker socket in the worker.

Other stages—clone, image extraction, cloud/TLS collectors and reporting—need
separate boundaries and tests. A sandboxed source parser is not proof that the
whole pipeline is sandboxed. Define safe temporary-file cleanup and historical
snippet retention; redacted UI fields do not erase raw stored secrets.

## 6. Capacity: distribute control, not uncontrolled load

Current [worker pool](../../services/worker/worker/core/pool.py) provides local
bounded concurrency. [Admission](../../services/api/api/security/scan_admission.py)
provides safety/backpressure checks on admitted paths. They are not proof of
atomic distributed quotas, regional fairness or worst-case bank capacity.

A production scheduler should enforce a hierarchy:

1. Region/site global execution budget.
2. Bank/legal-entity share and priority class.
3. Supplier/provider API quota and credential/session limit.
4. Target/device concurrency and connection/request rate.
5. CPU, memory, disk, output size, deadline and retry budget per job.

Reserve/release capacity atomically across workers. Add jitter/backoff to avoid
midnight scheduled bursts and synchronized retries. Ensure one large supplier
import cannot starve certificate-expiry checks or another bank.

Capacity sizing should measure selected bank workloads. For illustration only,
200,000 observations/day at 2 KiB normalized each is about 391 MiB/day before
indexes, replication, history, logs or raw artifacts. A 90-day retention period
alone does not size backups or source archives. Benchmark real evidence sizes,
query patterns and failure bursts rather than adopting this as a sizing promise.

## 7. Availability, recovery and integrity

The bank must set RTO/RPO and allowable evidence lag per service. Prove:

- Durable dispatch/receipt behavior under worker, queue and DB restarts.
- Idempotent ingestion, bounded replays and no silent success after failed commits.
- Database failover behavior and restored ownership/isolation semantics.
- Backup integrity, encryption, permitted location and restore rehearsal.
- Evidence-chain verification plus separately managed signing trust where used.
- Immutable/historical answers are not rewritten by reprocessing or migrations.

Tamper evidence is not the same as independently enforced immutable storage.
“WORM-ready export” is not proof that bank-controlled object retention/legal
holds are configured. Deletion and privacy obligations can conflict with archive
requirements; retain authorized provenance/tombstones without preserving
unnecessary prohibited payloads, under an approved policy.

## 8. Observability and emergency control

Measure queue age, accepted/partial/blocked/failed targets, stale evidence,
provider throttles, collector heartbeats, commit failures, parser resource use,
credential expiry and receipt lag. Avoid exposing high-cardinality internal
identifiers in an unrestricted monitoring plane.

Define a stop hierarchy: target, supplier, zone, region and program. A stop must
refuse new work and make in-flight operations terminate within agreed safe
bounds. Test propagation during a control-plane partition; expiry/timeouts and
network controls should fail closed rather than permit indefinite work.

Do not claim current admission guarantees all these stop scopes on every path.
Use route restrictions and bank network controls until implementation and
qualification establish the required uniformity.

## 9. Platform supply chain and operational ownership

Build approved images from pinned dependencies, scan the scanning platform,
verify provenance, sign according to bank policy and promote through an internal
registry. Maintain offline feed/update packages with dates and compatibility
checks. Document emergency patches and rollback without broadening privileges.

Assign on-call ownership for the platform, each collector and each vendor
integration. Support access must be time-bound and auditable; source/evidence
bundles must not be sent to external support by default. International banks
need follow-the-sun coordination without turning global convenience into global
unrestricted access.

## Implemented increment versus regional authority

[Guide 44](44-queued-authority-and-durable-ssh.md) now rechecks persisted queue
ownership/options and current initiating authority before a QUEUED-only claim;
it does not yet bind every job to a legal entity, execution region, positive
scope revision or original authenticated request provenance.
[Guide 45](45-redis-tls-sentinel-qualification.md) supplies verified realtime TLS/
Sentinel controls and local fault evidence, not multi-region residency or DR
acceptance. The regional controls and approval evidence proposed above remain
necessary.
