# CryptoScan enterprise system — end-to-end target and execution plan

**Planning date:** 2026-10-03 UTC
**Status:** forward-looking implementation and qualification plan
**Audience:** product owners, engineering, security, operations, customer success, and enterprise buyers

> This document explains what CryptoScan must become to operate as an enterprise
> system. It separates repository evidence from work that still needs real
> infrastructure, customers, providers, or independent assessors. It is not a
> certification, a customer attestation, a valuation, or a claim that every
> planned capability is production-ready.

## 1. The short answer

CryptoScan becomes enterprise-level when it is not only a large security product,
but a **controlled, tenant-safe, evidence-producing operating system** for
cryptographic risk:

1. An authorized organization can onboard it without sharing secrets with the
   product team.
2. It discovers only approved assets and records exactly how each observation
   was obtained.
3. Every request, job, artifact, finding, export, and administrative decision is
   attributable to an authenticated principal and tenant.
4. Unknown, unavailable, stale, unverified, or incomplete evidence stays visibly
   unknown or blocked; it cannot silently become green.
5. The same evidence can be replayed into inventory, CBOM/SBOM/HBOM/NBOM/VBOM,
   policy, risk, migration, audit, and customer reports without contradictory
   copies of the truth.
6. Operators can monitor, upgrade, back up, restore, fail over, investigate, and
   roll back the service using tested runbooks.
7. A customer can independently verify the result and an assessor can inspect
   the controls, history, and limitations.

The next move is therefore **proof in risk order**, not another broad feature
list. The repository already contains substantial product breadth. The
enterprise gap is the distance between “the code path exists” and “a real
customer can rely on it under security, availability, evidence, and procurement
requirements.”

## 2. What exists now and what it does not prove

### 2.1 Current repository evidence

The current checkout provides a meaningful engineering foundation:

- Authentication, MFA/session lifecycle, RBAC, API-key controls, tenant
  resolution, tenant-scoped writes, cross-tenant regression coverage, security
  middleware, security headers, rate limiting, audit/event surfaces, and
  fail-closed production checks are implemented and tested in the repository.
- Discovery surfaces include source, network, cloud, container, runtime,
  telecom, payment, hardware, certificate, vendor, and cryptographic inventory
  paths. The exact readiness of each surface remains tiered rather than being
  inferred from the number of routes.
- The evidence model includes content/provenance hashing, sanitization,
  verification/export paths, immutable-style BOM snapshots, and no-secret
  handling requirements. A hash proves that bytes were not changed; it does
  not prove that the original observation was complete or customer-approved.
- The event path supports authenticated realtime delivery and resume behavior.
  Event delivery is not a substitute for a durable audit record or a fresh
  inventory snapshot.
- The live vendor path records connector availability and evidence boundaries.
  A connector that is not configured or cannot authenticate must remain
  unavailable/degraded, not appear as a successful empty scan.
- The repository's last full test execution in this workstream completed with
  **6,330 passed, 15 skipped, and 38 warnings**. Focused security/readiness
  validation also passed. This is engineering evidence from this checkout, not
  customer production evidence.
- The capability table currently distinguishes **33 GA, 30 Beta, and 10
  Preview** console surfaces. The labels describe repository maturity, not a
  promise that every deployment has the required credentials, network reach,
  customer data, or external qualification.

Relevant source-of-truth documents include:

- [`../ROADMAP-TO-ENTERPRISE.md`](../ROADMAP-TO-ENTERPRISE.md) — risk-ordered
  enterprise roadmap and evidence gaps.
- [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md) — release gate and
  external-evidence boundary.
- [`enterprise-readiness.md`](enterprise-readiness.md) — capability-by-capability
  readiness inventory.
- [`CAPABILITY-MATURITY.md`](CAPABILITY-MATURITY.md) — GA/Beta/Preview labels.
- [`architecture/multi-tenancy.md`](architecture/multi-tenancy.md) — tenancy
  model and isolation rules.
- [`security/threat-model.md`](security/threat-model.md) — threat boundaries.
- [`ops/production-checklist.md`](ops/production-checklist.md) — deployment and
  operations checks.

### 2.2 Evidence that is still external

The following must not be claimed merely because a script, manifest, adapter, or
test exists:

| Area | What is still required before an enterprise claim |
|---|---|
| Customer validation | A real customer pilot, approved scope, reviewed findings, triage feedback, and retained accuracy evidence |
| Independent security | An appropriately scoped penetration test, remediation record, and formal exception decisions |
| Disaster recovery | Two real database instances or an equivalent target topology, measured RPO/RTO, restore verification, and retained logs |
| HSM/key providers | Provider-controlled evidence for the selected HSM/KMS deployment, non-exportability, signing, outage, rotation, and audit behavior |
| Integrations | Real IdP, ITSM/SIEM, cloud, registry, network, and notification endpoints tested in the customer topology |
| Capacity | Target-environment load and multi-day soak with thresholds, not only local unit or synthetic tests |
| Compliance | External SOC 2/ISO 27001 or other attestations if required by the customer; repository controls are not an attestation |
| Deployment approval | Immutable production image digests, approved change records, rollback evidence, and named operational owners |
| Data governance | Customer-approved retention, residency, deletion, export, subprocessors, and incident-notification decisions |

A missing external artifact is **SKIP or BLOCKED**, never PASS by implication.

## 3. The target enterprise architecture

CryptoScan should be operated as seven cooperating planes. They may be deployed
as separate services or bounded modules, but their security and evidence
contracts must remain explicit.

```text
Customer users / automation
            |
     Web UI, REST, GraphQL, SSE/WebSocket
            |
  Edge TLS/WAF -> authentication -> tenant resolution -> RBAC/ABAC
            |
       Control plane API and policy decision points
       /          |             |             \
  onboarding   scope        jobs/queues       audit/events
      |          |             |                 |
 secrets refs  connectors  worker/data plane  evidence log
      \          |             |                 /
       authorized discovery and collection adapters
                         |
       normalize -> validate -> deduplicate -> hash/provenance
                         |
       inventory -> policy -> findings -> risk -> migration plan
                         |
       BOM snapshots -> reports/exports -> ITSM/SIEM/customer review
                         |
      metrics, traces, logs, backup/restore, DR, support runbooks
```

### 3.1 Control plane

The control plane owns organization configuration and decisions, not raw
collector credentials. It includes:

- organization and tenant lifecycle;
- users, roles, groups, service accounts, API keys, MFA, SSO, and SCIM;
- approved scopes, asset ownership, connector configuration, schedules, policy
  packs, retention, and export permissions;
- workflow approvals, exceptions, baselines, release gates, and operational
  stop controls;
- audit records for every security-sensitive action.

The control plane must never accept a client-supplied tenant identifier as proof
of authorization. A tenant header can select a tenant only after membership,
status, role, and request context are validated.

### 3.2 Data and discovery plane

The data plane performs read-only or explicitly approved discovery against:

- repositories and build artifacts;
- hosts, containers, binaries, firmware, and runtime observations;
- TLS endpoints, certificates, network services, and authorized network scan
  targets;
- cloud accounts, KMS/key metadata, certificates, and workload inventories;
- telecom, payment, HSM, hardware, and vendor management surfaces.

Each connector must define its access mode, scope, credential reference,
collection time, source identity, authorization status, failure state, and
supported evidence. It must not retrieve private key material or persist raw
secrets as a shortcut to better coverage.

### 3.3 Job and worker plane

Long-running work must leave the request process and execute through a durable,
observable job contract:

1. The API validates the requested target and authorization.
2. The job row is persisted before the request reports acceptance.
3. The payload includes a verified tenant identifier and an immutable job ID.
4. The worker re-enters the tenant scope before reading or writing data.
5. Retry and lease behavior is idempotent; a retry cannot create contradictory
   findings or duplicate evidence.
6. Progress, stage errors, cancellation, and final status are attributable and
   auditable.
7. A queue, worker, or dependency outage produces an explicit unavailable or
   blocked state.

A background worker must not inherit an ambient request context by accident and
must not run unscoped because the original HTTP request has finished.

### 3.4 Evidence plane

Evidence is the product's trust boundary. Every observation should carry:

- source and connector identity;
- tenant and asset identity;
- collection timestamp and freshness/expiry state;
- method, scope, authorization, and configuration status;
- content/provenance hash or a safe reference to the retained artifact;
- parser/normalizer version where material;
- confidence and limitations;
- sanitization/redaction status;
- links to the finding, BOM component, policy evaluation, and export.

The evidence plane must support four different outcomes, not one boolean:

| State | Meaning | Permitted downstream behavior |
|---|---|---|
| `VERIFIED` | Evidence was collected, validated, and linked to a source | Can support a conclusion within its scope |
| `PARTIAL` | Some fields or sources are missing | Must display limitations and cannot satisfy a complete gate by itself |
| `UNAVAILABLE` | The source was not reachable/configured/authorized | Must remain unavailable; do not infer a clean result |
| `STALE` or `UNKNOWN` | Freshness or interpretation is not established | Must not silently become current or green |

Sanitization must happen before persistence, indexing, export, logging, and
queue publication. It must cover passwords, tokens, private keys, raw key
material, authorization headers, connection strings, and secret-bearing
nested structures. Redaction metadata should say that a value was removed; it
must not create a false claim that the underlying control passed.

### 3.5 Analysis and decision plane

The decision path should remain deterministic and inspectable:

```text
observed asset
  -> normalized identity
  -> evidence/provenance validation
  -> cryptographic classification
  -> policy evaluation
  -> finding and severity
  -> business/context prioritization
  -> dependency/blast-radius analysis
  -> migration/PQC recommendation
  -> human approval or controlled exception
```

AI or heuristics may help search, summarize, or prioritize only where the
product contract permits it. They must not silently decide compliance,
security status, tenant authorization, or destructive remediation. An unknown
algorithm, missing certificate chain, unavailable connector, or unverified
vendor statement must remain explicit.

### 3.6 Delivery and integration plane

Enterprise customers need controlled delivery into their operating systems:

- REST/GraphQL for automation;
- signed or hash-manifested reports and BOM exports;
- ITSM tickets with stable correlation IDs and idempotent retries;
- SIEM events without secrets;
- CI/CD gates that return deterministic policy outcomes;
- email/webhook/notification delivery with delivery status and retry history;
- customer-managed storage or air-gapped export where required.

Each integration needs a contract test, a sandbox test, a failure/retry test,
secret handling review, tenant-scoping test, and an operator runbook. “The
connector class exists” is not the same as “the integration is qualified for a
customer deployment.”

### 3.7 Operations plane

The operations plane makes the service supportable:

- liveness, readiness, drain, dependency, queue, database, and worker metrics;
- structured logs with correlation ID, tenant-safe identity, and no secrets;
- traces that preserve request/job/evidence relationships without raw payloads;
- alert thresholds and on-call ownership;
- backup, restore, failover, rotation, incident, and rollback runbooks;
- release manifests pinned to immutable image digests;
- a release evidence bundle tied to a commit and environment.

## 4. One complete customer transaction

This is the end-to-end behavior to design, test, document, and demonstrate.

### Step 1 — Customer onboarding

An administrator selects the deployment model: customer-controlled
single-tenant, managed tenant, or approved air-gapped installation. The
customer records data residency, retention, support contacts, recovery
objectives, identity provider, allowed egress, and approved collection
boundaries.

The onboarding flow creates organization and tenant records, verifies the
administrator, requires MFA or the configured enterprise IdP, and assigns only
an explicitly approved initial role. It must not create hidden superadmin
access or use a shared default credential.

**Proof:** onboarding audit events, tenant record, role assignment, security
configuration, data-location decision, and a negative test for unauthorized
cross-tenant selection.

### Step 2 — Identity and tenant resolution

A browser, API key, or SSO session makes a request. The edge and authentication
middleware validate the credential. Tenant resolution then validates membership,
tenant status, explicit selection rules, and platform-operator rules. If the
context is unknown, ambiguous, suspended, unavailable, or inconsistent, the
request fails closed.

RBAC answers “may this principal perform this action?” ABAC/scope checks answer
“may this principal perform it on this resource, environment, asset, or
connector?” Database guards provide a second boundary; they do not replace the
request authorization decision.

**Proof:** positive and negative matrix tests for every role, every tenant
selection path, API keys, stale sessions, disabled users, suspended tenants,
missing tenant context, and platform-admin exceptions.

### Step 3 — Scope registration

The customer registers repositories, hosts, endpoints, cloud accounts, network
ranges, vendors, or other targets. Each target receives an owner, tenant,
collection method, schedule, environment, and evidence expectation. A target
must be rejected if it is outside configured roots, outside a tenant's
ownership, unsafe for the requested scan mode, or missing required approval.

Credentials are referenced by a provider/secret name or short-lived resolver;
they are not copied into vendor profiles, evidence records, logs, exports, or
job payloads.

**Proof:** scope approval record, connector health/authorization state
(measured from the outbound delivery audit at `GET /health/connectors` —
registration alone is not health), target validation test, and a sanitized
configuration export.

### Step 4 — Job acceptance

The API validates the request, creates the job transactionally, and publishes a
safe job payload. If persistence fails, the API reports that no job was
accepted. If queue publication fails after persistence, the job enters an
observable retry or blocked state rather than disappearing.

The worker verifies the job tenant and scope again. It records lease owner,
start time, stage, attempt, and cancellation state. A client cannot change the
tenant ID, target, or authorization fields by mutating a request after the job
is created.

**Proof:** database transaction test, queue outage test, retry/idempotency test,
worker tenant test, and audit trail linking request → job → result.

### Step 5 — Collection

The connector performs only the approved read-only collection. It reports
connected, authenticated, configured, unauthorized, unreachable, unsupported,
and partial states distinctly. A collector that cannot verify a source does not
emit a clean empty inventory.

The collector stores safe metadata and an evidence reference. Where raw
artifacts are required, retention, encryption, access, redaction, and deletion
rules apply before an operator or downstream service can retrieve them.

**Proof:** connector contract tests, mock-unavailable tests, real sandbox
integration, no-secret scan, and source authorization evidence.

### Step 6 — Normalize and correlate

The pipeline parses the observation into stable asset, component, certificate,
algorithm, protocol, library, key-metadata, vendor, and dependency identities.
Deduplication keys must be deterministic and tenant-aware. Conflicting
observations remain linked as separate provenance rather than being overwritten
by whichever connector ran last.

A binary/static candidate must not be presented as a live network observation
until an authorized network source corroborates it. A vendor declaration must
remain vendor-reported evidence, not an independent certification.

**Proof:** golden fixtures, parser failure cases, duplicate/replay tests,
conflicting-source tests, provenance inspection, and explicit `observed` versus
`candidate` fields.

### Step 7 — Evaluate policy and risk

Policy packs evaluate the normalized evidence deterministically. The output
contains the rule, input evidence, decision, reason, severity, exceptions, and
freshness. The risk layer adds business context and dependency impact without
changing the underlying evidence.

If a required field is missing, the result should be `UNKNOWN`, `INCOMPLETE`,
`BLOCKED`, or the relevant non-green state. It must not become PASS because a
parser returned an empty list or a connector returned no data.

**Proof:** policy truth tables, unknown-input tests, stale-evidence tests,
exception approval tests, and reproducible evaluation from a saved evidence
snapshot.

### Step 8 — Materialize inventories and BOMs

One normalized state produces linked SBOM, CBOM, HBOM, NBOM, VBOM, vulnerability
BOM, and unified technology-BOM views. Components carry stable references,
version/state metadata, evidence links, and dependency edges. Snapshot creation
is content-addressed or fingerprinted so identical state does not create fake
versions.

The BOM is an evidence projection, not a proof that every component is secure.
A missing layer remains empty or explicitly unavailable. A static NBOM
candidate remains a candidate until network evidence confirms it.

**Proof:** materialization fixture, snapshot fingerprint, diff/compare test,
removal test, export verification, and no-secret artifact scan.

### Step 9 — Review, approve, and act

Findings and migration plans enter an approval workflow. A reviewer can accept,
reject, defer, or create a time-bound exception with reason, owner, expiry, and
supporting evidence. Destructive remediation, rotation, revocation, outage,
certificate replacement, and production changes require separate explicit
approval and safety flags.

Default enterprise behavior is recommendation plus controlled handoff, not an
unreviewed production mutation.

**Proof:** four-eyes approval test, expiry/re-review test, denied-action audit,
rollback plan, and safe dry-run output.

### Step 10 — Export and operate

The customer exports an evidence/report package containing the manifest, hashes,
provenance, policy decisions, findings, limitations, approvals, and generation
metadata. The package can be independently verified without giving the
recipient credentials or secret values.

Operators monitor the job, evidence, queue, database, integrations, and tenant
health. The customer can trace a report back to a snapshot and evidence record,
then trace that evidence back to a scoped collection job.

**Proof:** offline verification, export authorization, tenant filter test,
retention/deletion test, audit-pack review, alert test, and operator runbook
execution.

## 5. Enterprise requirements by control family

### 5.1 Identity, authorization, and tenancy

Minimum enterprise bar:

- OIDC/SAML with issuer, audience, signature, nonce/state, expiry, and PKCE
  validation where applicable;
- MFA and session revocation for local accounts;
- SCIM provisioning/deprovisioning with safe role mapping;
- least-privilege RBAC plus resource/scope authorization;
- tenant resolution that fails closed on ambiguity or lookup failure;
- tenant IDs stamped by trusted server context, not accepted as mutable client
  data;
- API keys with scopes, method/path policy, rotation, revocation, last-use
  controls, and optional network restrictions;
- audit records for login, role, tenant, key, export, policy, exception,
  connector, and destructive-action decisions;
- no default shared administrator or hidden bypass route.

**Acceptance gate:** an authorization matrix is generated from the route list,
all protected routes are covered, cross-tenant reads/writes are negative-tested,
and failed checks produce no data response.

### 5.2 Data protection and secret handling

Minimum enterprise bar:

- TLS in transit and encrypted databases/object storage/backups at rest;
- customer-controlled or approved secret manager integration;
- short-lived credentials where providers support them;
- no credentials in vendor profiles, evidence, logs, queues, reports, URLs, or
  frontend state;
- redaction before persistence and a secret-scanning test over exports;
- key rotation and revocation runbooks with explicit approval;
- documented retention, deletion, legal hold, residency, and backup expiry.

**Acceptance gate:** a synthetic secret corpus passes through every scan,
connector, queue, database, report, audit, and error path; the secret is absent
from all durable and exported artifacts.

### 5.3 Evidence, integrity, and auditability

Minimum enterprise bar:

- immutable or append-only evidence references;
- canonical serialization and deterministic content hashes;
- hash-chained audit events with verification tooling;
- time source and clock-drift policy;
- source, tenant, actor, collection method, freshness, limitations, and
  software version on every material conclusion;
- signed or manifest-hashed exports;
- legal/customer review of evidence retention and deletion.

**Acceptance gate:** an independent verifier can detect a changed evidence byte,
changed manifest, changed audit link, missing provenance, or unauthorized export.

### 5.4 Availability and recovery

Minimum enterprise bar:

- defined RTO/RPO per deployment tier;
- PostgreSQL backup, encryption, restore, integrity, and retention procedure;
- tested queue/worker recovery and idempotent job retry;
- API and worker readiness/drain behavior;
- high-availability topology appropriate to the supported deployment;
- dependency degradation states and operator alerts;
- two-person approval for destructive recovery or production failover;
- retained drill evidence with measured time, not a “script exists” claim.

**Acceptance gate:** execute a controlled backup/restore and failover drill in
the target topology, reconcile records, verify evidence-chain integrity, and
publish measured RPO/RTO with limitations.

### 5.5 Scale and performance

Define capacity in customer terms instead of only process counts:

- number of tenants and users;
- assets/endpoints/repositories per tenant;
- concurrent scans and maximum scan duration;
- events per second and replay window;
- evidence/BOM storage growth;
- report/export size and latency;
- queue depth, retry rate, database connections, and external API quotas.

**Acceptance gate:** run target-environment load and soak tests with thresholds
for p95/p99 latency, scan throughput, queue lag, error rate, memory, database
health, storage, and recovery. Record the exact topology and dataset; never
turn synthetic capacity into an unlimited production claim.

### 5.6 Secure software delivery

Minimum enterprise bar:

- required CI checks and branch protection in the actual GitHub organization;
- dependency, container, secret, static, and license scanning;
- reproducible build metadata and immutable image digests;
- signed release artifacts and verification instructions;
- migration compatibility and rollback checks;
- release notes with security-impact classification;
- security advisories, vulnerability intake, patch SLA, and emergency release
  procedure;
- separation of development, test, staging, and production credentials.

**Acceptance gate:** a clean release can be built, verified, deployed to staging,
smoke-tested, rolled back, and traced to a commit without using mutable tags or
unrecorded manual changes.

### 5.7 Compliance and procurement

Prepare a control evidence room, but label each item correctly:

- policy and procedure;
- technical implementation;
- test result;
- customer/provider evidence;
- independent assessment;
- exception and remediation plan.

A repository control is not automatically SOC 2, ISO 27001, PCI, FIPS, banking,
telecom, or government compliance. Map controls to the customer's framework,
identify the control owner, define frequency, preserve evidence, and obtain
external attestations where required.

## 6. Risk-ordered roadmap

### Phase 0 — Freeze the enterprise contract (week 1)

**Goal:** decide what deployment and customer promise CryptoScan is actually
making.

1. Choose the initial supported model: customer-controlled single tenant,
   managed multi-tenant, or air-gapped. Do not promise all three at once.
2. Write the system boundary: included services, excluded customer systems,
   data flows, subprocessors, egress, and trust assumptions.
3. Select one reference customer profile and one supported deployment topology.
4. Define RTO/RPO, retention, residency, support hours, incident notice,
   customer responsibilities, and scan authorization rules.
5. Freeze the claim register. Every product claim must point to code, a test,
   an internal evidence artifact, or an external qualification artifact.
6. Select release gates and owners. Unknown or missing evidence starts as
   `SKIP`/`BLOCKED`.

**Exit evidence:** signed internal product boundary, control matrix, claim
register, reference architecture, threat model update, and a list of evidence
that can only come from a pilot or external assessor.

### Phase 1 — Close engineering trust gaps (weeks 1–4)

**Goal:** make the codebase safe to operate before expanding feature breadth.

- Keep authentication, tenant resolution, RBAC/ABAC, API-key, route coverage,
  security header, rate-limit, and audit tests mandatory.
- Add a generated authorization inventory so a new route cannot silently omit
  authentication, tenant scope, or permission checks.
- Finish unknown/unavailable/stale-state tests across scanners, vendors, CBOM,
  policy, exports, dashboards, and metrics.
- Run the secret corpus through every persistence, export, log, queue, and error
  path.
- Pin production images by approved registry digest and verify release
  artifacts.
- Require PostgreSQL migration, rollback-compatibility, and tenant-isolation
  tests in the release gate.
- Remove or downgrade claims that are not supported by current evidence.

**Exit evidence:** engineering gate PASS, threat-model review, no open critical
security findings, secret-scan report, route authorization report, and a signed
staging release.

### Phase 2 — Build the operable reference platform (weeks 3–8)

**Goal:** run one realistic customer deployment repeatably.

- Deploy API, worker, monitor, PostgreSQL, Redis/queue, object/evidence storage,
  and observability using a documented supported topology.
- Configure customer IdP, MFA, groups, role mapping, tenant lifecycle, and
  emergency access procedure.
- Configure backup encryption, restore verification, retention, and deletion.
- Execute a staging deployment, upgrade, rollback, queue outage, dependency
  outage, and controlled restore.
- Add dashboards and alerts for API errors, auth failures, tenant refusals,
  queue lag, worker leases, scan age, evidence failures, storage, DB health,
  export failures, and integration delivery.
- Establish on-call ownership, incident severity, escalation, and customer
  communication templates.

**Exit evidence:** deployment package, staging runbook, restore report, alert
screenshots/logs, rollback record, dependency failure drill, and a named
operator who can run the system without the feature developers.

### Phase 3 — Qualify the high-value integrations (weeks 5–12)

**Goal:** connect CryptoScan to the systems an enterprise actually operates.

Prioritize one integration in each category rather than claiming every
connector:

1. identity: one real OIDC or SAML provider plus SCIM if required;
2. ITSM: one ServiceNow or Jira workflow with idempotent retry;
3. SIEM: one supported event format and delivery path;
4. cloud: one read-only provider/account model;
5. source/CI: one repository provider and deterministic gate;
6. network/vendor: one real authorized sandbox connector;
7. storage/export: one customer-approved evidence destination.

For every integration, test authorization, timeout, quota, retry, duplicate,
revocation, secret redaction, tenant ownership, and operator recovery.

**Exit evidence:** sandbox contract tests, customer-topology test report,
configuration guide, failure runbook, data-flow review, and integration owner.

### Phase 4 — Run the first supervised customer pilot (weeks 8–16)

**Goal:** replace synthetic confidence with reviewed field evidence.

Start with the lowest-risk useful scope, normally read-only source repositories
and approved non-production network targets. Agree on:

- assets and environments included/excluded;
- customer data and credential responsibilities;
- scan schedule and change window;
- finding review and correction workflow;
- severity disagreement process;
- support and incident contacts;
- evidence retention and deletion;
- success criteria and exit date.

The pilot must capture false positives, false negatives, missed assets, parser
failures, stale evidence, scan duration, operator effort, useful reports, and
customer corrections. A customer-reviewed triage workbook is more valuable
than another internal fixture corpus.

**Exit evidence:** signed pilot scope, run logs, reviewed findings, accuracy
limitations, customer feedback, remediation record, and decision to proceed,
repeat, or stop.

### Phase 5 — Independent security and resilience qualification (weeks 10–20)

**Goal:** have evidence that is credible outside the engineering team.

- Conduct an external penetration test covering web/API, tenant isolation,
  API keys, worker/job boundaries, exports, integrations, and deployment.
- Run a real two-instance database recovery/failover drill where that topology
  is promised.
- Test encrypted backup restore and evidence/audit-chain reconciliation.
- Qualify the selected HSM/KMS provider path if the product promises key or
  signing operations.
- Run target-environment load/soak with stated thresholds.
- Close, mitigate, or formally accept every finding with owner and expiry.

**Exit evidence:** independent report, remediation closure, DR/load artifacts,
provider evidence, signed exceptions, and updated release gate.

### Phase 6 — Enterprise launch and continuous assurance

**Goal:** make enterprise readiness repeatable instead of a one-time demo.

- Version the supported deployment topology and compatibility matrix.
- Run release gates on every release; do not manually edit a passing report.
- Re-test tenant isolation, auth, secrets, backups, integrations, and rollback
  after material changes.
- Review access, keys, connectors, exceptions, and stale evidence monthly.
- Re-run DR and restore drills on a defined schedule.
- Maintain vulnerability response, customer notification, support, and end-of-
  life procedures.
- Publish a bounded capability/maturity page so GA, Beta, Preview, and
  unavailable surfaces remain visible to customers.

**Exit evidence:** signed release package, current evidence index, control-owner
review, customer support readiness, and a dated decision record.

## 7. First 30/60/90-day execution board

| Time | Must be completed | Evidence required | Stop condition |
|---|---|---|---|
| Days 0–7 | Select deployment model; freeze claims; define tenant/data boundary; name owners; run engineering gate | Approved architecture, claim register, control matrix, risk register | Do not add broad features if the boundary is unresolved |
| Days 8–30 | Harden reference deployment; IdP; secrets; image digests; migration gate; backup/restore; alerting; route authorization inventory | Staging release, restore log, security test report, runbooks | No customer data until secrets and tenant tests pass |
| Days 31–60 | Qualify first IdP/ITSM/SIEM/cloud/network integrations; execute failure/retry tests; prepare pilot | Integration reports, sanitized configs, support procedures | No “supported integration” label without a real sandbox result |
| Days 61–90 | Start supervised pilot; collect reviewed findings; commission pentest and DR/load work | Pilot workbook, accuracy baseline, external scopes, measured operations | No production approval while required evidence is SKIP/BLOCKED |

## 8. Release gates

A release candidate should be evaluated in this order:

### Gate A — Build and dependency integrity

- source revision, dependency lock, migration head, generated artifacts, and
  image digest are recorded;
- security/license/secret/static checks complete;
- no accidental debug or development bypass is enabled.

### Gate B — Authentication and authorization

- all protected routes require the correct authentication path;
- role/action/resource matrix passes;
- tenant resolution and database isolation negative tests pass;
- API-key scopes, revocation, quotas, and audit events pass;
- exports and realtime streams are tenant-filtered.

### Gate C — Evidence and no-secret behavior

- source/provenance/freshness fields are present;
- unknown/unavailable/partial states are preserved;
- secret corpus is absent from durable and exported outputs;
- manifest/hash/audit verification passes.

### Gate D — Operational readiness

- health/readiness/drain behavior passes;
- backup, restore, queue retry, worker recovery, and rollback pass;
- metrics, logs, traces, alerts, and runbooks are available;
- external dependencies are either tested or clearly marked unavailable.

### Gate E — Customer and external qualification

- pilot scope and reviewed field evidence exist;
- independent security assessment is complete or explicitly accepted as a
  release limitation;
- DR/load/soak/provider/compliance evidence matches the promised topology.

The release decision must be one of:

- **PASS:** required evidence is present and within threshold;
- **PASS WITH EXCEPTION:** named approver, scope, compensating control, expiry,
  and customer acceptance are recorded;
- **BLOCKED:** a required control failed or is unsafe;
- **SKIP:** an external dependency or customer artifact was not available.

`SKIP` is not a green result.

## 9. Operating model after launch

### Daily

- review readiness, queue lag, failed jobs, auth anomalies, tenant-refusal
  counters, connector health (`GET /health/connectors`), worker-fleet health
  (`GET /health/worker-fleet` — stuck jobs, stale leases, drain evidence),
  stale evidence, export failures, and integration retries;
- verify no critical security alert is silently suppressed;
- review production changes and active emergency controls.

### Weekly

- review vulnerabilities, failed scans, policy exceptions, stale connectors,
  unresolved findings, audit-chain verification, backup status, storage growth,
  and support tickets;
- sample a report back to its snapshot, evidence, job, actor, and tenant;
- review release and dependency changes.

### Monthly or per release

- rotate or validate credentials and keys according to the customer policy;
- review user/role/API-key/connector access;
- execute or schedule restore and DR drills;
- review retention/deletion and residency controls;
- re-run security regression, integration, and no-secret suites;
- update capability maturity and external evidence status.

### Incident response

The incident procedure must cover credential compromise, cross-tenant suspicion,
evidence integrity failure, database corruption, queue loss, connector abuse,
export leakage, ransomware/availability events, and vulnerable dependencies. It
must define containment, evidence preservation, customer notification, recovery,
root cause, corrective action, and lessons learned. Never delete or rotate
production credentials, keys, certificates, or data as an unapproved test.

## 10. Team ownership needed for the enterprise system

A small team may hold multiple roles, but the responsibilities must be named:

| Role | Owns |
|---|---|
| Product owner | supported deployment, scope, customer promise, maturity labels, priorities |
| Platform/SRE | deployment, capacity, backups, restore, DR, observability, on-call |
| Application security | threat model, auth/RBAC/tenant controls, secrets, pentest remediation |
| Data/evidence owner | provenance, retention, sanitization, export verification, audit chain |
| Scanner/domain owner | connector contracts, parser quality, field limitations, accuracy work |
| Integration owner | IdP, ITSM/SIEM/cloud/network contracts and failure handling |
| Customer security owner | pilot authorization, review, data processing, incident contacts |
| Compliance/procurement owner | control mapping, attestations, vendor risk, contracts, exceptions |
| Release owner | gates, artifact signatures, immutable versions, rollback approval |

No control should depend on one developer remembering an undocumented manual
step.

## 11. What not to do next

1. Do not add a market, certification, customer, valuation, or production claim
   without an attributable source or retained evidence.
2. Do not call a synthetic bank estate a bank deployment or field validation.
3. Do not promote every console route to GA because the page renders.
4. Do not mark an unconfigured scanner, absent vendor evidence, unavailable
   integration, or incomplete dependency graph as healthy.
5. Do not put credentials, tokens, private keys, or raw secrets in vendor
   profiles, evidence fixtures, screenshots, reports, or support bundles.
6. Do not make automatic destructive changes part of the default workflow.
7. Do not promise HA, DR, load capacity, HSM support, compliance, or SaaS
   tenancy until the target topology has been executed and measured.
8. Do not build a second source of truth for each report or dashboard. Project
   views from normalized evidence and immutable snapshots.
9. Do not treat a passing unit test as proof of a customer's environment.
10. Do not merge or release while required gates are SKIP/BLOCKED and silently
    describe the system as enterprise-ready.

## 12. Final enterprise definition of done

CryptoScan can be described as enterprise-ready for a **specific deployment
model and customer scope** only when all of the following are true:

- the scope, tenant, data, and trust boundaries are documented and approved;
- identity, authorization, tenant isolation, secrets, and audit controls pass
  negative tests and external review where required;
- collection, evidence, normalization, policy, BOM, reporting, and export form
  one traceable chain;
- unknown, unavailable, stale, incomplete, and unverified states remain honest;
- the reference deployment can be installed, upgraded, monitored, backed up,
  restored, failed over where promised, and rolled back by the operations team;
- real customer integrations and at least one customer-reviewed pilot have
  produced retained evidence;
- capacity and recovery claims are measured in the promised topology;
- external security, compliance, provider, and procurement requirements are
  either satisfied or explicitly accepted as bounded exceptions;
- every release has a reproducible artifact, immutable identity, approval, and
  rollback path;
- support, incident response, vulnerability response, retention, deletion, and
  end-of-life procedures have named owners.

Until those conditions are met, the accurate position is:

> **CryptoScan is an extensive, security-tested cryptographic discovery and
> evidence platform progressing through supervised pilot and production
> qualification. Enterprise readiness is a scoped, evidenced deployment
> decision—not a feature-count claim.**
