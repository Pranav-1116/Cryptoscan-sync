# CryptoScan end-to-end technical stack and data flow

**Status:** implementation-aware technical description for pilot discussions
**Audience:** CISO, security architect, platform owner, procurement security reviewer

This document describes the repository as it exists today. It deliberately marks
capabilities as **implemented**, **proposed for a customer deployment**, or
**not yet validated**. A route, class, dependency, or test is evidence that code
exists; it is not evidence of enterprise-scale availability, accuracy across a
customer's estate, regulatory approval, or production SLA.

## 1. One-sentence architecture

CryptoScan is a React/TypeScript browser console backed by a FastAPI/Python API.
The API authenticates users or API keys, resolves a tenant boundary, validates
scope, persists scan/job/evidence records in SQLAlchemy-backed PostgreSQL, uses
Redis for queued work and live coordination, runs bounded scanners in a separate
worker process, writes signed/encrypted artifact manifests to a tenant-scoped
store, and optionally projects dependency relationships into Neo4j. A Docker
Compose deployment puts these services behind an Nginx edge.

## 2. Architecture at a glance

```text
Customer browser / API client
          |
          | HTTPS through customer edge / Nginx
          v
React + TypeScript + Vite frontend
          |
          | relative /api calls, session cookie or API key
          v
FastAPI API (uvicorn, Python 3.11 image)
  |       |              |                  |
  |       |              |                  +--> metrics, traces, structured logs
  |       |              +--------------------> Redis: queue, rate limits, live state
  |       +-----------------------------------> PostgreSQL: tenants, users, scans,
  |                                              findings, evidence, jobs, reports
  +-------------------------------------------> Neo4j: graph projections (optional)
  |
  +--> synchronous bounded scan for approved small paths, or enqueue job
                 |
                 v
        Redis list / job lease / dead-letter queue
                 |
                 v
        Worker pool (separate Python process)
          | clone/extract approved target into workspace
          | scanner pipeline: load -> scan -> normalize -> evidence -> BOM/report
          | persist DB/read model + tenant-scoped artifact
          v
        bounded API response + frontend evidence/history views
```

For a real customer pilot, the customer controls the network route, source
permissions, identity provider, data classification, backups, retention, and
whether any external connector is enabled.

## 3. Frontend

### Implemented

- React 18, TypeScript, React Router, and Vite in `frontend/`.
- API client modules in `frontend/src/lib/api.ts` and related client/auth modules.
- Session-aware login and user/tenant context in the frontend.
- Current navigation is the navigation in `frontend/src/components/Layout.tsx`,
  including Dashboard, Live Asset Intelligence, Activity, Scan, Assets, Network,
  Cloud, Applications, Hardware, Certificates, Vendors, CBOM, HBOM, NBOM,
  Dependency Graph, Crypto Inventory, PQC Readiness, Crypto Agility, Crypto Drift,
  Banking & SWIFT, Policies, Compliance, Evidence, Audit Log, Reports, What-If
  Analysis, System Health, Settings & Org, Security Center, Users & Teams, and
  Integrations & API.
- DevSecOps/application views include binary scan history and bounded evidence
  views for the recently expanded binary read model.
- English and Arabic locale files exist. Locale availability is not the same as a
  complete Arabic customer-support or legal-localization programme.

### Data shown in the browser

The browser should show API-provided state such as:

- scan/job status and timestamps;
- findings and evidence links;
- counts and bounded excerpts;
- inventory and dependency relationships;
- CBOM/HBOM/NBOM views;
- reports and audit/event views where the authenticated user can access them; and
- explicit unknown, unsupported, refused, or truncated states.

A count in the UI must not be presented as full-estate coverage unless the API
response contains the coverage and scope metadata that supports that statement.

### Not yet validated for a customer

- accessibility conformance, browser support, localization quality, and SSO UX in
  a particular customer's environment;
- frontend performance at a customer's largest inventory size;
- customer-specific branding, role taxonomy, and report language; and
- whether every UI page is appropriate for external customer use. The pilot should
  expose only the agreed routes and roles.

## 4. API and service layer

### Implemented

- FastAPI application in `services/api/api/main.py` with uvicorn deployment.
- Route modules cover authentication, tenant/onboarding, scans/jobs, inventory,
  certificates, cloud/container/network/live/OT flows, DevSecOps, crypto assets,
  BOMs, findings, reports, exports, compliance/audit, integrations, and health.
- Pydantic schemas provide request/response validation in `services/api/api/schemas`.
- API clients and REST documentation are maintained in
  `docs/api-reference/rest-api.md`.
- The API supports synchronous and queued paths where the particular route allows
  them. Heavy or customer-scale work should be queued rather than run in the HTTP
  request.

### Implemented security controls at the API boundary

- session cookie authentication with HMAC-signed, expiring session tokens;
- password authentication and an MFA challenge path;
- optional OIDC token verification against issuer/JWKS with local role assignment;
- API-key lookup with tenant association, route policy, revocation/usage handling,
  and audit events;
- role checks and attribute/tenant-aware authorization middleware;
- request ID and W3C trace context propagation;
- security headers, CORS configuration, request rate limiting, and target/path
  validation controls;
- signed webhook checks where configured; and
- explicit production settings that refuse demo secrets, SQLite, wildcard CORS,
  or missing required secrets in the production overlay.

### Tenant boundary

Tenant context is resolved from an authenticated membership or tenant-associated
API key. The tenant-scope middleware enters a database tenant scope for API
requests, and queued job payloads carry `tenant_id` so the worker can re-enter the
same scope before persisting results. The design must fail closed on a refused
tenant selection; an unscoped platform operator context is a distinct, privileged
case.

For a pilot, verify with a customer-provided test account that:

1. a user in tenant A cannot read tenant B's records;
2. API keys cannot be used outside their allowed tenant/route policy;
3. worker-created findings and artifacts have the expected tenant identifier; and
4. audit events record the correct actor, tenant, operation, and result.

Do not turn those code paths into a blanket claim of independently audited
multi-tenancy.

## 5. Authentication and identity deployment choices

### Available in the code

- local username/password session flow;
- MFA challenge flow;
- optional OIDC federation (issuer discovery/JWKS verification, PKCE callback
  flow, local account mapping); and
- API keys for selected programmatic routes.

### Proposed pilot default

Use the customer's existing IdP if it can provide a test group and the customer
approves the OIDC trust. Otherwise use a dedicated pilot account with MFA and a
short list of named users. Start with read-only roles; add scan-trigger or admin
rights only to the named operators who need them.

### Not yet a claim

The current OIDC module explicitly does not claim SAML, complete IdP-initiated
logout, or automatic role mapping. Do not promise SCIM, SAML, privileged-access
workflow, or just-in-time role mapping until tested for that customer and version.

## 6. Worker, queue, and job lifecycle

### Implemented

- Redis 7 is the normal queue backend in Compose.
- The API enqueues scan jobs with target, scan options, job ID, scan ID, and
  tenant context.
- `services/worker/worker/core/job_consumer.py` uses a leased processing list
  model: a job is moved to a worker processing list, acknowledged only after
  completion, and recovered if a worker lease expires.
- Failed/repeatedly orphaned jobs can be dead-lettered, and database reaper logic
  prevents jobs remaining forever in `QUEUED` or `RUNNING`.
- The worker uses a pool for bounded concurrency and drains in-flight work on
  graceful shutdown.
- Development can have an in-process fallback; production is configured not to
  silently rely on that fallback.

### Customer implications

The customer should know whether a pilot is using a single worker or multiple
workers, the maximum concurrent scans, the queue retention, and what happens to a
job after timeout. The pilot charter should include a rescan/retry policy and a
manual stop procedure.

### Not yet validated

Queue durability, throughput, back-pressure, and recovery times at a customer's
largest workload are deployment-specific. Measure them in a non-production
sandbox before offering a customer SLA.

## 7. Database and read models

### Implemented

- SQLAlchemy models and repositories in `services/database/db`.
- PostgreSQL 15 in the base Compose stack; SQLite is useful for some tests/local
  development but the production overlay disables it.
- Alembic migrations and schema/health helpers.
- Models cover tenants, users, memberships/keys, scans, scan jobs, assets,
  certificates, crypto assets and evidence, vulnerabilities, findings, network and
  container runs, cloud accounts, binary scans/observations, report snapshots,
  verification/audit records, migration projects, and related entities.
- Database read models bound large response payloads and expose truncation/coverage
  metadata rather than silently returning an incomplete list.
- Binary evidence persistence stores bounded observations, parser status, refusal/
  depth/truncation metadata, and references to the artifact/BOM representation.

### Data model principle

The database is the queryable operational read model, not necessarily the complete
raw evidence archive. A record should identify its source, scan/run, tenant,
provenance, parser/collector status, timestamps, and any limit or error that
changed the result.

## 8. Evidence and artifact storage

### Implemented

- Tenant-scoped binary manifests and BOM artifacts are assembled in the
  `services/devsecops/devsecops/artifact_store.py` module.
- Artifact IDs support idempotent rewrites for retrying the same job.
- Stored manifests include bounded findings excerpts, complete severity counts,
  scan metadata, payload digest, ruleset/fingerprint metadata where available,
  parser/depth/truncation information, and tenant bucket information.
- Artifact encryption/signing helpers record the at-rest protection metadata and
  tenant scope. Storage is mounted local/shared storage in the supplied Compose
  topology, including the telecom/event-stream volume.
- Raw key material is not emitted by binary evidence; embedded-key detection keeps
  bounded metadata and a digest/reference rather than republishing key bytes.
- Export/report routes can produce bounded customer-facing representations where
  the authenticated user is authorized.

### Proposed for a customer deployment

- customer-managed object storage or a customer-controlled mounted volume;
- separate encryption keys through the customer's KMS/HSM where required;
- backup/restore policy, retention lock, deletion evidence, and cross-region
  replication decisions documented in the pilot charter;
- a data-processing agreement, subprocessors list, and support-access procedure;
  and
- an immutable evidence export delivered to the customer at pilot exit.

The Python dependencies include cloud SDKs, but their presence is not proof that
an end-to-end S3, Azure Blob, GCS, or customer-KMS deployment has been validated.

### Not yet validated

Do not claim that a particular cloud storage provider, HSM, KMS, customer-region
residency requirement, backup RPO/RTO, legal hold, or deletion certificate has
been tested until the pilot tests it and records evidence.

## 9. Scanners and collection paths

The platform contains several distinct evidence paths. They must not be sold as
one universal scanner.

### Repository/application and DevSecOps path

A source or repository target can be cloned/extracted into an allow-listed
workspace and passed through stages such as load, language detection, scan,
normalization, evidence, multi-scanner aggregation, policy, dependency/BOM,
reporting, and graph synchronization. GitHub/registry webhook and connector
modules exist for event-driven paths.

### Binary and firmware path

The bounded binary engine supports identification and metadata extraction for
multiple executable, archive, package, bytecode, compression, filesystem, and
firmware-related formats. It can inspect strings, symbols/imports, constants,
embedded key/certificate indicators, package signatures/metadata, and parser
status within configured limits.

Important limits:

- it does not execute customer binaries;
- it does not prove runtime behavior, exploitability, signer validity, or complete
  filesystem contents when a filesystem parser is not implemented;
- it does not collect private-key bytes;
- a static binary-derived NBOM is a candidate/view of software-visible network
  indicators, not a live network observation; and
- refusal, unsupported format, depth cap, walk cap, file-size cap, and truncation
  are outcomes to report—not reasons to infer a clean result.

The current vendor layer is called **VBOM** in project terminology. Add/use an
explicit vulnerability-BOM view for vulnerability relationships; do not redefine
VBOM as vulnerability BOM.

### Certificate and crypto-inventory paths

Certificate, key-usage, algorithm, library, protocol, asset, and evidence records
can be created by the relevant scanners/importers. A customer's certificate
authority, PKI, secret store, HSM, or cloud account is not scanned by implication;
it must be specifically enabled and authorized.

### Cloud, container, network, live, and OT paths

Route and worker modules exist for cloud scans, container scans, network scans,
live scans, and OT/telecom-related workflows. Each requires separate target
authorization, credentials, network reachability, rate limits, and safety review.
A source-code or binary pilot should not silently expand into a network or OT
scan.

## 10. BOMs, correlation, and graph

### Implemented concepts

- CBOM: cryptographic bill of materials and related cryptographic asset/evidence
  views.
- HBOM: hardware-related inventory view.
- NBOM: network-oriented view, with the restriction that binary-derived evidence
  is not a live observation.
- VBOM: existing vendor layer terminology.
- explicit vulnerability-BOM view/relationships for vulnerability evidence;
- technology/application/dependency artifacts and report snapshots; and
- graph relationships, with Neo4j available for dependency/system/asset
  projections and relational records remaining the source for many operational
  queries.

### What correlation means

Correlation combines evidence from authorized sources into a read model; it does
not upgrade weak evidence into strong evidence. A string match, symbol import,
certificate record, live network observation, and customer-confirmed owner should
remain distinguishable. The UI/report should show confidence/provenance and
unknown or conflicting states.

### Not yet validated

Do not claim deduplication precision, graph completeness, vulnerability severity
accuracy, ownership mapping accuracy, or a full SBOM/VEX interoperability result
without a customer validation set and repeatable measurement.

## 11. Reporting and exports

### Implemented

- REST API response schemas and bounded list/read models;
- JSON/read-model evidence and artifact manifests;
- export/report routes and report snapshot models;
- PDF dependency (`fpdf2`) and reporting code paths;
- audit/compliance evidence routes with separate auditor-credential behaviour in
  production configuration; and
- frontend reports, evidence, findings, inventory, BOM, and audit views.

### Pilot report contents

Every pilot report should include:

1. scope and authorization;
2. sources and timestamps;
3. scan configuration and ruleset/fingerprint digest where available;
4. observed inventory/findings;
5. evidence link for each material finding;
6. unknown/unsupported/refused/truncated counts;
7. validation sample and customer disposition;
8. remediation/re-scan result;
9. limitations and out-of-scope systems; and
10. export, retention, and deletion status.

The report is a decision aid, not a certificate of compliance, penetration-test
report, or regulator submission unless a separately contracted and qualified
service explicitly creates that deliverable.

## 12. Deployment

### Implemented deployment shape

The Compose stack includes PostgreSQL, Redis, Neo4j plus an init job, API,
worker, monitor, frontend, and Nginx. Production overlay settings include:

- explicit secrets and CORS origins;
- PostgreSQL rather than SQLite;
- uvicorn on `0.0.0.0` behind the edge;
- non-root containers, `no-new-privileges`, dropped capabilities, resource limits;
- workspace tmpfs and allow-listed source roots;
- JSON log rotation; and
- production fail-closed checks for required credentials and signing secrets.

### Customer deployment choices

Discuss three patterns without assuming any one is available:

1. customer-controlled single-tenant Compose installation;
2. vendor-operated isolated tenant deployment with a documented data/support
   boundary; or
3. customer cloud account / private network deployment with customer-owned storage
   and identity.

The first pilot should use the least complex pattern that satisfies data
classification and network requirements. Do not describe the base Compose file
with development defaults as a hardened production service.

## 13. Security controls and operational hygiene

### Available code controls

- TLS termination can be performed at the customer edge/Nginx;
- secure/HttpOnly/SameSite cookie options are configured for production;
- CORS is explicit in the production overlay;
- rate limits use Redis in a multi-process deployment;
- path/target validation confines scan workspaces and blocks sensitive prefixes;
- containers drop Linux capabilities and block privilege escalation;
- webhook and CBOM/event streams support HMAC signing where configured;
- request logs omit sensitive fields via structured logging controls;
- trace IDs, request IDs, metrics, health checks, leases, dead letters, and job
  reaping support operations; and
- evidence/artifact manifests preserve digest/provenance and bounded content.

### Required customer review items

Before a real-system pilot, supply the evidence that actually exists:

- architecture and trust-boundary diagram;
- environment variables/secrets handling procedure;
- access-control and tenant test results;
- dependency/build provenance available from CI;
- vulnerability-management status available from the project;
- backup/restore and deletion approach for the pilot;
- incident/support contact and response expectations; and
- list of known limitations and unvalidated claims.

Do not label internal tests as an external penetration test, ISO/SOC evidence,
certification, or independent assurance.

## 14. Observability

### Implemented

- structured API/worker logs;
- request ID and trace context;
- Prometheus-style metrics endpoint and request counters/latency/errors;
- health/readiness probes for dependencies;
- Redis worker leases, orphan recovery, dead-letter handling, and database job
  reaper;
- event stream/trace storage paths in the deployment; and
- monitor process for scheduled/report/alert-related work.

### Proposed pilot dashboard

Track per pilot:

- queued, running, completed, failed, and dead-letter jobs;
- scan duration and worker resource use;
- source counts, bytes/files scanned, parser errors, refusals, and truncation;
- API 4xx/5xx and authentication failures;
- artifact write/read/signature failures;
- customer validation dispositions and rescan status; and
- deletion/retention completion.

Observability is not a promise that an operator watches the system 24/7. Define
support hours, alert ownership, and escalation before the pilot starts.

## 15. Testing and assurance status

### Evidence already present in the repository

The current development validation includes backend API/read-model tests, binary
parser/BOM/depth tests, database read-model and migration/schema tests, frontend
unit/component tests, frontend typecheck/build, Python compilation, and diff
hygiene checks. These tests support development confidence for the paths covered.

### What a customer pilot must add

- customer-like fixture and validation sample;
- tenant isolation tests with two test tenants;
- OIDC/API-key/role tests using the customer's chosen identity pattern;
- queue interruption and rescan/retry test;
- rate/size/depth limit test on approved benign samples;
- artifact export, backup, restore, and deletion test;
- report review by the named security owner; and
- a written coverage/accuracy review that records false positives, false negatives
  found by the sample, unknowns, and untested areas.

### Explicitly not validated by the repository alone

- complete enterprise coverage or accuracy;
- safe operation against an arbitrary production system;
- regulated production readiness, certification, or approval;
- penetration-test independence;
- customer-specific data residency or DPA compliance; and
- effectiveness of every scanner against every version of every format.

## 16. End-to-end example: bounded binary pilot

1. The customer names a sponsor, source owner, and authorized sample directory.
2. The vendor records the charter, data classification, max file size, file count,
   recursion/depth, rate limits, and stop condition.
3. A user logs into the frontend using the approved local/IdP flow.
4. The frontend sends a relative API request. The API authenticates, resolves the
   tenant, validates the target/workspace, and creates a scan/job record.
5. Small permitted work may run in the API; otherwise the API enqueues a Redis job
   carrying the tenant and scan options.
6. The worker claims the job with a lease, reads the approved workspace, and runs
   the bounded binary parser. It does not execute the binary.
7. The parser emits format, metadata, evidence, parser status, depth, refusal,
   error, and truncation information. Embedded key bytes remain out of the
   report.
8. Normalization creates read-model observations and BOM projections. Binary
   NBOM-like evidence is labelled static; it is not a live network observation.
9. The artifact store creates an idempotent tenant-scoped manifest with digests,
   bounded excerpts, counts, provenance, and at-rest metadata.
10. The worker persists status, evidence links, and artifact ID; the API returns a
    bounded response.
11. The frontend displays the scan under the current Applications/DevSecOps path
    and exposes evidence, status, limits, and history rather than a bare score.
12. The customer validates a sample, performs one safe remediation or annotation,
    reruns the approved scope, reviews the report, and receives an export.
13. At exit, access is revoked, data is deleted or retained according to the
    charter, and the deletion/retention result is recorded.
