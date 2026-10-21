# CryptoScan enterprise system blueprint

**Later implemented slice (2026-10-21):** persisted/current queue authority,
durable SSH receipts and verified realtime/current-run Redis TLS/Sentinel are
now documented in [Guides 44–45](bank-environment/44-queued-authority-and-durable-ssh.md).
They are bounded local controls, not the full positive/regional grant,
distributed-budget or production qualification architecture proposed below.
Use the [upgrade runbook](runbooks/execution-and-replay-upgrade.md) for rollout.

**Decision document · 2026-10-04 · status: implementation guide, not a production attestation**

This document explains the next stage for CryptoScan: turning the existing crypto-discovery and evidence platform into an enterprise operating system for cryptographic risk. It is deliberately split between **what the repository already demonstrates** and **what must still be qualified**. A route, scanner, connector, policy pack or UI badge is not evidence of production readiness by itself.

## 1. Enterprise outcome

CryptoScan should become the system of record for an organisation's cryptographic estate:

1. **Discover** applications, infrastructure, networks, clouds, hardware, vendors, certificates and crypto services through authorised, tenant-scoped collection.
2. **Normalize** observations into stable assets, algorithms, protocols, keys, certificates, libraries, providers and dependencies without inventing facts when evidence is absent.
3. **Materialize** SBOM, NBOM, CBOM, TechBOM, HBOM and VBOM views from the same evidence-backed model.
4. **Evaluate** policy, vulnerability, compliance, PQC exposure, crypto agility, drift and business impact using deterministic rules.
5. **Prove** every important answer with immutable evidence references, provenance, timestamps, hashes, actor identity and policy version.
6. **Operate** the estate continuously: queue scans, watch live sources, detect change, route findings, approve exceptions and verify remediation.
7. **Report** bounded, audience-specific views to security operations, application owners, executives, auditors, regulators and vendors.

The enterprise promise is therefore not “we scanned everything.” It is: **we can show what was observed, what was not observable, how fresh it is, which controls evaluated it, and who approved the next action.**

## 2. Current repository baseline

The repository already contains substantial building blocks for this target:

- FastAPI control-plane routes, worker pipelines and shared models.
- Server-verified authentication, RBAC, tenant resolution and fail-closed tenant middleware.
- Tenant-scoped vendor profiles, network inventory and evidence sanitization tests.
- Event bus/SSE/Redis federation with `Last-Event-ID` replay and tenant filtering.
- Scanner families for source, network, cloud, containers, OT, telecom, hardware and binary/firmware surfaces.
- SBOM/CBOM/HBOM/NBOM/VBOM-related models and export paths.
- Policy, compliance, evidence, drift, PQC and crypto-agility services.
- A React console with lazy routes, maturity labels, live status, organization/environment context and server-verified role affordances.
- A continuously tested repository: the last full regression completed with 6,330 passed, 15 skipped and 38 warnings.

These are engineering facts, not customer or production attestations. Deployment evidence, connector qualification, external review, customer acceptance, recovery drills and operational ownership must still be established per environment.

## 3. Target architecture, end to end

```text
User / API client
      │ HTTPS, OIDC/SAML/LDAP, session or scoped API key
      ▼
Edge / ingress / rate limits / security headers
      │
      ▼
FastAPI control plane ─────── audit events ───────► event bus / Redis stream
      │                                  │                         │
      │                                  └──────────────► SSE / WebSocket console
      │
      ├── authentication, RBAC, ABAC, tenant resolution
      ├── scan orchestration and approval gates
      ├── vendor/network/application inventory APIs
      ├── evidence, policy, report and export APIs
      └── read models for the console
      │
      ▼
Durable database + evidence store + key/secret references
      │
      ▼
Workers and authorised connectors
      │
      ├── source / binary / firmware / container / cloud scanners
      ├── network, telecom, OT and hardware probes
      ├── vendor APIs, telemetry, syslog and event streams
      └── policy, normalization, correlation and risk stages
      │
      ▼
Evidence-backed canonical observations
      │
      ├── asset and dependency graph
      ├── SBOM / CBOM / HBOM / NBOM / VBOM projections
      ├── findings, controls, drift, PQC and remediation tasks
      └── signed, redacted reports and audit exports
```

### 3.1 Request path

1. The browser uses relative API URLs. The edge or Vite proxy owns the backend hop; browser code never calls `localhost` or `127.0.0.1`.
2. The edge applies TLS, origin policy, request-size limits, security headers and rate limits.
3. The API authenticates the principal using the server-side session, OIDC/SAML/LDAP result or a scoped API key. A browser-local role value is never authoritative.
4. Tenant resolution validates membership and an optional `X-Tenant-ID`. Unknown, ambiguous, unavailable or cross-tenant selections fail closed; the request is not allowed to continue unscoped.
5. RBAC/ABAC evaluates the action, resource, method, tenant, environment and any approval requirement.
6. The API validates targets before a scan or connector can read them. Local filesystem targets stay inside configured source roots; remote/cloud targets use explicit connector policies.
7. The API writes an auditable command or queues a worker job only after persistence succeeds. A job is never reported as accepted when its durable row did not commit.
8. The response contains a status, identifier and provenance boundary. It does not claim a clean estate when the backend is offline or evidence is incomplete.

### 3.2 Scan and observation path

1. A user or schedule submits a scan request with tenant, environment, target, scope, requested mode, actor and policy context.
2. The orchestrator creates a durable job and idempotency key, then publishes a tenant-stamped queue message.
3. The worker reacquires the tenant scope before reading or writing data. Background work cannot inherit a stale request context.
4. The connector or scanner reports availability separately from observations: configured, reachable, authenticated, authorized, unsupported, partial, stale or unavailable.
5. Raw material is validated and sanitized at ingestion. Credentials, tokens, passwords, private keys and secret material are rejected or redacted; only safe metadata and evidence references survive.
6. Parsers emit normalized observations with source, timestamp, confidence, evidence hash and explicit unknown fields.
7. Normalization resolves identities without collapsing two assets merely because their display labels look alike.
8. The evidence writer stores content hashes, chain/manifest hashes, source provenance and verification status. Evidence is immutable from the consumer's perspective.
9. Policy stages evaluate the observation set. `UNKNOWN`, `UNAVAILABLE`, `STALE`, `PARTIAL` and `UNVERIFIED` do not become `PASS`.
10. Read models update inventories, graphs, findings, compliance controls and maturity/status surfaces.
11. An event is published only after the durable state is safe to advertise. Subscribers receive the tenant-filtered event and can resume from `Last-Event-ID`.
12. The console shows the result with freshness, coverage, evidence links, policy version and remediation ownership.

## 4. Enterprise control planes

### 4.1 Identity, access and tenancy

- Use server-verified `GET /api/v1/auth/me` as the only UI source for current user and roles.
- Keep `/login`, `/register`, `/reset-password` and `/invite-accept` outside the authenticated console shell.
- Make tenant membership, selected tenant, organization and environment explicit on every sensitive screen.
- Apply least privilege to read, scan, export, approve, manage connectors, manage identity and execute production-impacting actions.
- Keep UI hiding as a usability feature only; the backend must authorize every request.
- Require re-authentication or step-up approval for exports, destructive actions, key/certificate changes, exception approvals and production connector changes.
- Record actor, tenant, target, decision, reason, policy version, old/new safe metadata and evidence references in the audit trail.

### 4.2 Evidence and data governance

Every material answer should carry:

| Field | Purpose |
|---|---|
| `tenant_id` | Prevent cross-tenant reads and identify ownership at rest and in transit |
| `source` / connector | Explain where an observation came from |
| `observed_at` / freshness | Prevent stale evidence from appearing current |
| `evidence_reference` | Link to a hash-addressed, sanitized record |
| `provenance` | Preserve parser, API, artifact, file, row or event origin |
| `confidence` | Distinguish direct observation from a derived relationship |
| `coverage` | Explain scope, exclusions, depth and collection limits |
| `verification_status` | Show verified, unverified, unavailable, partial or failed |
| `policy_version` | Make a decision reproducible after rules change |
| `actor` / approval | Establish accountability for human decisions |

No secret belongs in a vendor profile, CBOM component, report, log, event payload, export, test fixture or UI state. Secret references may identify an external vault location, but the secret value is never copied into CryptoScan data.

### 4.3 Availability and resilience

- API, worker, database, Redis/event federation and evidence storage each need independent health and readiness signals.
- Queue acceptance, worker lease, retry, dead-letter and replay states must be observable.
- Backups require encryption, retention, restore verification and tenant-aware access controls.
- Disaster-recovery exercises must be acknowledged and run with explicit safety flags; no destructive restore, revocation, rotation or production outage command is implied by this document.
- Recovery objectives must be agreed per deployment rather than presented as a universal CryptoScan guarantee.
- An offline console must show unavailable state, not cached green posture.

### 4.4 Change and release governance

Before a release is promoted:

1. Unit, integration, tenant-isolation, security, frontend typecheck/build and end-to-end tests pass.
2. Database migrations are reviewed forward and backward where supported.
3. Images and dependencies are pinned and scanned.
4. Evidence export, signature verification, redaction and tenant isolation are rechecked.
5. Operational runbooks, rollback notes, ownership and support contacts are current.
6. Production qualification evidence is attached to the release record.
7. An explicit approver accepts remaining unknowns; unknowns are never silently downgraded.

## 5. Console information architecture

The console has six primary sections and follows a command-to-proof workflow:

1. **Overview** — Command Center, Live Asset Intelligence, Activity.
2. **Discovery** — Scan, Assets, Network, Cloud, Applications, Hardware, Certificates, Vendors.
3. **Intelligence** — CBOM, HBOM, NBOM, Dependency Graph, Crypto Inventory, PQC Readiness, Crypto Agility, Crypto Drift.
4. **Governance** — Banking & SWIFT, Policies, Compliance, Evidence, Audit Log.
5. **Output** — Reports, What-If Analysis.
6. **Administration** — System Health, Settings & Org, Security Center, Users & Teams, Integrations & API.

The six sections contain 31 sidebar slots (3 + 8 + 8 + 5 + 2 + 5) and 30 unique primary paths. The duplicate Security Center placement is intentional: the governance placement is an audit workflow; the administration placement is a platform-control entry point. It remains one route and one permission model. Other authenticated pages may remain deep-link routes reached from cards, search and reports; a deep link is not implied to be a primary navigation slot.

### 5.1 Navigation behavior

- `/` redirects to `/command-center`.
- Unknown authenticated routes redirect to `/command-center`.
- Authentication entry routes never render the main sidebar or realtime stream.
- Collapsed navigation keeps icons, keyboard focus and accessible labels; tooltips expose the label when text is hidden.
- English and Arabic use the same route model and switch document direction between LTR and RTL.
- Every route reads GA/Beta/Preview from the generated maturity table. Omission defaults down to Preview; it never promotes a route.
- “Start Scan” is rendered only when the server-verified role set includes `superadmin`, `ciso`, `security_analyst`, `developer` or `scanner`. The backend remains authoritative.
- Motion uses spring physics for spatial changes and respects `prefers-reduced-motion`. Dynamic navigation uses auto-animate for bounded layout shifts.

## 6. Applications pipeline UX

`/dev-sec-ops` should read as a provenance pipeline, not as a collection of unrelated scanners:

```text
source / binary / image
        │
        ▼
SBOM ──► CBOM ──► HBOM / NBOM context ──► VBOM + advisories
        │             │                    │
        └─────────────┴──────────────► policy gates / evidence / tasks
```

The page must show a stage as **observed**, **derived**, **unavailable**, **partial** or **not configured**. It should never use a green “clean” state to mean that a source was not scanned.

### Required metadata markers

- **Observation boundary:** signatures and imported manifests are evidence inputs; a signature is not automatically a trust decision.
- **Coverage boundary:** a clean result means “no matching finding in this observed scope,” not “the unobserved estate is clean.”
- **Static/live boundary:** binary-derived network capabilities are candidates with `observed: false`; live network probes are separate observations.
- **Unknown boundary:** architecture, provider, version, key usage and PQC migration fields remain explicit `UNKNOWN`/`UNAVAILABLE` values until evidence fills them.
- **Provenance boundary:** advisories show feed source, feed timestamp and matching rule; vendor claims remain vendor-declared unless independently verified.
- **Action boundary:** a gate can block or request review; it does not rotate keys, revoke certificates or change production without an explicit approved operation.

The first release of this UX should expose the pipeline and evidence boundaries even when a stage is unavailable. It should not manufacture sample counts, CVEs, certificates, PQC readiness or provider confidence.

## 7. Enterprise operating lifecycle

### Phase 0 — control baseline

- Define tenant, organization, environment and data-retention boundaries.
- Configure identity providers, role mappings, session lifetime, API-key scopes and approval roles.
- Configure source roots, egress policy, connector allowlists, evidence storage and secret-reference policy.
- Run the security, tenancy, sanitization and production-hardening test suites.

### Phase 1 — controlled discovery

- Onboard one non-production estate with an approved collection scope.
- Run source, binary, network, cloud, container and vendor discovery separately.
- Review partial/unavailable outcomes and evidence freshness before enabling executive dashboards.
- Establish asset identity and ownership mappings; resolve collisions before bulk scanning.

### Phase 2 — intelligence and governance

- Enable CBOM/HBOM/NBOM/VBOM projections backed by evidence.
- Define cryptographic policy packs and exception workflows.
- Establish PQC migration inventory without presenting a roadmap as deployed capability.
- Connect findings to owners, tickets and change windows using dry-run/preview modes first.

### Phase 3 — continuous operations

- Enable scheduled scans and authorized live connectors.
- Monitor event lag, replay gaps, queue saturation, evidence failures, stale sources and tenant-isolation counters.
- Review drift, certificate expiry, algorithm changes, new dependencies and vendor posture.
- Run periodic export verification and restore drills.

### Phase 4 — regulated qualification

- Attach deployment-specific performance, recovery, access-review, vulnerability-management and external-assurance evidence.
- Obtain customer/regulator-specific acceptance for policy mappings.
- Promote only the surfaces and connectors whose evidence supports production status.
- Keep beta/preview labels where qualification is incomplete.

## 8. Acceptance criteria for enterprise promotion

A CryptoScan deployment is ready to call enterprise-qualified only when all applicable criteria have evidence:

- **Security:** authentication, RBAC/ABAC, tenant isolation, headers, rate limits, target validation, secret handling and audit verification.
- **Correctness:** no cross-tenant result, no unknown-to-pass conversion, no stale evidence presented as current, and no fabricated inventory.
- **Coverage:** each enabled scanner and connector has a documented scope, freshness SLA, failure state and owner.
- **Evidence:** immutable hashes, redaction tests, provenance, export verification and policy-version traceability.
- **Operations:** health/readiness, queue metrics, alert routes, on-call ownership, replay/retry procedures and capacity evidence.
- **Resilience:** backup encryption, restore verification, recovery objectives and a completed non-destructive drill.
- **Governance:** access reviews, exception approvals, change management, data retention, privacy and vendor responsibility boundaries.
- **User experience:** role-safe navigation, RTL support, keyboard access, reduced-motion behavior, route fallback, server-verified action visibility and bounded-state messaging.
- **Qualification:** deployment-specific sign-off. Repository tests are necessary engineering evidence, not a customer attestation or certification.

## 9. Next implementation sequence

1. **Ship the console foundation:** the route table, isolated auth entries, collapsible six-section navigation, server-verified Start Scan control, generated maturity pills and RTL-aware shell.
2. **Ship the visual system:** graphite surfaces, chartreuse/terracotta/emerald semantic signals, display/body typography, asymmetrical workspace grids, spring transitions and auto-animated lists.
3. **Ship the Applications pipeline view:** explicit SBOM/CBOM/HBOM/NBOM/VBOM stages, provenance badges and unknown/coverage boundary markers.
4. **Harden operational workflows:** connector configuration lifecycle, queue/retry/dead-letter visibility, approval gates, evidence verification and export review.
5. **Qualify deployment:** run tenant/security suites, frontend build/typecheck, performance and recovery drills, connector tests and customer-specific acceptance.
6. **Promote maturity labels conservatively:** update the source-of-truth table only when repository and deployment evidence supports the tier.

## 10. Decisions still required from the product owner

- Which identity providers and regional data-residency rules are required for the first enterprise deployment?
- Which source classes are in the initial contract, and what freshness/coverage target applies to each?
- Which actions require dual approval, change windows or step-up authentication?
- Which evidence retention and deletion schedule applies to each tenant and artifact class?
- What deployment-specific RTO/RPO, scale, support hours and escalation path are committed?
- Which compliance mappings are customer-requested versus merely available as deterministic templates?

Until these decisions have owners and evidence, CryptoScan should present them as **open qualification work**, not as completed enterprise capabilities.
