# Vendor due diligence and structured network inventory

**Status:** current implementation guide
**Date:** 2026-10-03
**Scope:** tenant-scoped, versioned vendor profiles and network-inventory evidence

This guide covers two related but distinct evidence surfaces:

- **Vendor due diligence** records what is known about a supplier's identity,
  services, contracts, security, privacy, finances, incidents, dependencies,
  access, exit plan, and supporting evidence.
- **Structured network inventory** records network devices, topology,
  configuration references, services, controls, WAN, monitoring, wireless,
  firmware/software, documentation, and evidence.

Neither surface proves that a vendor is safe, that a network is complete, or that
an organization is compliant. Missing, stale, unavailable, unverified, and
incomplete values remain visible and are not converted to a green result.

## 1. Vendor due diligence

### 1.1 Profile sections

The profile schema is `cryptoscan.vendor-profile/1`. It is strict: unknown fields
are rejected, so a caller cannot silently add an unreviewed assertion. The
profile contains these top-level sections:

| Section | Examples of captured fields |
|---|---|
| `identity` | legal name, vendor ID, D-U-N-S number, type, criticality, tier, ownership, jurisdictions, operating locations |
| `contacts` | business, technical support, security incident response, account manager, escalation and emergency contacts |
| `components` | products/services, versions, type, license/support, end of life, replacements, consumers, alternatives, lock-in risk |
| `contracts` | contract type, dates, renewal, termination, assistance, value/currency, payment terms |
| `service_level_agreements` | uptime, response/resolution times, maintenance windows, measurement, penalties, remedies, service credits |
| `legal_liability` | liability, indemnification, insurance, intellectual property, confidentiality, governing law, dispute resolution |
| `security_compliance` | assessments, findings, certifications, regulatory attestations, DPA, framework alignment, subprocessors |
| `data_privacy` | data types/classification, owner, flows, locations, residency/sovereignty, retention/deletion, DPO and privacy mechanisms |
| `financial_stability` | public/private status, statement reference, revenue range, profitability, credit/funding, continuity, succession and financial risk |
| `incident_history` | incident type, dates, scope, impact, root cause, remediation, notification and response plan |
| `dependencies` | single-point and concentration risk, sub-vendors, fourth-party visibility, ecosystem, integrations and cascading failure |
| `access_permissions` | remote/API/VPN/physical/admin access, scope, MFA, restrictions, privilege, reviews, personnel controls |
| `exit_strategy` | transition, retrieval/deletion confirmation, export, knowledge transfer, portability, escrow, replacement, migration and rollback |
| `evidence` | evidence ID/type/reference, status, capture/expiry, issuer, source, collection method, reviewer, hash and limitations |

An empty or partially populated profile is a **DRAFT**. It is not a risk
acceptance and does not claim that unspecified controls exist.

### 1.2 Lifecycle and approval

Profile revisions are append-only:

```text
DRAFT → IN_REVIEW → APPROVED
   │         │          │
   └─────────┴──── EXPIRED (historical revision retained)
```

`APPROVED` is allowed only when completeness is complete, required evidence is
present and `PASS`, assessments/certifications are current and rated, unresolved
unknowns required by the approval rules are closed, and `reviewed_by` matches
the authenticated reviewer. Appending evidence to an approved or expired
profile creates a new revision and returns it to review.

A content SHA-256, source, capture time, creator, reviewer, notes, and revision
number are retained with each revision. Expiring a profile does not delete its
history.

### 1.3 Vendor endpoints

All routes require application authentication and resolve the vendor inside the
requester's tenant. A missing vendor is returned as not found rather than
revealing another tenant's object.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/vendors/{vendor_id}/profile` | Current profile or explicit empty draft, completeness, and audit metadata |
| `PUT` | `/api/v1/vendors/{vendor_id}/profile` | Validate and append a profile revision |
| `POST` | `/api/v1/vendors/{vendor_id}/profile/validate` | Validate and hash without persistence |
| `GET` | `/api/v1/vendors/{vendor_id}/profile/schema` | Return the strict JSON Schema |
| `POST` | `/api/v1/vendors/{vendor_id}/profile/evidence` | Append provenance-only evidence metadata |
| `GET` | `/api/v1/vendors/{vendor_id}/profile/history` | Return immutable revision history |
| `DELETE` | `/api/v1/vendors/{vendor_id}/profile` | Append an `EXPIRED` revision; does not delete history |
| `GET` / `POST` | `/api/v1/vendors/{vendor_id}/questionnaire` | Generate or ingest questionnaire data into the legacy crypto-inventory path |
| `POST` | `/api/v1/vendors/{vendor_id}/cbom` | Import a supplier CBOM into the vendor crypto inventory |
| `POST` | `/api/v1/vendors/{vendor_id}/docs` | Extract crypto mentions from supplied documentation |
| `GET` | `/api/v1/vendors/{vendor_id}/risk` | Explainable crypto and due-diligence screening output |
| `GET` | `/api/v1/vendor-risks` | List vendor screening results |

The questionnaire, CBOM, documentation, and live API-scan surfaces are related
inputs; they are not substitutes for the complete operational profile.

### 1.4 Evidence and secret boundary

Evidence entries are metadata and references. They may contain a hash and a
reference to a controlled evidence system, but not the artifact's secret
contents. Profile and evidence writes reject credential-like fields and values,
including passwords, bearer tokens, API keys, connection strings, private keys,
and raw authentication material.

Do not put a private key, password, token, community string, or production
credential into a JSON profile, CBOM, log, or evidence export. Use a reference to
the customer's approved vault or evidence store and record the limitation.

## 2. Structured network inventory

### 2.1 Schema and sections

The schema is `cryptoscan.network-inventory/1`. It is a versioned document with
explicit observation metadata (`status`, evidence IDs, source, timestamp and
limitation) on sections and observations. The top-level sections are:

| Section | What it records |
|---|---|
| `devices` | device identity/type, manufacturer/model, location, interfaces, management identity, criticality, redundancy, firmware, discovery source and observation |
| `topology` | physical/logical connections, graph edges, segments, VLANs, routing, trust zones, data flows, critical paths and topology references |
| `configuration` | running/startup/baseline/template references, content hashes, change records, routing, switching, ACL/security and drift state; raw configurations are not accepted |
| `network_services` | DNS, DHCP, NTP, IPAM and network authentication references |
| `security_controls` | ACLs, firewall/NAT/application rules, zones, segmentation, VPN and perimeter controls |
| `wan_connectivity` | ISP circuits, MPLS, SD-WAN, cloud connectivity and data-center interconnects |
| `monitoring` | NMS, SNMP posture, flow collectors, taps, telemetry, syslog, SIEM, configuration management and automation references |
| `wireless_networks` | controllers, access points, coverage, standards, SSIDs, encryption, isolation and rogue-AP detection |
| `firmware_software` | operating systems, versions, patches, vulnerabilities, upgrade paths, management/orchestration and analytics |
| `documentation` | topology, zones, WAN/IP plans, standards, change, incident, disaster recovery, support and vendor references |
| `evidence` | discovery/configuration/topology/monitoring/documentation evidence, source, collector, status, timestamp, hash and limitations |

A network inventory can be complete as a document while still being incomplete
as a view of the real network. Completeness is section-level and evidence-backed;
it is not a claim of universal network visibility.

### 2.2 Network inventory endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/network/inventory/schema` | Return the strict JSON Schema |
| `POST` | `/api/v1/network/inventory/validate` | Validate, calculate completeness/approval issues, and hash without persistence |
| `GET` | `/api/v1/network/inventory` | Current revision or explicit empty draft (`inventory_id` defaults to `default`) |
| `PUT` | `/api/v1/network/inventory` | Validate and append a revision |
| `GET` | `/api/v1/network/inventory/history` | Return newest-first immutable revisions |
| `GET` | `/api/v1/network/inventory/risk` | Calculate explainable risk factors, unknowns, and next actions |
| `POST` | `/api/v1/network/inventory/discover` | Run authorized safe discovery and persist a `DRAFT` revision |
| `GET` | `/api/v1/network/inventory/topology` | Build a typed topology graph and report integrity gaps |
| `POST` | `/api/v1/network/inventory/topology/validate` | Analyze a supplied topology without persistence |
| `GET` | `/api/v1/network/inventory/configuration/drift` | Compare recorded configuration hashes |
| `POST` | `/api/v1/network/inventory/configuration/drift` | Analyze a supplied inventory without persistence |
| `GET` | `/api/v1/network/inventory/coverage` | Return completeness, risk, topology, drift, and section states |

`POST /network/inventory/discover` validates target scope through the same
network safety controls as other network probes. Discovery creates a `DRAFT`
only: it does not prove ownership, configuration correctness, topology
completeness, firmware currency, or control effectiveness.

### 2.3 Configuration and topology semantics

- Configuration drift compares recorded content hashes only. Missing hashes are
  `UNKNOWN` or `NOT_ASSESSED`, never `IN_SYNC`.
- A topology edge whose endpoints are not in the device inventory is reported as
  an unknown endpoint.
- Unlinked devices and unverified edges remain visible in topology results.
- A network `GREEN` posture cannot be inferred from an empty inventory. Missing
  sections contribute to incomplete status and risk factors.
- Raw device configurations and authentication material are not accepted; use
  secret-free artifact references and SHA-256 hashes.

## 3. Tenancy, auditability, and operating boundaries

- Vendor profile and network inventory revisions are tenant-scoped.
- Reads, writes, history, risk, coverage, topology, drift, and schema access
  must resolve the object in the authenticated tenant context.
- Revisions are append-only and retain creator/reviewer/source/hash metadata.
- Unknown, stale, incomplete, unverified, and unavailable are first-class states.
- The system does not certify a vendor, approve a network, or replace a qualified
  risk, architecture, compliance, or operational review.
- Live network scanning remains authorized and safety-gated. Do not run active
  probes, configuration changes, certificate replacement, revocation, key
  rotation, or production control-plane actions without customer authorization,
  change control, and rollback evidence.

## Related documentation

- [Vendor due-diligence operations](../operations/vendor-due-diligence.md)
- [Vendor crypto discovery](vendor-risk.md)
- [Network TLS scanning](network-scanning.md)
- [Navigation and feature reference](../NAVIGATION-FEATURE-REFERENCE.md)
- [REST API reference](../api-reference/rest-api.md)
- [Capability maturity](../CAPABILITY-MATURITY.md)
