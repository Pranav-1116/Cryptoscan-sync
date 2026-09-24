# ZELNX CryptoScan — the product, end to end

_This folder is the complete description of the product: what it is, what it
does, how it is built, how data moves through it, and how ready it is. Every
diagram is rendered from `scripts/gen_docs_diagrams.py` so it can be
regenerated when the code changes; every number is counted from the
repository, not from a plan. Version 1.0.0, 2026-09-23._

![What the product does](img/01-product-overview.png)

_Figure 1 — CryptoScan in one picture. Each block is explained in depth in the pages below and in the explanatory posters (images 10–31)._

## Read in this order

| # | Document | What it answers |
|---|---|---|
| 1 | [What it is](01-what-it-is.md) | The problem, who it is for, what it refuses to do, how to think about it in one page |
| 2 | [Features, end to end](02-features.md) | Every capability grouped by the loop stage it belongs to, with the page, endpoint and service that implements it |
| 3 | [Architecture](03-architecture.md) | The layers, the runtime processes, the stores, the security model — with diagrams |
| 4 | [Data flow](04-dataflow.md) | How a finding becomes evidence, inventory, BOM, export and a live event — with diagrams |
| 5 | [A scan, step by step](05-scan-walkthrough.md) | One job traced through all fourteen pipeline stages, with the rows it writes and how to verify it afterwards |
| 6 | [Scope, maturity and readiness](06-scope-and-readiness.md) | Which of the 71 surfaces are GA / beta / preview, how production-ready the whole thing is, and what is still open |
| 7 | [Glossary](07-glossary.md) | CBOM, HBOM, VBOM, evidence chain, drift, baseline, gate, PQC, HNDL … |
| 8 | [The engines behind the pages](08-platform-engines.md) | Scanner gate and orchestrator, privacy and data controls, normalisation/identity/dedup, PQC planning and agility, remediation/SLA/exceptions, KeyAssure, dependency graph and blast radius, tenancy/billing/marketplace/data lake/connectors/workload identity, sectors/anomaly/observability |
| 9 | [End to end — one finding, every subsystem](09-end-to-end.md) | A hard-coded 3DES key followed through all fifteen steps from push to regulator, with the artefact each step leaves |

## The product in five sentences

**CryptoScan** discovers every use of cryptography across an organisation's
estate — source code, dependencies, binaries and firmware, TLS endpoints,
certificates, cloud key services, containers, OT/ICS networks, telecom cores,
hardware security modules and payment systems — and turns it into one
inventory. Every finding is recorded in a **SHA-256 evidence chain** so it can
be re-verified later without trusting the server. The inventory is assessed
against **deterministic YAML policy packs** (PCI-DSS, NIST SP 800-131A, CNSA
2.0, FIPS, HIPAA, UAE, a baseline), watched for **drift** against approved
baselines, scored for **post-quantum readiness** and **crypto agility**, and
enforced in **CI as a gate**. What comes out is a versioned **Technology BOM**
(SBOM · CBOM · HBOM · VBOM), signed exports in six formats, and hash-manifested
**audit and evidence packs** a regulator can check. Policy is never decided by
AI, unknowns are reported as unknown with the reason, and nothing on any page
is fabricated: it is empty until a real scan produces evidence.

## Measured today

| | |
|---|---|
| Backend services | 51 packages under `services/` |
| REST surface | 642 paths / 86 tag groups, plus GraphQL and SSE/WebSocket ([reference](../api-reference/rest-api.md)) |
| Console | 71 pages, 6 sidebar sections, English + Arabic |
| Scanners | 6 first-class languages (Python, Java, C#, JS/TS, Go, Rust) + Kotlin, PHP, Ruby, config/IaC; 10 lockfile formats; ELF/PE/Mach-O/archive/firmware parsing; TLS; AWS/Azure/GCP; containers; OT; telecom; hardware; payment |
| Policy packs | baseline · PCI-DSS · NIST · CNSA 2.0 · FIPS · HIPAA · UAE (`services/policy/rule_definitions`) |
| Export formats | json · csv · cyclonedx · cyclonedx-xml · spdx · xml · pdf — each with content hash + HMAC + RFC 7515 JWS |
| Database | PostgreSQL 15/16 in production (SQLite for development), 60 Alembic migrations, 102 tables |
| Identity | local + TOTP MFA, OIDC (relay / auth-code / PKCE), SAML 2.0, LDAP/AD, SCIM 2.0, API keys; 9 RBAC roles |
| Tests | 4,808 backend test functions, hermetic and parallel (~8 min); frontend vitest suite; live PostgreSQL migration test |
| Readiness | ~80 % overall, core path ~92 % — [PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md) |

## Image index

Two sets of images. The first nine are structural diagrams; images 10–31 are
explanatory posters that carry the detailed explanation of each part of the
product on the image itself; 22–31 cover the engines behind the pages.

| # | Image | Explains | Used in |
|---|---|---|---|
| 01 | [product overview](img/01-product-overview.png) | what the product does, in one picture | this page |
| 02 | [layered architecture](img/02-layered-architecture.png) | frontend / API / services / stores | [03](03-architecture.md) |
| 03 | [runtime topology](img/03-runtime-topology.png) | the processes that run and how they connect | [03](03-architecture.md) |
| 04 | [scan pipeline](img/04-scan-pipeline.png) | the stages of one job | [05](05-scan-walkthrough.md) |
| 05 | [data flows](img/05-dataflows.png) | ingest, materialise, export, live delivery | [04](04-dataflow.md) |
| 06 | [evidence chain](img/06-evidence-chain.png) | how records chain and verify | [03](03-architecture.md) |
| 07 | [console map](img/07-console-map.png) | the pages and sections | [03](03-architecture.md) |
| 08 | [security model](img/08-security-model.png) | identity, RBAC, tenancy, guards | [03](03-architecture.md) |
| 09 | [scope and readiness](img/09-scope-readiness.png) | GA / beta / preview and readiness | [06](06-scope-and-readiness.md) |
| 10 | [collection in depth](img/10-collection-in-depth.png) | eleven collectors, what each finds, the "unknown is unknown" rule | [02](02-features.md) |
| 11 | [evidence explained](img/11-evidence-explained.png) | canonicalise → content hash → chain hash → manifest → verify; what tampering looks like | [02](02-features.md) |
| 12 | [Technology BOM explained](img/12-technology-bom-explained.png) | one inventory, four views, immutable versions, signed export | [02](02-features.md) |
| 13 | [assessment explained](img/13-assessment-explained.png) | a rule as YAML, 7 packs / 37 rules, per-finding evaluation, drift, PQC, agility, risk | [02](02-features.md) |
| 14 | [gate and automation](img/14-gate-and-automation-explained.png) | CI gate, SBOM gate, monitor, alerts, WHEN/IF/THEN with approval | [02](02-features.md) |
| 15 | [prove](img/15-prove-explained.png) | exports, reports, evidence pack, audit pack, how an auditor checks without trusting the server | [02](02-features.md) |
| 16 | [real-time and console](img/16-realtime-and-console-explained.png) | the delivery path, one API client, nothing fabricated, labelled maturity | [03](03-architecture.md) |
| 17 | [identity](img/17-identity-explained.png) | 9 roles, the middleware chain, how people and machines sign in | [03](03-architecture.md) |
| 18 | [operations](img/18-operations-explained.png) | dev / staging / production / air-gap / HA, health, backups, migrations, release, soak | [02](02-features.md) |
| 19 | [testing](img/19-testing-explained.png) | the test gate, frontend, live tests, soak; what the first real-database run found | [06](06-scope-and-readiness.md) |
| 20 | [user journeys](img/20-user-journeys.png) | analyst, developer, CISO, auditor, operator, machine | [01](01-what-it-is.md) |
| 21 | [data model](img/21-data-model.png) | the tables that matter and how they relate | [04](04-dataflow.md) |
| 22 | [scan gate and orchestrator](img/22-scan-gate-and-orchestrator.png) | the fail-closed chain a scan passes, four rate-limit layers, leases, scan modes | [08](08-platform-engines.md) |
| 23 | [privacy and data controls](img/23-privacy-and-data-controls.png) | data classes, redaction before hashing, verification states, triggers | [08](08-platform-engines.md) |
| 24 | [identity, dedup, confidence](img/24-identity-dedup-confidence.png) | normalisation, identity key, merge, merged confidence, correlation formulas | [08](08-platform-engines.md) |
| 25 | [PQC planning](img/25-pqc-planning-explained.png) | buckets, HNDL, Mosca's inequality, sector weight, roadmap waves, what-if | [08](08-platform-engines.md) |
| 26 | [remediation, SLA, exceptions](img/26-remediation-sla-exceptions.png) | templates, backlog, SLA clocks, exceptions, pentest findings, priority formula | [08](08-platform-engines.md) |
| 27 | [KeyAssure](img/27-keyassure-explained.png) | TLS audit, CT monitoring, expiry rules, HSM residence, trust stores, PQC downgrade | [08](08-platform-engines.md) |
| 28 | [graph and blast radius](img/28-graph-blast-radius-business.png) | dependency graph, reachability API, business context, impact | [08](08-platform-engines.md) |
| 29 | [platform services](img/29-platform-services-explained.png) | tenancy and plans, billing, marketplace, data lake, connector SDK, workload identity, notifications, onboarding | [08](08-platform-engines.md) |
| 30 | [sectors, anomaly, observability](img/30-sectors-anomaly-observability.png) | 11 sector profiles, statistical anomaly detection, SLOs and self-alerts, accuracy benchmark | [08](08-platform-engines.md) |
| 31 | [end-to-end trace](img/31-end-to-end-trace.png) | one 3DES key through all fifteen steps and eleven tables | [09](09-end-to-end.md) |

## Where the rest of the documentation lives

This folder is the narrative. The detailed references it points to are the
existing ones: [user guide](../user-guide/), [admin guide](../admin-guide/),
[architecture decisions](../decisions/), [API reference](../api-reference/rest-api.md),
[runbooks](../runbooks/), [security](../security/), and the
[soak evidence](../soak-evidence/README.md). The index is [docs/README.md](../README.md).

Regenerate the images: `python scripts/gen_docs_diagrams.py` (01–09) and `python scripts/gen_docs_posters.py` (10–21), `python scripts/gen_docs_posters2.py` (22–31) — matplotlib only, no browser or Graphviz.
