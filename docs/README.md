# CryptoScan documentation

Production cryptographic inventory and compliance platform: deterministic
scanners, hashed evidence, YAML policy, drift, and a dashboard. Policy is
never decided by AI; unknowns are skipped with reasons, never faked.

**New here?** Boot the stack with `bash scripts/run_stack.sh`, log in with
`admin` / `cryptoscan` (development only), then read
[Dashboard overview](user-guide/dashboard-overview.md).

## Start here

| Doc | What it covers |
|---|---|
| [Platform status](PLATFORM-STATUS.md) | every planned capability vs. what ships — honest accounting |
| [Enterprise readiness](enterprise-readiness.md) | feature matrix with honest gaps; what blocks production |
| [Platform boundaries](architecture/platform-boundaries.md) | what CryptoScan is and is not (single source of truth: `shared_models/platform_scope.py`) |
| [Real-world comparison](architecture/real-world-comparison.md) | honest benchmark vs. Venafi, SandboxAQ, Prowler, Trivy, testssl.sh, Nozomi, SAST |

## User guide

| Doc | What it covers |
|---|---|
| [Dashboard overview](user-guide/dashboard-overview.md) | the working loop: scan → evidence → inventory → policy → drift → dashboard |
| [Crypto asset inventory](user-guide/crypto-asset-inventory.md) | deduplicated crypto-asset store |
| [Certificate inventory](user-guide/certificate-inventory.md) | TLS/certificate estate, expiry, chains |
| [Multi-language scanning](user-guide/multi-language-scanning.md) | six first-class languages (Python/Java/C#/JS/Go/Rust) + Kotlin/PHP/Ruby/config |
| [Network scanning](user-guide/network-scanning.md) | TLS endpoints, active/passive |
| [Cloud scanning](user-guide/cloud-scanning.md) | AWS/Azure/GCP, read-only roles |
| [Container scanning](user-guide/container-scanning.md) | images, registries, IaC |
| [OT/ICS scanning](user-guide/ot-ics-scanning.md) | passive, zero packets |
| **[Telecom scanning](user-guide/telecom-scanning.md)** | 5GC/roaming/EPC/IMS verdicts, SEPP PQC readiness, carrier packs |
| **[Hardware crypto catalog](user-guide/hardware-catalog.md)** | HSM/key-store registry, quantum-resistant flags with firmware-cited provenance |
| [Payment crypto](user-guide/payment-crypto.md) | HSM/PCI/TR-39, ceremony provenance |
| [Estate CBOM](user-guide/cbom-export.md) | CycloneDX CBOM export |
| [Dependency graph](user-guide/dependency-graph.md) | graph model, blast radius |
| [Crypto agility](user-guide/crypto-agility.md) | what-if, migration tracking |
| [Migration tracking](user-guide/migration-tracking.md) | PQC program progress |
| [Drift detection](user-guide/drift-detection.md) | baseline vs. observed |
| [CI/CD gates](user-guide/cicd-gates.md) · [CI drift gate](user-guide/ci-drift-gate.md) | pipeline enforcement |
| [SBOM supply-chain gate](user-guide/sbom-supply-chain-gate.md) | generate an SBOM, match advisories offline, block the build, re-scan and diff |
| [Evidence pack](user-guide/evidence-pack.md) | hash-manifested exports |
| **[Audit pack, exit report, engagement archive](user-guide/audit-pack-and-exit-report.md)** | the three hash-sealed engagement deliverables, SC-1…4 scorecard |
| [Compliance reports](user-guide/compliance-reports.md) · [standards](user-guide/compliance-standards.md) | regulator-facing output |
| [Understanding findings](user-guide/understanding-findings.md) · [prioritization](user-guide/prioritization-dashboard.md) | triage |
| [Live monitoring](user-guide/live-monitoring.md) | watch-list daemon, alert-once |
| [Manual scans](user-guide/manual-scans.md) · [viewing scans](user-guide/viewing-scans.md) | running and reading scans |
| [Systems and assets](user-guide/systems-and-assets.md) · [business impact](user-guide/business-impact.md) | estate modeling |
| [Vendor risk](user-guide/vendor-risk.md) | vendor crypto discovery, 0–100 score |
| [Remediation templates](user-guide/remediation-templates.md) | work orders |
| [Exceptions & analytics](user-guide/exceptions-and-analytics.md) | waivers, query |
| [Blast radius](user-guide/blast-radius-analysis.md) | impact analysis |
| [Realtime](user-guide/realtime.md) · [live monitoring](user-guide/live-monitoring.md) | event feeds |

## Admin guide

[Installation](admin-guide/installation.md) ·
[Production](admin-guide/production.md) ·
[Air-gap install](admin-guide/air-gap-install.md) ·
[Hardening](admin-guide/hardening.md) ·
[Backup/restore](admin-guide/backup-restore.md) ·
[Performance](admin-guide/performance.md) ·
[System configuration](admin-guide/system-configuration.md) ·
[Policy rules](admin-guide/policy-rules.md) ·
[Policy scopes](admin-guide/policy-scopes.md) ·
[Baseline approval](admin-guide/baseline-approval.md) ·
[Compliance rule authoring](admin-guide/compliance-rule-authoring.md) ·
[Repo configuration](admin-guide/repo-configuration.md) ·
[Network scan targets](admin-guide/network-scan-targets-config.md) ·
[Container registry integration](admin-guide/container-registry-integration.md) ·
[Fingerprint DB management](admin-guide/fingerprint-db-management.md) ·
[Business context setup](admin-guide/business-context-setup.md) ·
Cloud: [AWS IAM](admin-guide/aws-iam-setup.md) ·
[Azure service principal](admin-guide/azure-service-principal-setup.md) ·
[GCP service account](admin-guide/gcp-service-account-setup.md) ·
Identity: [OIDC SSO](admin-guide/oidc-sso.md) ·
[GitHub integration](admin-guide/github-integration.md) ·
[Neo4j setup](admin-guide/neo4j-setup.md)

## Reference

| Doc | What it covers |
|---|---|
| **[REST API reference](api-reference/rest-api.md)** | generated from the live OpenAPI schema — 585 paths / 644 operations |
| [Plugin SDK](plugin-sdk.md) | writing source scanners |
| [Navigation & feature reference](NAVIGATION-FEATURE-REFERENCE.md) | every page → every feature |
| [Dataflow](DATAFLOW.md) · [end-to-end architecture](END-TO-END-ARCHITECTURE.md) | how data moves |

## Architecture & decisions

[System overview](architecture/system-overview.md) ·
[Service map](architecture/service-map.md) ·
[Database schema](architecture/database-schema.md) ·
[Evidence chain](architecture/evidence-chain.md) ·
[CBOM generation](architecture/cbom-generation-design.md) ·
[Scanner design](architecture/scanner-design.md) ·
[Multi-language scanner](architecture/multi-language-scanner-design.md) ·
[Network scanner](architecture/network-scanner-design.md) ·
[Cloud scanner](architecture/cloud-scanner-design.md) ·
[Container scanner](architecture/container-scanner-design.md) ·
[Deduplication](architecture/deduplication-design.md) ·
[Graph data model](architecture/graph-data-model.md) ·
[Business context](architecture/business-context-design.md) ·
[Multi-layer visibility](architecture/multi-layer-visibility.md) ·
[Platform boundaries](architecture/platform-boundaries.md)

ADRs: [ADR-001…015](decisions/ADR-001-postgresql-over-nosql.md) — Postgres,
JDT parsing, SHA-256 evidence hashes, tree-sitter for JS/TS, Roslyn for C#,
fingerprinting, dedup keys, CycloneDX 1.5 CBOM, Neo4j, active-vs-passive
TLS, eBPF-vs-LD_PRELOAD, multi-cloud IAM, live hardware engine, universal
crypto engine.

## Security

[Threat model](security/threat-model.md) ·
[Hardening checklist](security/hardening-checklist.md) ·
[Dependency audit](security/dependency-audit-2026-08-30.md) ·
[Security questionnaire](security-questionnaire.md)

## Operations & runbooks

[Production checklist](ops/production-checklist.md) ·
[DR recovery](runbooks/dr-recovery.md) ·
[Telecom operations](runbooks/telecom-operations.md) ·
[Live scanning](dev/LIVE-SCANNING.md) ·
[Load test](dev/load-test-2026-08-30.md)

## PoC playbook (FAB engagement)

| Doc | What it covers |
|---|---|
| [PoC proposal](proposals/fab-poc.md) | scope, two-container on-prem run, success criteria agreed up front |
| [Demo script](proposals/fab-demo-script.md) | meeting-ready walkthrough |
| [Security questionnaire](security-questionnaire.md) | bank procurement answers |
| `deploy/poc/` | compose stack, env template, day-by-day operator checklist |
