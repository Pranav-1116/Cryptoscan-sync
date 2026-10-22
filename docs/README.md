# CryptoScan documentation

## Quality implementation progress

See the [step-by-step implementation ledger](product-improvement/IMPLEMENTATION-STATUS.md)
for reproduced defects, bounded code corrections, actual regression results and
remaining independent/site acceptance. Three bounded increments are published
in `2fd8fc8f`: source coverage proof/font bootstrap, unresolved package identity,
and role-store failure/selected probe privacy. See the
[upgrade handoff](runbooks/evidence-assurance-upgrade.md#current-quality-source-handoff-2fd8fc8f)
for changed refusals and requalification. This is not feature expansion, a tagged
release, bank deployment or production approval.

## Deploy directly inside a bank

Read [Bank on-premises deployment](BANK-ON-PREMISES-DEPLOYMENT.md) for the direct,
detailed walkthrough: bank-owned infrastructure, supported topology, data flows,
network rules, identities/secrets, isolated runtime, signed/offline delivery,
installation, upgrades, recovery and actual bank acceptance. It explicitly separates
the controlled local-source profile from unqualified development features.

## Operate continuously with bank monitoring and weekly support

Read [24/7 bank operations and weekly vendor support](BANK-24X7-OPERATIONS-AND-WEEKLY-SUPPORT.md):
bank security monitoring and on-call responsibilities, our weekly health/error/
update review, immediate incident escalation, tested fixes, bank-approved changes
and restricted remote support. Continuous operation is a service objective, not
100% uptime, an enabled live collector or an automatic contractual SLA.

## Improve product quality without adding features

Read the new [end-to-end product-improvement pack](product-improvement/README.md):
baseline/priorities, all six BOMs and correctness, security/privacy/isolation,
reliability/performance/recovery, operator/frontend usability, testing and
maintainability, exact releases, actual bank operations/qualification, an ordered
execution roadmap and a worked example with review templates. This is a
quality-only program with three published bounded corrections, not completion
of the whole roadmap or production approval.

> **Latest published implementation — 2026-10-22 (`2fd8fc8f`):**
> [Current implementation status](CURRENT-IMPLEMENTATION-STATUS.md) reconciles migration
> **0105**, the published quality corrections and CI/launch Preview boundaries.
> The inherited **77**-surface and REST snapshots retain their original review scope.
> Use the [CI/product-build plan](CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) for configured
> checks versus remaining release work. Old evidence retains its original run/date;
> this refresh is not a new production or all-suite passing verdict.

> **What to do next:** [ROADMAP-TO-ENTERPRISE.md](../ROADMAP-TO-ENTERPRISE.md)
> — the sequenced plan to enterprise grade, and what deliberately not to
> build. Its first phase is evidence, not features: this product has never
> scanned a real bank, and that is the binding constraint.
>
> **Read [BACKEND-DATABASE-GAPS.md](../BACKEND-DATABASE-GAPS.md) before quoting
> any readiness figure in this tree.** A 2026-09-28 audit ran the code rather
> than reading the docs and found several controls described here as enforced
> that were not — most seriously, tenant isolation on the scan surface. Where
> that file and later implementation disagree, current code/tests and the dated
> superseding guides take precedence; the audit is historical evidence. It
> also records what was then fixed (CI, PostgreSQL parity, tenant isolation,
> frontend route guards) and what is still open.
>
> **Supported topology: one deployment per customer.** Self-serve tenant
> signup ships disabled for the reason given in that document.
>
> **Newer than that audit:**
> [PRODUCTION-ROADMAP.md §0](PRODUCTION-ROADMAP.md#0-internal-work-update-2026-10-05)
> records the 2026-10-05 internal pass — probe behaviour under a database
> outage, evidence-chain de-duplication, monitor liveness, DR and restore
> probes, local-stack data durability, and the browser-facing npm advisories.
> It flips no gate category: those still turn on external evidence.
>
> **2026-10-08 code handoff:** [Production gap handoff](PRODUCTION-GAP-HANDOFF-2026-10-08.md)
> records the evidence-path changes, tests actually run, unresolved bugs and
> suggested fixes. Its final full-suite and lint gates have **not** been rerun;
> it is not a production approval.

> **Start with [docs/product/](product/README.md)** — the whole product end to end, with diagrams.
> **For an enterprise vendor-style manual, use the [Enterprise Documentation Center](product/enterprise/README.md)** — product, deployment, security, API, operations, developer, support, adoption, and readiness in one path.
> **For the current console menu and route map, use [Navigation & Feature Reference](NAVIGATION-FEATURE-REFERENCE.md)** — it mirrors the six sidebar sections in `frontend/src/components/Layout.tsx` and the deep links in `frontend/src/App.tsx`.
> **How production-ready is it?** Read the current gate at
> [the root PRODUCTION-READINESS.md](../PRODUCTION-READINESS.md). It reports
> explicit PASS/FAIL/SKIP evidence and does not turn percentages or synthetic
> estates into a production approval.
> **Which parts are production-supported?** [CAPABILITY-MATURITY.md](CAPABILITY-MATURITY.md) — every classified console surface is GA, beta or preview (33 / 32 / 12), labelled in the UI and served at `GET /api/v1/platform/capabilities`. The documentation audit and remaining gaps are tracked in [DOCUMENTATION-STATUS.md](DOCUMENTATION-STATUS.md).

Production cryptographic inventory and compliance platform: deterministic
scanners, hashed evidence, YAML policy, drift, and a dashboard. Policy is
never decided by AI; unknowns are skipped with reasons, never faked.

**New here?** Boot the stack with `bash scripts/run_stack.sh`, log in with
`admin` / `cryptoscan` (development only), then read
[Dashboard overview](user-guide/dashboard-overview.md).

## Bank environment walkthrough

Start with [How CryptoScan enters a bank and produces six BOMs](bank-environment/README.md)
for an expanded, code-traced guide: deployment, permissions and collection,
scan-to-evidence processing, the six BOMs, practical bank examples, UI/API
exports, operational acceptance, and implementation limits. Examples are
illustrative, not real-bank scan results or production approval.

For dependency analysis, continue with [discovery and evidence](bank-environment/12-dependency-discovery-and-evidence.md),
[cascade mechanics](bank-environment/13-cascade-and-blast-radius.md),
[bank examples](bank-environment/14-bank-cascade-examples.md),
[API runbook](bank-environment/15-dependency-cascade-api-runbook.md) and
[limitations/acceptance](bank-environment/16-dependency-limitations-and-acceptance.md).

For international, multi-vendor estate assessment, start with
[guide 27](bank-environment/27-international-bank-scan-program.md) and continue
through guides 28–34 in the bank index. This eight-guide planning pack covers
supplier evidence contracts, every major system class, exact identity and
coverage, regional security/operations, failure qualification, engineering
priorities and a fictional multinational assessment. It distinguishes current
code from proposed controls and does not change readiness or supported topology.

Recent bank-boundary engineering is documented in
[queued authority and durable SSH receipts](bank-environment/44-queued-authority-and-durable-ssh.md)
and [Redis TLS/ACL/Sentinel qualification](bank-environment/45-redis-tls-sentinel-qualification.md).
The latter includes executable destructive disposable-lab instructions and an
explicit production acceptance checklist; passing local fixtures is not bank certification.
For coordinated producer/worker migration, legacy pins, RUNNING-job recovery and
cursor resets, use the [execution/replay upgrade runbook](runbooks/execution-and-replay-upgrade.md).
For endpoint semantics, use the [API contract companion](api-reference/execution-and-replay.md).
The generated API reference was refreshed in-process on 2026-10-22: **917 paths,
1,008 operations, 105 tagged groups**. No server/deployment was started by schema
generation; route availability and qualification remain separate.

## Start here

| Doc | What it covers |
|---|---|
| **[The product, end to end](product/README.md)** | ten implementation/strategy documents with 31 rendered diagrams and explanatory posters: what it is, every feature, architecture, data flow, scan trace, scope & readiness, glossary, engines, end-to-end trace, and the Cryptography Threat Intelligence roadmap |
| **[Documentation status and coverage](DOCUMENTATION-STATUS.md)** | full `docs/` inventory, source-of-truth order, documentation families, stale-count reconciliation, known gaps, and update rules |
| **[Navigation & Feature Reference](NAVIGATION-FEATURE-REFERENCE.md)** | the current six-section sidebar, primary routes, deep-linked pages, role-guarded actions, and the binary BOM workflow behind Applications |
| **[Enterprise Documentation Center](product/enterprise/README.md)** | vendor-style documentation path covering overview, capability catalog, deployment, first scan, architecture, data, identity, privacy, scanners, policy, API, operations, support, developer extensions, lifecycle, adoption, and readiness |
| [Telecom — 5G crypto configuration](telecom-5g-crypto.md) | SUPI concealment, NEA/NIA, N32 roaming, MILENAGE/TUAK and the 5G key hierarchy — the TS 33.501 controls no external probe can see, where the permissive setting looks healthy in service |
| [Network controls](security/NETWORK-CONTROLS.md) | how the product behaves behind a bank's IDS, firewalls, proxies and rate limits — traffic matrix and pilot firewall rules |
| [Key inventory](accuracy/KEY-INVENTORY.md) | HSM / KMS / keystore / certificate exports ingested and reconciled with code (consumers, orphans, keys outside the estate) |
| [Cascade analysis](accuracy/CASCADE-ANALYSIS.md) | dependency & blast-radius layer: providers, migration waves, libraries, shared keys, weak key sizes |
| [Production readiness](../PRODUCTION-READINESS.md) | unified timestamped evidence gate with explicit PASS/FAIL/SKIP; no synthetic-estate or corpus-only production claim |
| [Product capabilities, end to end](PRODUCT-CAPABILITIES-END-TO-END.md) | the whole product as one loop — collect → inventory → assess → gate → evidence → report |
| **[Cryptography Threat Intelligence roadmap](product/cryptography-threat-intelligence-roadmap.md)** | product strategy from discovery and CBOM through threat intelligence, detection, defence, response, evidence, and governance; shipped vs planned vs research |
| **[Global market value and commercial model](market/global-cryptography-threat-intelligence-market-value.md)** | dated market context, customer value, addressable wedge, illustrative pricing/revenue scenarios, and valuation boundaries |
| [Platform status](PLATFORM-STATUS.md) | every planned capability vs. what ships — honest accounting |
| [Enterprise readiness](enterprise-readiness.md) | feature matrix with honest gaps; what blocks production |
| **[Standard bank pilot](pilot-standard.md)** | standardized pilot scope, objectives, roles, evidence, acceptance criteria, and decision language |
| [Pilot duration and phases](pilot-duration-and-phases.md) | proposed two-, six-, eight-, and twelve-week pilot models with phase exit criteria |
| [Business model](business-model.md) | customer profile, offers, pricing basis, responsibilities, revenue model, and commercial guardrails |
| **[Detailed price model](price-model.md)** | proposed evaluation, subscription, estate-band, implementation, support, discount, margin, and quote structures |
| **[Company legal, privacy, assurance, and questionnaire pack](company/README.md)** | MSA, NDA, DPA, SLA, security, privacy, subprocessors, assurance, and reusable vendor-questionnaire answer bank |
| [Platform boundaries](architecture/platform-boundaries.md) | what CryptoScan is and is not (single source of truth: `shared_models/platform_scope.py`) |
| [Real-world comparison](architecture/real-world-comparison.md) | honest benchmark vs. Venafi, SandboxAQ, Prowler, Trivy, testssl.sh, Nozomi, SAST |
| [SBOM scanner architecture vs. what ships](architecture/sbom-scanner-architecture.md) | the 11-source / Kafka-Flink target architecture mapped against this repo, gap by gap |

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
| [Estate CBOM](user-guide/cbom-export.md) | CycloneDX CBOM export with real estate dependency edges |
| [Dependency graph](user-guide/dependency-graph.md) | graph model, blast radius |
| [Cross-BOM cascade](user-guide/cross-bom-cascade.md) | one target — algorithm, certificate, endpoint, system, vendor, device, library — fanned out across every BOM layer with persisted run history |
| [Crypto agility](user-guide/crypto-agility.md) | what-if, migration tracking |
| [Migration tracking](user-guide/migration-tracking.md) | PQC program progress |
| [Drift detection](user-guide/drift-detection.md) | baseline vs. observed |
| [CI/CD gates](user-guide/cicd-gates.md) · [CI drift gate](user-guide/ci-drift-gate.md) | pipeline enforcement |
| [Binary & firmware scanning](user-guide/binary-firmware-scanning.md) | bounded ELF/PE/Mach-O/WASM/mobile/archive/firmware parsing, graded crypto evidence, correlated SBOM/CBOM/HBOM/NBOM/VBOM/vulnerability views, and explicit limits |
| [SBOM supply-chain gate](user-guide/sbom-supply-chain-gate.md) | generate an SBOM, match advisories offline, block the build, re-scan and diff |
| [Evidence pack](user-guide/evidence-pack.md) | hash-manifested exports |
| **[Audit pack, exit report, engagement archive](user-guide/audit-pack-and-exit-report.md)** | the three hash-sealed engagement deliverables, SC-1…4 scorecard |
| [Compliance reports](user-guide/compliance-reports.md) · [standards](user-guide/compliance-standards.md) | regulator-facing output |
| [Understanding findings](user-guide/understanding-findings.md) · [prioritization](user-guide/prioritization-dashboard.md) | triage |
| [Live monitoring](user-guide/live-monitoring.md) | watch-list daemon, alert-once |
| [Manual scans](user-guide/manual-scans.md) · [viewing scans](user-guide/viewing-scans.md) | running and reading scans |
| [Systems and assets](user-guide/systems-and-assets.md) · [business impact](user-guide/business-impact.md) | estate modeling |
| [Vendor risk](user-guide/vendor-risk.md) | vendor crypto discovery, 0–100 score |
| **[Vendor and network inventory](user-guide/vendor-network-inventory.md)** | versioned vendor due diligence and structured network inventory, topology, coverage, drift, evidence, and no-secret boundaries |
| [Remediation templates](user-guide/remediation-templates.md) | work orders |
| [Exceptions & analytics](user-guide/exceptions-and-analytics.md) | waivers, query |
| [Blast radius](user-guide/blast-radius-analysis.md) | impact analysis |
| [Realtime](user-guide/realtime.md) · [live monitoring](user-guide/live-monitoring.md) | event feeds |

## Admin guide

[Installation](admin-guide/installation.md) ·
[Production](admin-guide/production.md) ·
[Air-gap install](admin-guide/air-gap-install.md) ·
[Hardening](admin-guide/hardening.md) ·
[Scanner configuration](admin-guide/scanner-configuration.md) ·
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
| **[REST API reference](api-reference/rest-api.md)** | generated API snapshot from 2026-10-16 — 834 paths / 920 operations across 101 tagged groups |
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
[Testing](dev/TESTING.md) ·
[Staging without Docker](../deploy/staging/README.md) ·
[Soak / burn-in evidence](soak-evidence/README.md) ·
[Burn-in](burn-in.md) · [Load / soak](load-soak.md) ·
[Load test 2026-08-30](dev/load-test-2026-08-30.md)

## PoC playbook (FAB engagement)

| Doc | What it covers |
|---|---|
| [PoC proposal](proposals/fab-poc.md) | scope, two-container on-prem run, success criteria agreed up front |
| [Demo script](proposals/fab-demo-script.md) | meeting-ready walkthrough |
| [Security questionnaire](security-questionnaire.md) | bank procurement answers |
| `deploy/poc/` | compose stack, env template, day-by-day operator checklist |

### Controlled execution (0102)

Read the [breaking controlled-execution upgrade](runbooks/controlled-execution-upgrade.md)
and [API examples](api-reference/controlled-execution.md) before deploying this
increment. It implements approvals, typed provenance, shared SQL budgets/fairness,
stop checks, ownership/residency admission and fenced/outbox recovery for a
**local-source-only support profile**. Production refuses other unqualified
surfaces; it does not certify physical residency, isolation or all P0 acceptance.
