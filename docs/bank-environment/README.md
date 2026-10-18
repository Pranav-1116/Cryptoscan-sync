# How CryptoScan enters a bank and produces six BOMs

**Code-traced guide · 2026-10-18 · SBOM / NBOM / CBOM / TechBOM / HBOM / VBOM**

The practical answer is: **the bank installs and authorizes the platform inside
its own approved environment, gives specific collectors limited access to
specific assets, and receives evidence-backed inventories through the internal
web console and export APIs.** It does not enter by exploiting infrastructure,
automatically discover every subnet, or obtain visibility merely by installing
one central server.

This guide explains the current implementation, an operator-approved deployment
pattern, and illustrative bank scenarios. It is not a report of an actual bank
installation or a substitute for the bank's security/change approval.

## Read in order

| Document | Question it answers |
|---|---|
| [01 — Entry and deployment](01-entry-and-deployment.md) | Who installs it, where does it run, and what crosses a firewall? |
| [02 — Collection and access](02-collection-and-access.md) | How does it reach repositories, networks, clouds, hardware and vendors? |
| [03 — Scan-to-output pipeline](03-scan-to-output-pipeline.md) | What happens between clicking Scan and seeing results? |
| [04 — The six BOMs](04-six-boms.md) | What exactly does each BOM contain, and how are they related? |
| [05 — Practical bank walkthrough](05-practical-bank-walkthrough.md) | What does a scoped payments pilot look like, including API requests? |
| [06 — Console, APIs and exports](06-console-apis-and-exports.md) | Where does the operator see, download and verify each output? |
| [07 — Operations and acceptance](07-operations-and-acceptance.md) | How do re-scans, remediation, audit handoff and production acceptance work? |
| [08 — Implementation map and limits](08-implementation-map-and-limits.md) | Which source files implement this, and what must not be overstated? |
| [09 — SBOM deep dive](09-sbom-deep-dive.md) | How are software packages, lockfiles, images, artifacts and assessments handled? |
| [10 — Six-BOM bank release example](10-six-bom-bank-release-example.md) | How do six inventories corroborate one release without inventing relationships? |
| [11 — Detailed rollout and responsibilities](11-detailed-rollout-and-responsibilities.md) | What does each bank team do, and what exits each implementation phase? |
| [12 — Dependency discovery and evidence](12-dependency-discovery-and-evidence.md) | How are code, packages, systems, telemetry and cross-domain links discovered or declared? |
| [13 — Cascade and blast-radius mechanics](13-cascade-and-blast-radius.md) | How do target resolution, directional walks, counts, backends and replay work? |
| [14 — Detailed bank cascade examples](14-bank-cascade-examples.md) | What do HSM, application, algorithm, certificate and supplier investigations actually show? |
| [15 — Dependency/cascade API runbook](15-dependency-cascade-api-runbook.md) | How does an operator inspect/register links, run analysis, retain history and compare results? |
| [16 — Dependency limitations and acceptance](16-dependency-limitations-and-acceptance.md) | What can be missing or misleading, what should improve, and what should the bank test? |
| [17 — Implemented classified system scope](17-classified-system-scope.md) | What changed in step 1, how do the disjoint counts work, and what remains pending? |
| [18 — Implemented shared system semantics](18-shared-dependency-semantics.md) | Which relations propagate in step 2, how are backends/history handled, and what is still unqualified? |
| [19 — Implemented package/release/deployment identity](19-package-artifact-deployment-identity.md) | How does a package SBOM explicitly join to immutable release bytes/digest and a declared application deployment? |

**CISO / bank sponsor:** start here, then 01, 04 and 07.<br>
**Platform / infrastructure team:** 01, 02, 05 and 08.<br>
**Application security / operators:** 02 through 07, then 09 and 10.<br>
**Auditor / procurement:** 04, 06, 07 and 08.

## One end-to-end picture

```text
BANK APPROVAL: estate owner + information security + network/change team
      |
      v
Bank-controlled deployment: HTTPS ingress -> React console / API
                            PostgreSQL + Redis + optional graph service
                            workers / explicitly configured monitors
      |
      +-- approved Git or mounted source ----------> source collectors
      +-- approved IP:port / TLS services ---------> network collectors
      +-- permitted cloud control-plane APIs -----> cloud collectors
      +-- approved hardware metadata / events ----> hardware collectors
      +-- vendor declarations / supplied BOMs ----> vendor ingestion
      |
      v
Observed facts + declared facts, labelled by source and time
      -> durable scan/job/evidence/inventory records (path-dependent)
      -> normalization / identity / policy / recorded relationships
      -> SBOM | NBOM | CBOM | HBOM | VBOM | TechBOM views
      -> internal UI, snapshots, comparisons and controlled exports
      -> bank owner reviews -> bank change -> re-scan -> evidence of outcome
```

The source parser's isolated container is a special boundary: it receives an
admitted staged checkout, **has no network**, and returns bounded structured
results. The worker outside that parser may need Git, database and queue access.
Network/cloud routes can also execute inside the API process; permitting only
the worker to reach targets is not sufficient for those routes.

## The six names in one minute

| Product output | Bank question | Example |
|---|---|---|
| **SBOM — Software Bill of Materials** | What software components, versions and dependencies are present in the inspected input? | Application manifests/lockfiles, container packages, or supplied software BOMs |
| **NBOM — Network Bill of Materials** | What service is exposed, with which observed transport cryptography? | A partner gateway listener, negotiated TLS/cipher and served certificate |
| **CBOM — Cryptographic Bill of Materials** | Where is cryptography used, and what evidence supports it? | RSA key usage, AES mode, library and source location |
| **TechBOM — Technology Bill of Materials** | How do the technology inventory layers fit together? | Application, crypto, hardware and vendor projections plus recorded dependencies |
| **HBOM — Hardware Bill of Materials** | Which hardware and security components have actually been inventoried? | HSM model/firmware, TPM status, observation agent and last-seen time |
| **VBOM — Vendor Bill of Materials** | Which vendors/products supply crypto dependencies, and what do we know about them? | Vendor crypto declaration, dependent systems and due-diligence profile |

In this product **VBOM means Vendor BOM**, not Vulnerability BOM. Binary scanning
also has a separate vulnerability-BOM sidecar; the two must not be conflated.
TechBOM is not another independent scanner: its current general materializer
projects `sbom`, `cbom`, `hbom`, `vendor` and certificate metadata. NBOM remains a
separate network-evidence surface; do not promise a `nbom` export layer that the
TechBOM export API does not implement.

## What is and is not being claimed

- These documents follow source at the time of writing; file/API links are
  collected in [08](08-implementation-map-and-limits.md). Existing older docs
  can describe broader designs or historical behavior.
- A bank-owned, single-customer deployment is the recommended discussion
  baseline. Tenant controls exist, but a shared multi-bank SaaS deployment is
  not made production-approved by this walkthrough.
- All bank names, paths, addresses, findings and scenario counts here are
  **illustrative**. No customer target was scanned to write these documents.
- Source scanning cannot prove the code path runs in production. TLS probing
  cannot see every internal application algorithm. A vendor claim is not a
  device measurement. Missing data remains unknown.
- Infrastructure, credentials, image provenance, isolated parser provisioning,
  provider integrations, performance, disaster recovery and security controls
  require bank-specific qualification. See the current
  [production readiness gate](../../PRODUCTION-READINESS.md).
- CI workflow changes are outside this documentation task; a documentation push
  is not a deployment or a successful CI/production test.

## SBOM is a first-class output, not just a TechBOM label

The standalone SBOM workflow discovers software components from supported
manifest/lockfile or container/binary inputs, renders CycloneDX/SPDX and stores
artifacts for download, verification, comparison and review. This is distinct
from the TechBOM `sbom` layer, which starts from registered applications/systems.
Begin with [the detailed SBOM guide](09-sbom-deep-dive.md), then follow
[one release across all six BOMs](10-six-bom-bank-release-example.md).

## Dependency, cascade and blast-radius learning path

Read [12](12-dependency-discovery-and-evidence.md) through
[16](16-dependency-limitations-and-acceptance.md) for the detailed explanation.
The central distinction is **modeled dependency exposure versus confirmed
operational failure**. A source import, declared system call, observed listener
and supported package resolution have different evidence strength. The new
[bank examples](14-bank-cascade-examples.md) include a reproducible pure-engine
fixture showing six implicated systems, an eight-system change-review context,
and a missing HSM link that must remain unknown rather than safe.

Implementation progress is tracked in the [ten-step engineering plan](../dev/dependency-intelligence-roadmap.md).
[Step 1](17-classified-system-scope.md), [step 2](18-shared-dependency-semantics.md)
and [step 3](19-package-artifact-deployment-identity.md) are implemented with local
checks; steps 4–10 and real deployment qualification remain pending.
