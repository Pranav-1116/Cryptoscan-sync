# 11 — Detailed bank rollout, responsibilities and acceptance

[Guide index](README.md) · [Deployment](01-entry-and-deployment.md) ·
[Operations](07-operations-and-acceptance.md) · [Release example](10-six-bom-bank-release-example.md)

This is a **recommended implementation plan**, not an automated installation
contract, completed bank deployment, staffing commitment or product certification.
The bank decides its approvals, roles, timelines and acceptance thresholds.

## 1. Who does what

| Team/role | Bank-owned responsibility | CryptoScan/platform activity | Evidence to retain |
|---|---|---|---|
| Sponsor / risk owner | Agree scope, purpose, residual risk and acceptance | Explain supported capabilities and gaps | Signed scope and risk decisions |
| Infrastructure / platform | Provision approved compute, TLS, storage, backup and runtime controls | Deploy the selected topology and configure services | Image versions/digests, configuration review, restore test |
| IAM / security engineering | Approve identities, roles, secrets and tenant boundaries | Configure authentication and exercise actual routes | Positive/negative authorization results |
| Network owner | Authorize named targets, ports, windows, egress and stopping conditions | Configure collectors and route-specific controls | Target approval, route used, actual stored run/job IDs |
| Application/build owner | Supply authorized source revision, manifests, lockfiles and release provenance | Run distinct software and crypto workflows | Source/build identities, SBOM artifact and crypto scan records |
| Container registry owner | Supply admitted digest/archive and access policy | Inspect supported image input | Actual image digest, collector/tool outcome |
| Cloud owner | Approve account/role/API scope and credential handling | Run selected supported metadata collectors | Account/region scope, API errors, collection time |
| Hardware owner | Approve collector and substantiate device/firmware identity | Ingest supported observations and capture independent HBOM | Device identity, observer, timestamps, HBOM pin |
| Procurement / vendor risk | Obtain version-specific supplier evidence | Maintain vendor records, declarations and due-diligence review | Supplier/product/version, provenance and unresolved claims |
| Application security | Interpret findings and agree remediation | Review all six outputs and their confidence/coverage | Decisions, exceptions, re-scan comparisons |
| Audit / compliance | Define retention, evidence access and required controls | Export supported artifacts and verification records | Evidence index, custody, integrity and access records |

Scanner service accounts should not automatically inherit platform admin rights.
A supplier representative does not approve the bank's network scan. A successful
export does not replace bank risk acceptance.

## 2. Phase 0 — Scope and data-handling agreement

Before installation, agree:

1. Which business service and environment are included, and which are excluded?
2. Which input types will be supplied: source, lockfiles, image, endpoints,
   cloud metadata, hardware observations, supplier documents?
3. Which data may be read, staged, persisted, backed up or exported?
4. Who may authorize scans, stop collection, review results and accept risks?
5. Which integration gaps need separate engineering rather than configuration?
6. What counts as success for each BOM independently?

**Exit:** approved scope and owners, realistic access model, explicit unknowns
and no unauthorized production target in examples or default schedules.

## 3. Phase 1 — Install and qualify the platform

Use the bank-controlled deployment baseline from [01](01-entry-and-deployment.md).
Inventory API, frontend, workers, database, queue, staging, artifact storage,
optional graph service, ingress and collectors. Determine which process executes
each workflow and which boundary it must reach.

A practical qualification sequence:

- Validate approved images/runtime versions and secrets provisioning.
- Verify HTTPS, authentication, route-level roles and tenant-negative cases.
- Prove database migration, persistence, backup and restore on the actual setup.
- Provision persistent SBOM artifact storage explicitly; test restart and
  replica visibility rather than relying on its temporary fallback.
- Provision the immutable isolated source-parser runtime and shared staging
  needed by the queued crypto AST path. The standalone source SBOM path is
  different and must be reviewed independently.
- Exercise bounded failure cases: unavailable target, invalid path, missing
  tool, denied role, parser failure, unavailable store and expired credentials.
- Validate logs/metrics for partial/error outcomes and their data exposure.

**Exit:** bank-approved environment and negative tests; no claim that stock
Compose alone provides every bank security or high-availability control.

## 4. Phase 2 — Admit one representative input per workflow

Use a small bank-approved non-production slice. For each input record:

```text
Owner -> approval -> input identity -> admitted execution path
      -> permissions/connectivity -> coverage expectation -> failure handling
```

For source, prove actual checkout/export identity and mounts. For network,
verify hostname/SNI/port and the selected handler's admission/persistence
behavior. For cloud, record real account/region scope. For hardware, prove the
observation source and staleness handling. For vendor material, retain supplier
origin and the product release to which it applies.

**Exit:** a traceable input register, not merely an “integration configured” label.

## 5. Phase 3 — Generate and inspect six independent outputs

| Output | Minimal practical acceptance exercise | Common misleading shortcut to reject |
|---|---|---|
| SBOM | Parse supported source/lockfile or image input, inspect package scope/counts and retrieve/verify the generated artifact | Calling the TechBOM `sbom` application layer a package inventory |
| CBOM | Locate one supported crypto observation, source/evidence reference and coverage/unknowns | Claiming every crypto-relevant dependency executes cryptography |
| NBOM | Read persisted approved probes and explain observed endpoint/certificate evidence | Expecting GET `/cbom/nbom` to perform network discovery |
| HBOM | Ingest a substantiated device observation and exercise supported independent snapshot/diff | Treating a hardware projection as measured app-to-HSM linkage |
| VBOM | Review a real supplier/product declaration with provenance and recorded system links | Treating a missing readiness field or unverified declaration as a measurement |
| TechBOM | Inspect shared inventory layers, known dependencies, missing mappings and caps | Assuming an atomic snapshot that embeds every other artifact |

Acceptance is about justified coverage, not a predetermined number of findings.
If an input has no supported crypto or no parsed packages, establish whether that
is expected or a parser/coverage limitation; do not manufacture a positive result.

**Exit:** real artifacts/records for the agreed scope, documented exclusions and
an explanation of evidence strength for each output.

## 6. Phase 4 — Reconcile identities and review one change

Select one authorized change, such as a dependency update in a controlled test
release. Keep its old input identity, build/deployment record and artifacts.
Generate the new software artifact and relevant crypto/network/hardware/vendor
observations only where the change and scope justify them.

Compare supported artifact/pin pairs; verify that identifiers really refer to
the intended records. Explain expected count differences and retain actual
cutoff times. Use a separate evidence manifest for the review bundle because
there is no guaranteed cross-store atomic six-BOM capture.

**Exit:** a reproducible before/after explanation with unchanged gaps, not just
two screenshots or a claim that a pipeline gate automatically deployed a fix.

## 7. Phase 5 — Operations handover

Agree a runbook with the following event handling:

| Event | Expected bank/operator action |
|---|---|
| New software release | Generate/reconcile relevant SBOM and crypto evidence; bind to build/deployment identity |
| New advisory/feed | Identify which artifacts were actually matched; assess affected deployed scope and escalate |
| Supplier declaration expires | Request refreshed, release-specific evidence; retain prior version and unresolved state |
| Hardware firmware changes | Refresh supported observations; preserve old/new HBOM evidence and independent linkage |
| TLS endpoint/certificate changes | Run an approved probe and retain the actual stored result; investigate unexpected identity changes |
| Scan fails or is partial | Record failure and last-good age; do not replace unknowns with clean status |
| Storage/key rotation | Exercise retrieval, digest/signature/decryption checks and retention of old verification material |
| Access revoked / target removed | Disable appropriate schedules/credentials, confirm route behavior and retain audit history |

The bank sets freshness limits, escalation times, maintenance windows, capacity
and retention periods. Validate concurrency/resource limits with its actual
representative inputs; unit tests are not a performance certification.

## 8. Release-review evidence bundle

An illustrative directory layout is a bank-managed handoff convention, **not an
existing automatic “export all six” endpoint**:

```text
release-evidence/
  scope-and-approvals/
  input-identities-and-build-provenance/
  sbom-artifacts-and-verification/
  cbom-evidence-and-pins/
  network-runs-and-nbom/
  hardware-observations-and-hbom/
  supplier-evidence-and-vbom/
  technology-view-and-recorded-relationships/
  coverage-failures-and-exceptions/
  change-review-and-acceptance/
```

Record artifact format, actual ID, content digest, capture time, collector/input
identity, verification results and access classification in the bundle index.
Keep raw source, credentials and signing keys out of the evidence handoff unless
the bank has separately approved a specific handling process.

Do not invent snapshot APIs for outputs that lack them. Capture the actual
supported result/export with its provenance and preserve integrity externally
where the product does not provide a native pin.

## 9. Questions a detailed demonstration must answer

- Can the operator distinguish declared, resolved, observed and independently
  verified facts?
- Can the reviewer find a software component/version without mistaking an
  application row for the entire package SBOM?
- Can each actual input and stored record be retrieved by its own identifier?
- Are advisory-feed absence, parser limits, missing links and stale evidence
  visible instead of collapsed into zero risk?
- Can the team demonstrate failure/denial, integrity verification and restore?
- Does every remediation have an accountable bank owner and a tested recheck?
- Can the team show what was **not** installed, scanned, integrated or qualified?

Only the bank can approve the resulting deployment and residual risk. These
documents and their local tests provide implementation guidance, not that approval.
