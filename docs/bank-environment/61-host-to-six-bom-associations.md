# Host evidence → existing six-BOM provenance associations

**2026-10-24 · bounded development adapter, not production qualification**

This follows [approved offline collection](59-approved-offline-host-collection.md).
It connects imported host facts to existing identities without creating another
inventory, service, collector or dependency-inference engine. The
[ten-point ledger](60-host-first-product-acceptance.md) remains an incomplete
acceptance ledger, not a bank certification.

## 1. Two things that must never be confused

- **Reviewed metadata association:** two identified customer humans explicitly
  associate one fact in an approved imported report with one existing scoped
  identity. The edge is `DECLARED`, runtime and PQC use `UNKNOWN`.
- **Operational dependency/use:** an application invokes a particular HSM, key,
  algorithm, library, endpoint or KMS operation. This adapter does **not** establish
  that. Its `operational_dependency_verified` and `host_identity_attested` flags
  remain false, even after independent customer review.

No graph edge is manufactured from a matching name, shared subnet, co-installation,
model name, vendor ML-KEM claim or empty/failed probe. Imported certificate metadata
is not an observed application crypto call. Local certificate inspection may say
`OBSERVED`; imported server evidence still says `IMPORTED`. Config metadata has
local basis `DECLARED`; its presence does not prove negotiated TLS.

## 2. All six BOMs, with actual identity boundaries

| Domain | Representation and association target | Checked on inspection/proposal/review/current graph read | Still not established |
|---|---|---|---|
| SBOM | Host package/binary metadata; optionally `sbom_binding` **plus exact canonical versioned package identity** | Exact owner and release artifact; retained original SBOM bytes/manifest/digest reopened; package actually present; active explicit deployment for the same approved system **and environment**; binding/deployment lifecycle, revisions and expiry | Installed binary belongs to that release, package is loaded or crypto is invoked |
| CBOM | Certificate and TLS-configuration metadata facts from the approved imported report | Full snapshot/manifest/Scan/EvidenceRecord membership, original source-derived projection and evidence chain; exact input and zero-based fact ordinal | Config is effective, cert is served, EC subject key means ECDSA/ECDH use, policy/PQC posture |
| NBOM | `phase_receipt` referencing an existing successful SSH `host_keys` receipt | Exact owner/job; completed job/phase; successful, hash-intact nonempty bounded key observation; matching receipt/observation endpoint; server-recorded start within seven days; no conflicting pre-existing system assignment | Endpoint authenticity, host→service identity, actual negotiated algorithm, secure/insecure verdict; this version does **not** add TLS-phase support |
| HBOM | Existing `hardware` identity | Exact owner; identity/manufacturer/model/revision/fingerprint and a digest of firmware/TPM/HSM/capability metadata | Attested physical identity, fresh agent observation, live mechanisms, firmware trust or application→HSM use |
| VBOM | Existing `vendor` identity | Exact owner; name/type/contract expiry; committed vendor metadata digest | Supplier declaration is correct, product certified, deployed HSM uses ML-KEM |
| TechBOM | Approved logical system scope, report/receipt containment; optional explicit `deployment` | Exact owner; artifact/system/environment/deployment key, lifecycle/revision/expiry and declaration evidence references | Approval attests the physical host, application is running or cloud KMS is in use |

An SSH job can have no pre-existing system assignment. In that case the **new
reviewed association itself is the declaration**; the job is not silently edited
or promoted into authenticated host identity. A job explicitly belonging to a
different system is refused. Existing SSH collection is reused; no packet is sent
by target lookup, graph construction or review.

A hardware/supplier association can refer to declared inventory even if an actual
hardware observation is unavailable or old. The association expiry is a customer
assertion validity window, **not** a refreshed agent heartbeat or a new observation.
Opaque hardware/vendor metadata is committed by hash, not returned wholesale by
the target-inspection response. Risk scores/contact details are not dependency
proof. Independent provenance/operation evidence must be added by a separately
qualified source before use can be claimed.

Every graph returns all six domain labels. `represented: true` means a typed
metadata node exists, not complete discovery or operational coverage.
`represented: false` means unresolved metadata, **not** absence of risk.

## 3. Deliberate operator workflow

1. Approve, collect and import the bounded host snapshot through the existing
   workflow. Inspect it in the CBOM console. No Git/repository is required.
2. Select a specific parsed source fact. Denied/unsupported inputs and missing
   ordinals cannot be selected as positive evidence.
3. Find the existing identity in the appropriate BOM. Supply its **actual ID**,
   not a matching display name. For SBOM supply its exact versioned package purl.
4. Inspect the target. The response contains the digest of the selected current
   identity projection. Proposal must echo that digest; a changed identity is
   refused rather than silently substituted.
5. Analyst/admin/CISO supplies an evidence reference and meaningful rationale.
   A strictly bounded, append-only `PROPOSED` record is created. It is **not** an
   active association edge.
6. A **different** current admin/CISO inspects the evidence and reviews the exact
   expected revision, with another reference/rationale. An auditor cannot perform
   this review. Giving the proposer a new CISO role does not make them a different
   human.
7. Load the graph. Only currently resolved `REVIEWED` associations appear as
   `CUSTOMER_REVIEWED_METADATA_ASSOCIATION` edges. Review does not promote their
   basis above `DECLARED`. Export uses the same revalidation and a chained audit.
8. An admin/CISO can retract a pending, reviewed or stale assertion by expected
   revision. History is retained. An unchanged tuple cannot be overwritten or
   reproposed in v1; a stale/retracted assertion requires a newly approved report
   for renewal. This deliberately avoids hidden refresh or silent reapproval.

The console uses a 24-hour assertion window; the API accepts an explicitly
UTC-offset-aware future expiry up to seven days. This is independent of the
one-use host **intake approval** interval. Historical imported bytes remain
inspectable; assertion expiry never grants renewed collection authority.

Changing source approval, tenant, session or identity clears applicable private
proof/drafts; pending responses cannot repopulate another scope. No auto-fetch on
panel mount, automatic upload, automatic action replay or sample-data fallback.
Current server authorization is authoritative even if a button is visible.

## 4. Routes and example using the existing authenticated console client

All routes are below `/api/v1/host-evidence/approvals/{approval_id}`:

| Method / suffix | Authority / effect |
|---|---|
| GET `/association-target?target_type=...&target_id=...&package_identity=...` | Scoped readers inspect a resolvable selected target; no collection or mutation |
| POST `/associations` | Current typed human `assurance.manage`; append proposal and audit atomically |
| POST `/associations/{id}/review` | Different current admin/CISO `assurance.trust`; expected revision, full source/target revalidation |
| POST `/associations/{id}/retract` | Current admin/CISO `assurance.trust`; expected revision, retained history |
| GET `/graph` | Scoped readers; complete bounded current projection, no mutation |
| GET `/graph/export` | Same checks plus atomic export audit; no-store JSON |

Example inside the existing authenticated, selected-estate frontend client;
`approvalId`, `hardwareId`, `inputId` and `ordinal` come from actual inspected
records, not this guide:

```typescript
const resolved = await apiHostAssociationTarget(approvalId, "hardware", hardwareId);
if (!resolved.ok || resolved.source !== "live" || !resolved.data) {
  throw new Error("Target unresolved; do not invent a relationship");
}
const proposal = await apiProposeHostAssociation(approvalId, {
  input_id: inputId, fact_ordinal: ordinal,
  target_type: "hardware", target_id: hardwareId, package_identity: null,
  expected_target_sha256: resolved.data.target_sha256,
  expires_at: new Date(Date.now() + 24 * 3600_000).toISOString(),
  evidence_ref: "change/approved-host-device-mapping",
  reason: "Customer metadata mapping reviewed against separately retained change evidence",
});
// Stop here. A DIFFERENT authorized human reviews the returned subject/revision.
// A successful proposal is not an active edge and is never runtime-use proof.
```

Do not copy one customer's identity/digest into another tenant, reuse sample IDs,
paste credentials into documents, or treat a local timeout as proof of rollback.
After uncertain mutation results inspect the exact approval before an intentional
retry. Duplicate proposals and stale revisions return 409.

## 5. Persistence, provenance and fail-closed reads

- Reuses existing `AssuranceRevision(kind="bom_relationship")`, with version
  `cryptoscan.host-association/v1`, deterministic scoped-source/target tuple ID,
  optimistic revision checks, linked payload hashes and current human actor IDs.
  No database migration or new inventory is needed.
- Generic relationship approval explicitly refuses this version. Its looser
  reviewer permission/other predicates cannot bypass the host-specific adapter.
- Source commitment includes snapshot/scan/input/ordinal, fact digest, original
  EvidenceRecord/content hash, claimed collection time and explicit null source
  revision where unavailable. No Git revision is invented.
- Reviewed edge includes target type/ID/package identity/digest, proposer and
  reviewer, both evidence references, revision/payload hash and expiry. Ordinary
  scope/containment edges also retain their own provenance and basis.
- Every graph read checks all relevant revision predecessors/hashes and matching
  audit receipts, including actor/scope/payload/source commitments. Removing a
  retraction tail while leaving its audit receipt cannot resurrect the link.
- Broken original host closure, revision/audit corruption or a graph budget
  overrun returns **409**, never a silently truncated healthy graph. A changed,
  unavailable, foreign, inactive, expired or retracted target yields a `STALE`
  assertion with no active edge; stored review history is not rewritten.
- Retraction remains possible when just the target is stale/unavailable. A broken
  original host evidence closure must be repaired/investigated before this
  adapter accepts another source-dependent operation.
- Budgets: 50 distinct associations per approval; 200 checked revision/audit rows;
  100 deployment candidates for an SBOM binding; inherited 100 inputs/1,000 facts;
  complete canonical graph payload at most 4 MiB before its digest field.
  PostgreSQL locks the existing approval row to serialize the association count;
  conflicting review revisions commit at most once.
- Existing host middleware applies 2 MiB request cap, bounded strict JSON,
  no-store responses and host read/write rate buckets. Read-only graph creation
  does not trigger a scan or write new inventory/rollup/policy results.

Graph JSON has version `cryptoscan.host-estate-graph/v1`; it is **not a CycloneDX
standard document**. Associations are intentionally not emitted as CycloneDX
`dependencies`. The existing host CBOM export remains independently validated
against pinned official CycloneDX 1.6 schemas and retains its existing semantics.
Do not claim interoperability/compliance from the graph's custom version marker.

The audit receipt cross-check is not a full global audit-chain walk on each graph
request and not DB-administrator-proof WORM storage. Ordinary API/ORM histories
are append-only; restricted production DB grants, independent retained anchors,
audit review and backups are still required. A privileged attacker able to rewrite
both records and audits is not defeated by self-consistent hashes. Graph evaluation
is a read-time projection, not an atomic snapshot across filesystem and SQL stores.

## 6. Qualification and remaining acceptance

See [execution evidence](../readiness-evidence/host-estate-graph-2026-10-24.md).
The joined witness uses synthetic host files and existing authenticated API/SQL
identities, original retained SBOM artifacts, and a controlled SSH producer with
stubbed acquisition. It is not a real HSM/TLS/KMS/Windows bank estate.

**All these host routes remain blocked in controlled production.** No isolated
host worker/queue/stager is qualified here; no Windows-native execution, deployed
TLS/secrets/monitoring, real HSM/KMS operation, bank acceptance, p95/p99 target or
20% bottleneck improvement is claimed. Estate-wide risk/crypto-agility/drift/timeline
integration remains distinct work. This slice supplies honest associations and
provenance, not permission to infer the remaining observations.
