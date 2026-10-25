# 69. Phase-wise universal collection build

**Engineering rule: a BOM is a projection of evidence, not a source of truth.**

Source of truth is evidence + provenance + scoped identity + evidence-backed relationships. One approved collection/intake feeds all supported projections. Neither AI explanations nor a BOM document may manufacture observations. Unsupported, denied, failed and unrequested scope never become asset absence.

This is the ordered build contract for the requested ten phases. It distinguishes existing code from universal-adapter qualification; it does not reset the repository or create ten parallel scanner/BOM databases. [Phase 1 foundation](62-universal-collection-foundation.md), [Phase 2 Linux](63-linux-collection-phase-two.md), [Windows candidate](64-windows-collection-phase-three.md) and [operator qualification](68-assigned-operator-qualification-workflow.md) remain applicable.

## Execution order and honest status

| Phase | Existing position | Next work / advancement gate |
|---|---|---|
| **1. Foundation** | Development/offline target registry, exact scoped authorization, typed collector/result, existing evidence DB, durable jobs and six shared projections are implemented. **This increment strengthens per-surface coverage and denial/unknown semantics.** | Validate current target/job/evidence bindings, complete input denominators, no collection on reads, tenant isolation, atomic writes, original tamper refusal and stable identity. Development implementation is not production admission. |
| **2. Linux** | Scoped ordinary-user OS/package/binary/config/certificate/process/map/listener/service/hardware metadata exists. Real interface availability and permissions vary. | Complete independently approved truth plans on genuine hosts; preserve each error. Extend only explicitly approved typed resources, never generic shell commands or broad discovery. VBOM requires separate supported vendor evidence/association, not guessed supplier identity. |
| **3. Windows** | Narrow SCM/OS/offline metadata plus [public certificate](72-phase-three-windows-public-certificate-candidate.md), [exact process/module](73-phase-three-windows-process-module-candidate.md), [CNG registration](74-phase-three-windows-cng-registration-candidate.md), [TPM device-info](75-phase-three-windows-tpm-device-info-candidate.md) and [bounded CAPI/extended-CNG/TCP-table](76-bounded-windows-metadata-and-operator-preflight.md) candidates with operator preflight exist; **not universally admitted or production-qualified**. | Genuine ordinary-user Windows/version/architecture/ACL/lifecycle/cancellation runs, independently reviewed original returns and negative cases remain required. Resolve the TPM SDK/documentation layout disagreement. Only the bounded current-user/fixed-provider CAPI/CNG and listener-table metadata profiles exist. Negotiated TLS, stable process↔listener/use relationships and justified firmware/hardware identity remain open; broader surfaces require explicit scope. Linux fixtures cannot satisfy native execution. Do not enable Windows jobs merely because candidate code exists. |
| **4. Containers** | [Metadata candidate](77-offline-oci-image-metadata-candidate.md) plus [verified-content/runtime candidate](78-verified-oci-content-and-runtime-candidate.md): compressed/diff-ID checks, bounded virtual whiteout/link overlay, dpkg/APK records, exact process/cgroup observation, stored validated SBOM and server-owned admission guard. | Production admission **still blocked**: real-image independent truth, verified runtime↔image binding, qualified signed/isolated/cancellable/resource-bounded worker and release acceptance remain missing. Current 1 MiB profile refuses large images; Zstd/RPM/language/binary/full filesystem-attribute support remains open. No sockets, privileged daemon or deployment/use inference. |
| **5. Network** | [Approved single TLS session candidate](79-approved-single-tls-session-candidate.md): one numeric endpoint/port/SNI/version/peer pin, explicit active operation/reviewed target, MemoryBIO byte/time bounds, typed session/certificate facts and stored validated export/UI. [Final TLS 1.3 selected-group evidence](80-tls13-selected-group-evidence.md) now directly observes one selected group without guessing from certificate/cipher. Host listener metadata remains separate. | **Operator-run Linux candidate, not production/network-job admission.** Independent endpoint/rotation/ACL/IPv6/provider truth, qualified isolated/cancellable executor and reviewed admission remain open. No DNS/CIDR/discovery/fallback, application/software/HSM-use or full-SBOM inference; CA/hostname/revocation validation explicitly not performed. Windows/container blockers remain open. |
| **6. Cloud** | Existing provider collectors are separate capabilities, not blanket universal-registry admission. | Provider/account/region/resource read allowlists, reference-only credentials, bounded pagination and explicit denial/throttling receipts. KMS/HSM service metadata is not hardware possession or application use. Qualify each provider separately. |
| **7. HSM / hardware** | Narrow DMI/TPM metadata and enrolled-key quote tooling exist; hardware origin/application use remain separate. | Approved public metadata interfaces, actual firmware/capability evidence, enrollment/custody/quote/replay review and justified edges. Do not create/use private keys, request TPM auth secrets or infer USES_HSM from co-existence. |
| **8. Vendor** | Existing imported/declared supplier evidence and reviewed associations are not an observed universal vendor collector. | Versioned supplier/product/revision records, approved public imports, provenance-preserving SBOM/CBOM input validation and revision handling. A vendor PQC claim remains VENDOR_DECLARED/DECLARED, never OBSERVED. |
| **9. Correlation** | Scoped metadata slots and reviewed evidence-backed relationships already exist. This is not an attested global asset identity graph. | Qualified cross-source identity rules, version history, false-merge negatives, per-edge provenance/status, retraction/drift and no linkage by mere co-existence. Reuse existing graph/DB rather than independent BOM stores. |
| **10. Production hardening** | RBAC/session/audit/isolation/recovery controls and qualification tools exist; full bank/deployment clearance **remains blocked**. | Independent deployed-worker/adversarial exercises, real IdP/MFA/transport/key custody, tenant/residency, rate/resource limits, air-gap handling, backup/restore/DR/monitoring and bank deployment approval. Do not postpone least privilege or audit until this phase; every earlier increment retains those controls. |

**Do not run all phases concurrently or skip qualification/admission prerequisites.** Existing candidate/legacy code is not a completed phase. Per the request to reuse existing work and build the next missing capability, Phase 4 offline candidate engineering is implemented and the next missing Phase 5 negotiated-session candidate is now built, while actual Windows/container/operator qualification remains external and blocked. Candidate engineering is not permission to skip an admission gate. This does not promote Windows or container execution, or remove any earlier gate. Later collectors must return typed, bounded facts and explicit errors through the same pipeline before contributing to stored projections. No service-directory rewrite or speculative new database tables is needed to begin.

## Phase 1 increment delivered here: surface coverage

New read-only route:

```text
GET /api/v1/collection/jobs/{job_id}/coverage/surfaces
```

The existing `/coverage` response is unchanged for compatibility. The new report:

- Opens the **same committed job/intake/original evidence**, verifies the envelope and exact authorized target revision, and projects coverage without collecting, creating a scan, modifying audit history or contacting hosts.
- Uses the immutable approved manifest as denominator, not an estimated host inventory. Every supported input kind maps to exactly one surface: OS, software, certificates, crypto configuration, processes/libraries, services, network observations (listener tables or exact approved TLS sessions in the compatible `network_listeners` slot) or hardware metadata.
- Lists original input status/reason, count of retained facts and evidence references, plus **separate local OBSERVED/DECLARED counts**. Transfer provenance stays IMPORTED. A parsed config file is a declaration, not observed negotiated configuration.
- Returns all six projection reference counts: **SBOM, CBOM, NBOM, HBOM, VBOM, TechBOM**. One fact can contribute to multiple counts; do not add these counts as distinct assets or collections. They are not CycloneDX documents or completeness scores.
- Preserves job/target/revision/hash, system/environment and original claimed collection window. Hashes are integrity commitments, not proof of host identity, hardware origin or executed-code authenticity.
- Refuses inconsistent source/input/fact/domain bindings, duplicate observation IDs/ordinals, facts on failed inputs, missing/foreign errors and changed originals rather than displaying a misleading percentage.

### Surface outcomes and denominator semantics

| Outcome | Meaning |
|---|---|
| `NOT_REQUESTED` | No approved input for this surface; percentage is **null**, not 0%; no inventory conclusion |
| `FAILED` | Approved inputs exist but none parsed; explicit reasons retained; no absence proof |
| `PARTIAL` | Some approved inputs parsed and some failed |
| `PARSED_WITH_FACTS` | All explicitly approved inputs parsed and emitted facts; **not complete surface discovery** |
| `PARSED_NO_FACTS` | Parsed input contract emitted no facts; still **not** proof that assets do not exist |

`approved_input_parse_percent` is `parsed approved inputs / approved inputs × 100`, rounded to two decimals. This is an **input parsing metric only**. It is not software/hardware coverage, confidence, asset inventory accuracy, SLA or bank coverage. Denominators are fixed by scope authorization before collection. No percentage is invented for an unknown/unrequested denominator.

For example, one approved public certificate parses and one is unavailable:

```text
certificates:
  approved_inputs: 2
  parsed_inputs: 1
  failed_inputs: 1
  outcome: PARTIAL
  approved_input_parse_percent: 50
  unavailable input: original status/reason retained
  complete_surface_coverage_verified: false

hardware_metadata:
  approved_inputs: 0
  outcome: NOT_REQUESTED
  approved_input_parse_percent: null
```

This does **not** say “50% of bank certificates discovered” or “no HSM.” `whole_host_percent` stays null; whole-host coverage, asset absence and production qualification stay false.

### Product use

In the existing **CBOM → Approved host collection** area, use **Phase 1 · Evidence-backed collection coverage**, enter a completed universal collection job ID and choose **Inspect collection coverage**. A standalone host approval ID is not a collection job ID. Nothing loads or scans automatically; there is no rescan fallback or automatic retry.

The read is bounded to 20 seconds. Changing job ID, tenant, authentication, relevant storage or returning through visibility/history restoration clears old proof; late responses cannot reappear in a new scope. Read failures do not become empty success. Historic evidence remains inspectable after scope withdrawal, but that never authorizes new collection. Original tampering refuses the report.

The Linux catalog now correctly describes already implemented explicit TCP-listener and kernel/DMI/TPM metadata support. These labels do not imply negotiated TLS, hardware attestation, crypto invocation or newly qualified adapters.

## Phase 2 next, without skipping native gates

Once Phase 1 regression gates remain passing, continue the existing scoped Linux implementation, not a second Linux scanner:

1. Approve real host/resource/truth windows and assign actual operators.
2. Capture original OS/package/library/config/certificate/service/listener/hardware receipts with ordinary-user permissions.
3. Keep denied/missing/native-unavailable cases; never broaden permissions to obtain PASS.
4. Reuse one intake/envelope and supported SBOM/CBOM/NBOM/HBOM/TechBOM projections; add VBOM references only from justified vendor evidence/associations.
5. Obtain independent review through the existing assigned-human workflow before making any deployment claims.

No real operator identity, bank host, channel approval or external signed decision has been supplied in this session. Execution/qualification on those environments remains pending. Do not send credentials, private keys or TPM authorization secrets.

See [the implementation/validation record](../readiness-evidence/phasewise-foundation-2026-10-25.md) for source paths, exact tests and remaining boundaries.
