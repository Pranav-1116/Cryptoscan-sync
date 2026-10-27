# Offline OCI metadata candidate API

See [Guide 77](../bank-environment/77-offline-oci-image-metadata-candidate.md) for the exact resource/fact/budget contract and [operator packet](../runbooks/offline-oci-metadata-candidate.md) for acquisition. This adds no scan-start route, table, service, registry pull or layer/package/runtime claim.

## Candidate catalog, not admission

`GET /api/v1/collection/collectors` describes `offline-oci-metadata/candidate-v1`, `OFFLINE_CANDIDATE_NOT_ADMITTED`, with false server-execution/production qualification. A `container` target may be declared in the development registry, but universal authorization remains **409**. `offline_host` authorization containing `OCI_IMAGE_METADATA` also refuses. Production adapter boundaries are unchanged. Registry declaration, offline candidate inspection and qualified execution are distinct states.

For reviewed offline experiments use existing authorized host manifest approval, snapshot intake and tenant-scoped inspection. `OCI_IMAGE_METADATA` facts are strictly discriminated, validate their approved URI/platform/manifest and reconstruct their selected-metadata receipt hash. Transport remains `IMPORTED`; local metadata byte observation does not independently authenticate the collector or publisher.

## New stored-evidence export

```http
GET /api/v1/host-evidence/approvals/{approval_id}/oci-image/cyclonedx-1.6
```

Uses the same read permission, active tenant resolution and original-evidence checks as existing host exports. Foreign-tenant and unselected-administrator access do not bypass custody. The approval must have retained intake with at least one consistent parsed OCI input and corresponding stored evidence IDs. It does not read operator files, collect, create scans, import more evidence or turn failures into an empty successful image inventory.

### Success

- 200 `application/vnd.cyclonedx+json`, attachment `oci-image-{approval_id}-cyclonedx-1.6.json`; `Cache-Control: no-store`.
- CycloneDX `specVersion: 1.6`, deterministic snapshot/approval-derived UUID and ordered components/properties.
- `cryptoscan:profile`: `OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM`.
- `cryptoscan:snapshot_sha256` and `cryptoscan:approval_id`: exact inspected originals.
- Container-type component for each unique exact manifest/platform identity, explicitly named image manifest; no layer/rootfs component hashes claiming whole-image verification.
- Specifically named manifest/config commitments, declared platform/layers/ports/base digest, original evidence IDs, input IDs, selected/layout/index hashes and explicit layer/package/deployment false/UNKNOWN qualifiers.
- Incomplete composition; failed image inputs retained as status/reason gaps in properties. No software package/dependency/supplier/runtime/TLS/HSM/crypto component inference.

The response is validated against the existing **official pinned offline CycloneDX 1.6 schemas before return**. Validation means document conformance, not image discovery, authenticity or completeness. A successful export appends `host.oci-sbom.export` with snapshot/document commitments; it does not append scan/evidence records.

### Refusal

| Status | Meaning |
|---|---|
| Existing 401/403/404 | Authentication, role or tenant visibility boundary |
| 409 | No intake, inconsistent/tampered custody, no parsed OCI metadata/evidence references, or contradictory same-manifest metadata |
| 503 | Official document validation unavailable/failed; no document and no success-export audit |

No failure triggers collection or fallback to legacy image scanning. General CBOM export stays unchanged and separate; zero crypto components is not proof of crypto absence.

## Frontend contract

Existing HostEvidencePanel structurally validates OCI facts rather than trusting arbitrary JSON. Only an explicit download action exports. It requires profile and snapshot SHA matching the currently inspected original and uses existing tenant/auth/context generation fences. Ports are labelled **declared**, layers/packages/runtime unverified. Changing context invalidates stale proof/download completion; no new dashboard or automatic probe is added.
