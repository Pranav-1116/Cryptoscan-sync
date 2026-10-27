# Container content/runtime candidate — stored evidence API

[Guide 78](../bank-environment/78-verified-oci-content-and-runtime-candidate.md) defines exact resource scope, bounded tar/gzip/link/overlay behavior and limitations. This adds no production execution route, registry/socket access, new service or storage table.

## Acquisition and admission

`OCI_IMAGE_CONTENT` and `OCI_RUNTIME_PROCESS` are new strict host-input/fact kinds. The existing candidate CLI requires `--include-verified-content-runtime`, reviewed target SHA-256, `container` method, no credentials, Linux environment/window and exact approved resources. Without the flag the old metadata-only wrapper rejects these kinds. Linux offline wrapper/API authorization reject all three container kinds. Universal `container` authorization invokes the server-owned empty admitted-profile policy and remains **409**; existing global production boundaries remain.

The collector catalog adds `offline-container-content/candidate-v1` as `OFFLINE_CANDIDATE_NOT_ADMITTED` with false server-execution/production flags. Registration does not authorize collection. Existing host approval/intake stores imported operator-returned snapshot bytes, not authenticated image publisher or production worker observations.

## Export

```http
GET /api/v1/host-evidence/approvals/{approval_id}/container/cyclonedx-1.6
```

Same tenant/RBAC/original-integrity resolution as existing exports. It never rereads the layout, inflates a layer, inspects `/proc`, invokes a collector or creates scan/evidence records.

200 sends `application/vnd.cyclonedx+json`, attachment `container-{approval_id}-cyclonedx-1.6.json`, `Cache-Control: no-store`. The server runs the existing official pinned offline CycloneDX 1.6 validator before returning or auditing a success.

- Profile `cryptoscan:profile = VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES`.
- Exact approval/snapshot SHA, IMPORTED transport, incomplete composition and false completeness/production clearance.
- Image component properties bind manifest/config SHA, declared platform, verified ordered compressed/diff-ID layer descriptors, virtual-file-view commitment, explicit database denominator and original evidence IDs/input IDs/selected receipt hashes.
- Package components contain only supported observed database name/version and manager/logical source path/source-file SHA/writer-layer provenance. Null version is omitted from standard version. `library` classifies packaged software, **not module loading or crypto use**. Image association is explicitly an artifact-reference property, not a verified runtime dependency.
- Runtime properties retain process identity/cgroup SHA/runtime/container ID and operator-declared image digest, with `runtime_image_verified: false`. No verified image↔process edge is invented.
- No supplier/licenses/purls/dependency graphs or full-rootfs component hashes; scopes outside dpkg/APK database records remain unsupported. Matching content identity observations deduplicate only if non-location semantics agree; contradictions refuse.
- Failed approved content/runtime inputs remain status/reason properties rather than disappearing into successful empty inventory.

Successful export appends `host.container-sbom.export`, with approval/snapshot/document commitments and profile. No new scan/evidence rows. Old metadata-only OCI and host CBOM export routes are unchanged.

| Status | Meaning |
|---|---|
| Existing 401/403/404 | Authentication/role/tenant visibility or no retained intake |
| 409 | No consistent parsed verified-content observation/evidence reference, conflicting descriptions or changed originals |
| 503 | Official schema validation failed/unavailable; no document or successful export audit |

## Admission readiness, not an authorization token

```http
GET /api/v1/host-evidence/approvals/{approval_id}/container/admission-readiness
```

Tenant/original checks are identical, 200 no-store for an intact stored snapshot even when its inputs failed. No scans/evidence/audit success-execution records are created. The deterministic report binds the current snapshot and contains:

```text
schema_version: cryptoscan.container-admission-readiness/v1
profile: offline-container-content/candidate-v1
source_basis: IMPORTED
verdict: BLOCKED_NOT_PRODUCTION_ADMITTED
approved_inputs: explicit container-kind denominator
failed_inputs: retained input_id/status/reason gaps
verified_content_observations: parsed content observations, not whole-image coverage
package_database_records: nested supported database-record total
runtime_process_observations: exact process/cgroup observations
runtime_image_binding_verified: false
production_execution_qualified: false
server_execution: false
windows_execution_qualified: false
materialized_without_collection: true
blockers: data gaps plus external binding/acceptance/release/worker/admission gates
```

Counts are descriptions of strict **imported evidence**, not independently authenticated collector output. A matching declared runtime image digest is insufficient to verify a deployment. No API field, environment override, missing response, all-positive fixture or returned report opens admission. A real qualified executor/release and independent acceptance remain missing; this endpoint cannot grant them.

## Frontend

Existing HostEvidencePanel validates strict content/runtime structures, nested metadata, package/database SHA/layer references, unique record ordering and false promoted-use/vendor/deployment/completeness fields before display. It shows verified layer/virtual-view scope, supported package-record count, exact cgroup observation and explicit blocked production admission. Downloads require the content profile and current inspected snapshot SHA and retain existing private-context fencing. No automatic download/probe/worker dispatch or new dashboard.
