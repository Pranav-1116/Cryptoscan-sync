# 78. Phase 4 — verified layer bytes, scoped packages and runtime evidence

## Delivered, with an explicit production boundary

This extends [metadata-only candidate 77](77-offline-oci-image-metadata-candidate.md) rather than replacing existing scanners/custody. New engineering paths verify layer content and project package database records, capture exact passive runtime process/cgroup evidence and enforce a server-owned admission guard. **Production execution is not admitted.** Independent runtime-to-image binding, real-image truth, release/worker provenance and production qualification are not available in this session. Actual Windows qualification, including the TPM documentation discrepancy, remains open.

| Requested capability | Implemented boundary |
|---|---|
| Verified layers | Every selected compressed blob size/SHA-256 and uncompressed diff-ID verified against approved manifest/config; uncompressed tar and gzip supported. Zstd refuses this content profile. |
| Package inventory | Existing dpkg/APK parsers over the verified final virtual file view; each retained record binds its database SHA-256 and writer layer. RPM/language/binary/executable verification and complete package inventory remain unsupported. |
| Runtime-container evidence | Exact approved PID+start ticks+boot ID and Docker/containerd cgroup ID, repeated passive kernel metadata. **Image association remains operator DECLARED**, not verified running-image/deployment identity. |
| Production admission | Empty server-owned admitted-profile set, explicit universal authorization refusal, immutable false snapshot clearance and stored-evidence blocker assessment. No production executor or clearance fabricated; no checkbox/env/import can enable it. |

## Explicit resource scopes and opt-in

Existing `OCI_IMAGE_METADATA` / `oci-layout://...` behavior remains unchanged. New kinds:

```text
OCI_IMAGE_CONTENT
oci-content://local/linux/{amd64|arm64|arm64/v8}/manifest/sha256/<approved-64-hex>/root/<absolute-root-without-leading-slash>

OCI_RUNTIME_PROCESS
container-proc://linux/{docker|containerd}/<approved-64-hex-container-id>/pid/<exact-pid>/start/<exact-start-ticks>/boot/<exact-boot-uuid>/manifest/sha256/<declared-64-hex-image-manifest>
```

No `self`, wildcard PID/container ID, process discovery, URL encoding, query, remote source or implicit image/platform selection. Runtime scope deliberately names its image association as **declared**; merely putting a digest in this URI cannot verify it. PID, start and boot must agree with the observed process. Linux image CPU is a declaration, not the collector host CPU.

Use existing reviewed `TargetSpec`, `collection_method: container`, Linux manifest, no credential reference, matching environment/window, only approved container kinds and no excluded approved input. `READ_APPROVED_METADATA` remains the existing operation vocabulary; the explicit **content URI/kind plus opt-in flag** authorize verification reads of the complete selected layer blobs, not just four metadata files. Do not reuse a metadata-only approval for those reads.

```bash
python scripts/collect_oci_metadata.py \
  --target reviewed-container-target.json \
  --approved-target-sha256 "$REVIEWED_CANONICAL_TARGET_SHA256" \
  --include-verified-content-runtime \
  --output new-container-snapshot.json
```

Without the new flag the old metadata wrapper rejects these kinds before acquisition. Canonical target hashing, exclusive mode-0600 output and exit statuses (0 parsed, 2 retained gaps, 64 whole-scope/output refusal) follow [the existing operator packet](../runbooks/offline-oci-metadata-candidate.md). No private key, registry credentials, daemon/socket, image execution or package command is needed. Ordinary-user/platform/expiry checks remain in the existing collector.

## Layer verification and safe virtual overlay

1. Reuse the existing bounded double-sampled OCI layout/index/manifest/config reader and shared exact selector. No first-manifest fallback, remote/embedded descriptors or hash/size/platform disagreement.
2. Read only the layer blobs named in that approved verified manifest, with the existing no-follow, single-link regular-file reader. Verify their descriptor sizes and SHA-256 before parsing.
3. For gzip, bound the full decompressed stream and validate CRC/truncation through the standard decoder. Verify SHA-256 of the **entire uncompressed tar bytes**, including padding, against the config diff-ID. For plain tar the already charged bytes supply the diff-ID directly.
4. Parse only bounded tar entries, without extracting any file to the host. Normalize supported `./`/directory framing; refuse traversal, absolute member names, controls/backslashes, duplicates, sparse/device/FIFO/special entries and nonzero/truncated/concatenated archive trailers.
5. Apply OCI lower-to-upper virtual file overlays. Empty regular-file whiteouts and opaque-directory markers remove lower entries **before** current-layer additions regardless of archive order. Removed databases cannot contribute records. The legacy filesystem merger now also orders whiteouts before additions and shares the whiteout names; the new trusted reader never imports the legacy scanner/its external dependencies.
6. File hashes/data stay in the bounded in-memory view. Image-internal symlinks are resolved only in that view (≤32 hops); escaping/root-target/cyclic/dangling database links refuse. Writes/whiteouts through non-directory/link ancestors refuse rather than following host paths or guessing extraction semantics. Hardlinks are frozen copies of earlier same-layer regular entries; forward, lower-layer and non-file targets refuse this narrow profile.
7. The rootfs-view SHA-256 commits sorted path/type/file-digest/size/link-target/writer-layer metadata. It is a **virtual file-content/provenance view**, not a materialized Linux filesystem, executable verification, permissions/ownership/xattr equivalence, trusted publisher signature or running rootfs hash.

All raw reads, gzip-expanded bytes and selected output consume the **existing combined per-input limit (maximum/default 1 MiB)** and total limit (16 MiB). No global limits were increased. Plain tar bytes are not charged twice for identical compressed/uncompressed representation. Gzip's one-byte overflow sentinel is not recorded beyond the approved budget; exhaustion preserves a bounded failure receipt. A maximum of 2,048 tar members across the image and 500 package records applies. Large real images will intentionally refuse this candidate profile; small synthetic success does not qualify a production bulk-image worker, wall-clock cancellation, RSS or throughput.

## Package records are scoped evidence

Only the final resolved `var/lib/dpkg/status` and `lib/apk/db/installed` files are parsed using existing `inventory.linux_packages` functions. No shell/package tools, scripts, dependency resolution, language directory scans, CVE network feeds or supplier guesses.

`OciContentFact` contains:

- The unchanged `OciImageFact` describing verified manifest/config metadata; its nested layer-content flag remains false because that nested metadata receipt alone did not verify layers.
- Parent `layer_contents_verified: true`, `final_filesystem_view_verified: true`, `filesystem_materialized: false`.
- Rootfs virtual-view commitment; both database denominator entries (`PARSED` with SHA-256/layer or `NOT_PRESENT_IN_VERIFIED_VIEW`). A dangling/invalid/malformed database is a gap, not missing software.
- Canonical package records: manager/name/version (null if unsupported/missing), logical database path, exact source-file SHA-256, source writer layer and `VERIFIED_IMAGE_PACKAGE_DATABASE_RECORD_NOT_EXECUTABLE_OR_USE`.
- `package_inventory_verified`, `complete_inventory_verified`, deployment/vendor verification **false**. A verified database record does not prove executable contents, all packaging surfaces, publisher/vendor origin, dependency edges or runtime invocation.

Any bad requested layer/database refuses that whole input; no partial positive image fact. Missing databases are an explicit scoped denominator, not NO_PACKAGES. Empty/malformed/ambiguous databases follow the existing parsers' refusal behavior. Successful image facts contribute SBOM/TechBOM only; the existing software coverage count counts observations, **not the nested package total or whole-image completeness**.

## Exact runtime-container observation

Reuse `linux_runtime.Reader`, `process`, `process_start` and boot-ID handling. Only `/proc/<approved-pid>/{stat,comm,cgroup}` and the fixed kernel boot-ID path are read. Two existing stable process samples plus additional cgroup/incarnation/boot checks must agree. Zombies/exited/reused or mismatched incarnations refuse. Docker cgroupfs/systemd paths and containerd systemd scopes must identify exactly the approved container ID without contradictory observed IDs.

No Docker/containerd API/socket, namespace entry, `/proc/*/root`, environment/arguments/memory inspection, active packets or privileged discovery. Denied/missing/changed/unknown cgroup layout remains a gap, not container absence.

`OciRuntimeFact` preserves process identity, original kernel-source and cgroup hashes, runtime/container ID, selected receipt hash and the declared image digest. `process_observed: true` means this bounded process/cgroup interface observation. `runtime_image_verified`, deployment/vendor verification **false**; runtime/crypto operation/PQC UNKNOWN. Kernel-reported cgroup naming is not authenticated engine/publisher authority. Equal samples are not atomic or continuous liveness. Runtime contributes TechBOM only, no image↔process **verified-use** edge or NBOM/TLS/HSM fact.

## Existing custody, export and UI

Existing host manifest approval → offline candidate → original intake → tenant/RBAC/integrity-checked inspection remains the custody path. Snapshots remain IMPORTED; hashes detect byte changes, not collector/publisher authenticity. No new service/table/dashboard or HTTP execution endpoint.

New stored-only routes:

```http
GET /api/v1/host-evidence/approvals/{id}/container/cyclonedx-1.6
GET /api/v1/host-evidence/approvals/{id}/container/admission-readiness
```

The first returns officially validated CycloneDX 1.6, profile `VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES`, image components plus packaged-software record components, source database/layer/original receipt evidence references and explicit incomplete/UNKNOWN/false limits. `library` is a packaged-software classification, **not loaded-library evidence**. Runtime evidence is a separate qualified property, never a verified dependency/deployment edge. No fabricated supplier/licenses/purls, full-rootfs component hashes or dependencies. Duplicate identity descriptions must agree. All-failed/no-content inputs give 409; official schema refusal gives 503 without a successful export audit. Successful export is no-store, audited and creates no scans/evidence. The old metadata-only SBOM endpoint is unchanged.

The existing panel strictly guards both new fact structures and nested provenance before display. The explicit verified-layer/package-record download requires the correct profile and current inspected snapshot SHA, using existing private-context generation fencing. It labels cgroup membership/image declaration and blocked admission, not verified image use. API/report details: [container content contract](../api-reference/container-content-candidate.md).

## Production admission remains a real gate

`container_admission.require_container_profile` is wired into universal container authorization. The admitted container profile set is empty; no environment variable/imported fact/review checkbox changes it. Offline-Linux rejects **all** container kinds, including runtime, before collection; its API authorization also refuses them. Existing global production boundaries are unchanged. The metadata-only collector cannot silently opt into content/runtime.

The read-only readiness report derives approved/failed inputs, verified content observations, package-record total and runtime observations from stored originals. It always reports BLOCKED and concrete outstanding gates:

- Missing/failed approved inputs and missing content/runtime observations where applicable.
- Declared runtime image lacking matching verified content where applicable; matching hashes still do not authenticate a deployment link.
- Independently verified runtime↔image binding and independently agreed real-image truth/acceptance.
- Signed release and measured worker provenance, container isolation/cancellation/resource/recovery qualification.
- A qualified explicitly admitted container executor/release.

Existing signed human qualification workflows remain available but do not certify these new surfaces merely because earlier checks passed. No such independent container qualification or actual Windows execution was performed here. **The production-admission requirement is still open; this increment implements its refusal/assessment controls, not a qualified production execution path.**

## Validation and references

[Local validation and retained artifacts](../readiness-evidence/container-content-candidate-2026-10-25.md) distinguish synthetic contract tests from operator truth. No credentials/private keys or customer deployment were requested/changed.

- [Pinned OCI image specification v1.1.0](https://github.com/opencontainers/image-spec/tree/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2), especially [layer changesets, whiteouts and diff-IDs](https://github.com/opencontainers/image-spec/blob/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2/layer.md).
- Existing `inventory.linux_packages`, `inventory.linux_runtime`, `inventory.host`, image layer merger and pinned official offline CycloneDX validator are the reused implementation contracts, not new independent BOM scanners.
