# 77. Phase 4 — offline OCI image metadata candidate

## Move to the next missing implementation

Foundation, bounded Linux and Windows candidates already exist. This increment starts the **next unadapted implementation area**, containers, without rebuilding those collectors or declaring their qualification complete. Windows operators still need to return real independently reviewed evidence. Neither later candidate code nor this guide opens production admission.

Existing container utilities already inspect/extract images and scan packages. Their legacy output is not automatically a universal typed evidence result. This increment reuses the existing shared contracts, no-follow reader, JSON bounds, custody, official schema validator and UI, and gives the existing container metadata parser an explicit-selector option using the common selector. It does **not** reimplement the container scanner or invoke its registry/daemon/extraction paths.

## Exact approved resource

```text
kind: OCI_IMAGE_METADATA
path: oci-layout://local/linux/{amd64|arm64|arm64/v8}/manifest/sha256/<64-lowercase-hex>/root/<absolute-root-without-leading-slash>
```

Example shape, not an executable approval:

```text
oci-layout://local/linux/amd64/manifest/sha256/<reviewed-manifest-digest>/root/home/operator/reviewed-oci-layout
```

`root/home/...` denotes `/home/...`, not a relative path. No URL encoding, queries, fragments, dot/dot-dot/empty components, backslashes, remote layout, registry reference, first-manifest fallback or implicit platform selection. The exact source URI and approved time are committed through the existing target/manifest authorization process. An image's declared platform is not the collection host's CPU identity.

The candidate accepts only an unpacked local OCI layout and direct Linux OCI image manifest/config. Docker-save archives, nested indexes, attestation/artifact manifests and remote/embedded descriptor data are not this profile. Do not unpack an untrusted image using this collector; extraction remains separate reviewed work.

## What is read, and what is not

Only these four explicit regular files are read, twice:

1. `oci-layout`, with supported `imageLayoutVersion: 1.0.0`.
2. `index.json`, bounded to 64 descriptors, selecting **exactly one** matching approved SHA-256 manifest descriptor and explicit platform.
3. `blobs/sha256/<approved-manifest-digest>`, checking descriptor size and actual byte digest.
4. `blobs/sha256/<config-descriptor-digest>`, checking descriptor size, actual byte digest and declared platform/rootfs consistency.

Existing descriptor-relative no-follow Linux reads refuse symlinks, hardlinks, special files and changed regular files. Explicit selected descriptors reject external URLs/embedded data; only SHA-256 and supported OCI image/layer media types are accepted. Duplicate JSON keys, non-finite numbers and excessive nesting refuse through the existing bounded JSON parser. Duplicate selected descriptors refuse; selection never defaults to the first image.

**No layer blobs are read.** Their ordered digest/size/media-type declarations and config `diff_ids` are retained only as declarations, with equal bounded counts (≤128). This can inspect an ordinary image's small metadata even when its layers are large or unavailable. Missing layers do not become verified content or filesystem/package facts.

No pull, Docker/containerd socket, credentials, registry API, shell, archive extraction, decompression, whiteout application, container execution, package tool, vulnerability feed or active network probe is invoked. Environment, command, entrypoint, arbitrary labels and raw metadata bytes are not emitted. Only bounded canonical exposed-port declarations (≤64) and an optional exact declared base-image digest are retained from the selected configuration/manifest annotations. No supplier identity is guessed.

### Budget and stability

All eight raw metadata-file reads plus selected canonical JSON consume the existing per-input and total charged-byte limits. The default per-input maximum is 1 MiB; it is **not** 1 MiB independently for every file/sample. Exhaustion refuses the whole positive receipt rather than truncating facts. Existing ordinary-user/platform/expiry/fact limits remain. These are byte/read bounds, not a wall-clock/RSS guarantee.

Two complete samples must agree, including original layout/index hashes and selected bytes. Changed samples refuse. Equal samples do not establish an atomic directory snapshot, trusted publisher, host identity or continuous monitoring. SHA-256 equality gives integrity/content addressing, not authenticity.

## Typed evidence and provenance

One parsed input emits one separate strict `OciImageFact`:

- `kind: OCI_IMAGE_METADATA`, `purpose: PINNED_OCI_MANIFEST_CONFIG_METADATA`.
- `interface: OFFLINE_OCI_LAYOUT_METADATA`; local OBSERVED means those metadata bytes were read and checked.
- `configuration_basis: DECLARED`; platform, ports, base digest and layer/diff-ID declarations do not become runtime observations.
- Actual layout/index/manifest/config SHA-256 references, manifest/config byte sizes, explicit Linux architecture/variant and ordered layer descriptors.
- Content-addressed metadata identity: `oci-manifest:sha256:<manifest>:linux:<architecture>:<variant-or-unspecified>`. This identifies a manifest/platform description, not a running deployment or mutable package lineage.
- `interface_sha256` reconstructs canonical selected metadata, matches receipt `content_sha256` and is validated against the exact approved manifest/platform scope.
- Algorithm/runtime/operation/PQC UNKNOWN; capabilities false; policy NOT_EVALUATED; software name/version/key size null.
- `layer_contents_verified`, `filesystem_materialized`, `package_inventory_verified`, `deployment_verified`, `vendor_identity_verified`: **false**.

Unknown fields, forged identities/source commitments, unsupported platforms, promoted use/vendor/package/layer claims and noncanonical ports refuse. Missing/denied/malformed/changed/over-budget input produces a retained gap, not NO_IMAGE/NO_PACKAGES/NO_CRYPTO.

## Existing custody and six BOMs

Use existing host approval → offline candidate snapshot → original intake → authorized inspection. This is a temporary **offline candidate custody profile**, not a new universally admitted execution mode. Target registry `container` and an `offline_host` attempt containing this input both remain 409/future capability. The Linux runtime adapter also rejects this input, preventing an accidental candidate bypass. No server HTTP handler inspects paths or starts collection.

| BOM | Contribution |
|---|---|
| SBOM | Image manifest/config artifact metadata only; not installed packages/libraries/dependencies |
| CBOM | No crypto component inferred from image/package labels, ports or layer digests |
| NBOM | No live listener/TLS endpoint; ExposedPorts remains DECLARED configuration |
| HBOM | No physical host, hardware possession, TPM or HSM use |
| VBOM | No authenticated vendor; base digest remains a declaration |
| TechBOM | Same scoped artifact metadata references, not verified deployment topology |

The existing software coverage bucket recognizes the new kind, but any reference count measures metadata observations/approved inputs, not package or whole-image coverage. Six BOM namespaces remain required; unsupported facts are not manufactured.

## Schema-validated artifact-only SBOM

New stored-evidence projection:

```http
GET /api/v1/host-evidence/approvals/{approval-id}/oci-image/cyclonedx-1.6
```

The route uses existing tenant/RBAC/original integrity checks, creates no scan/evidence and never rereads OCI files. It materializes only parsed approved OCI metadata, with original receipt/evidence references. Identical manifest/platform descriptions are grouped only when their non-location metadata agrees; contradictory descriptions refuse.

- Standard CycloneDX 1.6 `container` components explicitly named **OCI image manifest SHA-256**, not a claimed running application.
- Profile property `OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM`, exact approval/snapshot commitments, declared platform/layers/ports/base digest, unknown/false limits and failed-image input receipts.
- No invented package components, software versions/licenses/purls/suppliers, dependencies or full-image/rootfs component hashes. Manifest/config hashes stay specifically named provenance properties.
- Composition explicitly `incomplete`; no all-six-BOM completeness claim.
- Official offline pinned CycloneDX 1.6/reference validation **before return**. Validation failure is 503 with no document/export audit; no consistent parsed OCI evidence is 409, not an empty successful inventory.
- Successful export writes the existing audit ledger, sends `no-store`, and does not create new scan/evidence records.

The existing panel displays manifest/platform, declared ports and explicit unverified layers/packages/runtime. Its new explicit download button uses the existing private-context generation guard and requires the OCI profile/snapshot commitment to match current inspection. It does not automatically fetch/export or create a new dashboard. Ordinary host CBOM remains separate; zero crypto components is not NO_CRYPTO.

## Operator-owned candidate run

Prepare a reviewed `TargetSpec` using `collection_method: container`, no credential reference, Linux manifest, only approved `OCI_IMAGE_METADATA` inputs, matching environment, allowed read operation and approved time. `address` is a descriptive registry field, not a remote pull instruction. Obtain the independently reviewed **canonical target model** digest before measurement; it is not an approval signature.

```bash
python scripts/collect_oci_metadata.py \
  --target reviewed-oci-target.json \
  --approved-target-sha256 "$REVIEWED_CANONICAL_TARGET_SHA256" \
  --output new-oci-metadata-snapshot.json
```

Output is exclusively created; no overwrite/retry-to-success. Exit 0 means all requested metadata inputs parsed, 2 retains gaps, 64 refuses scope/output/platform/identifier handling. It is a candidate `HostSnapshot`, not independent native qualification or production clearance. Return original bytes through the existing approved intake/channel; do not send credentials/private keys. No customer image/host/registry or real operator packet was supplied or contacted during this increment.

## Remaining Phase 4 work

This starts Phase 4 engineering, **not completion**. Next implement exact layer compressed/uncompressed content verification, bounded archive/decompression/whiteout/link-safe final-rootfs handling and evidence-backed package/library/config extraction using existing container utilities and Linux parsers. Keep image content distinct from running workload state. Independent real-image/operator truth, signed release/worker provenance, isolation/cancellation/resource qualification and separate admission remain open.

Windows qualification and its TPM discrepancy remain open independently. Network/cloud/HSM/vendor/correlation/hardening phases are not newly completed by this metadata adapter. No HA/DR/SLA/performance improvement or bank acceptance follows.

## References and validation

- [OCI Image Spec v1.1.0, pinned commit](https://github.com/opencontainers/image-spec/tree/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2).
- [Image layout](https://github.com/opencontainers/image-spec/blob/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2/image-layout.md), [manifest](https://github.com/opencontainers/image-spec/blob/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2/manifest.md), [config](https://github.com/opencontainers/image-spec/blob/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2/config.md), [descriptors](https://github.com/opencontainers/image-spec/blob/e7f7c0ca69b21688c3cea7c87a04e4503e6099e2/descriptor.md).
- [Retained local validation](../readiness-evidence/oci-metadata-candidate-2026-10-25.md).

## Follow-on engineering

[Guide 78](78-verified-oci-content-and-runtime-candidate.md) adds a separately approved/opted-in bounded content/runtime candidate. The original metadata-only resource/wrapper/export described above retain their exact scope; they do not silently read layers. Production admission and independently verified runtime-image binding remain open.
