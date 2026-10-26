# 68. Phase 4 — bounded offline OCI image evidence

## What was already present, and what this increment builds

The current workspace already contains the foundation in [62](62-universal-collection-foundation.md), the Linux path in [63](63-linux-collection-phase-two.md), the Windows candidate in [64](64-windows-collection-phase-three.md), and the worker/native qualification boundaries in [65](65-signed-collector-isolation-and-native-gates.md)–[67](67-native-quotes-and-independent-qualification.md). Rebuilding these would duplicate the product. Their presence does **not** close real Windows, hardware, independent-review or production qualification.

The next implementation gap addressed here is **Phase 4: an evidence-first offline OCI image reader**. The older container scanner remains available; this increment does not replace it or reinterpret its findings as this new evidence contract.

| Phase | Existing implementation / decision |
|---|---|
| 1 — foundation | Typed target, scope, evidence, durable revision store and collection job path already present; keep existing admission closed where unqualified |
| 2 — Linux | Explicit ordinary-user metadata collection already present; no broad privileged discovery |
| 3 — Windows | Native candidate code and qualification tools present; real Windows qualification still required |
| 4 — container/image | **Built here:** typed OCI target/evidence, bounded layer reader, offline CLI and pure six-view materializer |
| 5 — network | Existing network/TLS and controlled endpoint paths remain; no scan is triggered by a BOM read |
| 6 — cloud | Existing AWS/Azure/GCP scanner implementations are not automatically universal-collector admission or physical hardware proof |
| 7 — HSM/hardware | Existing metadata and quote verification boundaries remain; presence/signature validity is not application use or hardware enrollment |
| 8 — supplier | Existing import/assurance paths retain their provenance; an image label is not a verified supplier relationship |
| 9 — correlation | Existing graph/association paths remain; this candidate does not directly insert graph edges |
| 10 — hardening | Existing controls are not a blanket bank deployment certificate; independent environment acceptance remains necessary |

This is **offline candidate implementation**, not completion of every phase. No existing source, workflow, deployment, dependency manifest or API admission list was edited for this increment. The user-approved working-tree baseline contains substantial other pending work; these new files are intentionally isolated from it.

## Pipeline and implementation

```text
Explicit operator-approved OciTarget + independently agreed canonical digest
    -> ordinary-user scope/window/platform validation
    -> exact local OCI manifest/config/layer blobs
    -> descriptor SHA256 + size and uncompressed diff_id verification
    -> bounded in-memory overlay; no extraction or image execution
    -> typed per-input metadata receipts and source commitments
    -> retained OciEvidence
    -> deterministic central materialize_oci(evidence, agreed digest)
    -> SBOM / CBOM / NBOM / HBOM / VBOM / TechBOM internal views
```

- [Typed target and evidence](../../shared/shared_models/shared_models/oci_collection.py)
- [Collector and candidate runtime adapter](../../services/inventory/inventory/oci_evidence.py)
- [Pure materializer](../../shared/shared_models/shared_models/oci_projection.py)
- [CLI](../../scripts/collect_oci_evidence.py)
- [Operator runbook](../runbooks/offline-oci-image-evidence.md)
- [Contract/API boundary](../api-reference/offline-oci-image-evidence.md)
- [Retained engineering validation](../readiness-evidence/offline-oci-image-2026-10-25.md)

Collectors produce `OciEvidence`, **not BOMs**. Materialization is a separate pure function over an already-retained object: it cannot open a blob, pull an image, start a job or negotiate a network connection. An observation used in two views has the same `evidence_id` and source commitments. No separate SBOM/CBOM database is added.

The candidate has typed `validate_scope`, `collect` and `health` methods. Its `OciTarget -> OciEvidence` interface is deliberately **not falsely registered as the existing `TargetSpec -> HostSnapshot` host adapter**. The existing HTTP registry/job worker does not yet admit this OCI contract. The image target's authorization reference and approved digest are operator-supplied commitments, not server authorization tokens, signatures or proof of organizational authority.

## Scope and supported sources

Only a local OCI image-layout directory with `oci-layout` version `1.0.0` and an explicitly pinned SHA256 OCI image manifest is supported. `index.json` is not enumerated or parsed: the exact manifest digest is the approved root. No repository/tag resolution, registry pull, Docker socket, container daemon, shell, mount, chroot or credentials are used.

Supported candidates are **Linux amd64/arm64 image metadata**, processed by an ordinary Linux user. This is not native ARM execution or Windows/container execution qualification. Docker schema-2 manifests, multi-platform index selection, foreign/URL/data descriptors, zstd, artifact manifests and Windows layers refuse.

Approved metadata paths:

| Kind | Scope | Meaning |
|---|---|---|
| `DPKG_STATUS` | `var/lib/dpkg/status` | Installed-status records; ambiguous duplicate fields/names and missing versions refuse |
| `APK_INSTALLED` | `lib/apk/db/installed` | Literal Alpine package/version records |
| `RPM_SQLITE` | `var/lib/rpm/rpmdb.sqlite` or `usr/lib/sysimage/rpm/rpmdb.sqlite` | Existing bounded, checkpointed SQLite RPM profile; not Berkeley DB/ndb/WAL or package signature verification |
| `LINUX_OS_RELEASE` | `etc/os-release` or `usr/lib/os-release` | Declared literal ID/version; never shell-sourced |
| `PUBLIC_CERTIFICATE` | Exact approved relative file | Public certificate metadata; private keys, bundles and trailing DER refuse |
| `NGINX_TLS_CONFIG` | Exact approved relative file | Bounded literal TLS declarations; not effective negotiated TLS |
| `BINARY_METADATA` | Exact approved relative file | ELF/PE magic metadata only; not executable validation, library version, capability or runtime use |

There is no recursive source/dependency discovery, language-package lockfile support, image signature verification or complete software assertion in this increment. Large real libraries can exceed the selected 1 MiB input limit and must produce a gap, not fabricated evidence. Crypto library names stay in SBOM metadata; `libcrypto` does not manufacture RSA/AES usage in CBOM.

## Layer correctness and least privilege

The reader verifies compressed layer SHA256/size **and** the corresponding uncompressed SHA256 `rootfs.diff_ids` entry. It supports uncompressed tar and gzip only. All tar processing is in memory; `extract`, `extractall`, image programs and link targets are never invoked.

- Upper-layer files replace lower-layer records.
- `.wh.name` removes the lower path and its descendants.
- `.wh..wh..opq` removes lower-layer children of the directory.
- Whiteouts affect lower layers before all same-layer entries, regardless of tar entry order.
- Replacing a directory with a file/link removes its old children; those children cannot reappear after a later directory replacement.
- Symlink/hardlink/device/FIFO entries are never resolved. A selected link or a selected path under a non-directory ancestor yields `UNSUPPORTED`, not absence.
- Absolute, traversal, backslash, noncanonical, control-character, duplicate and overlong paths refuse. PAX/sparse profiles are refused; this is not a promise of support for every tar extension.
- Filesystem reads use the existing no-follow descriptor-relative local file reader; symlinked ancestors, hardlinked blobs and special files refuse. Referenced immutable bytes must match their approved content address.

### Explicit bounds

| Resource | Limit |
|---|---:|
| Approval window | Positive, at most 24 hours |
| Approved metadata inputs | 1–16 |
| Manifest layers | 1–16 |
| Each referenced blob | 16 MiB |
| Total referenced blob bytes | 64 MiB, including repeated references |
| Each uncompressed layer | 32 MiB |
| Total uncompressed layer bytes | 64 MiB |
| Tar entries across layers / retained paths | 10,000 |
| Selected metadata file | 1 MiB |
| Total facts | 1,000 |

These are parser bounds, **not** a hostile-code sandbox, CPU/memory exhaustion certification, throughput benchmark or SLA. The image is never executed. Expiry is checked before reading and again in final result validation.

## One capture, six evidence projections

| View | What this candidate contributes | What it never infers |
|---|---|---|
| SBOM | Package database and binary-presence metadata | Every language dependency, installed/loaded production software, complete image inventory |
| CBOM | Public certificate and literal TLS configuration facts | Crypto algorithm invocation from a package name, HSM use, negotiated TLS, PQC readiness |
| NBOM | `UNKNOWN` | `ExposedPorts` is a config declaration, not an observed listener/session |
| HBOM | `UNKNOWN` | CPU architecture in an image is not observed bank hardware |
| VBOM | Allowlisted vendor label as `DECLARED_ONLY`, when present | Verified supplier identity, contract, product authenticity or supplier capability |
| TechBOM | Same image-scoped metadata references and explicit system scope | Actual deployment or operational dependency edges |

Allowlisted base-image name/digest labels and exposed-port declarations remain in retained evidence. `base_image_verified` and `live_listeners_observed` stay false. The base label does not cause another pull/scan.

The manifest SHA256 is the stable **artifact identity**. Evidence IDs are observation references, not independent fleet asset IDs. A new image/version is a new artifact: linking it to the same deployed application must use the existing approved deployment/identity workflow. The materializer sets `graph_persisted=false` and does not create `USES`, `USES_HSM`, `DEPENDS_ON` or deployment relationships.

These are internal evidence views, not CycloneDX JSON documents. `cyclonedx_export=false`; no specification-conformance claim is made. All six views remain `complete=false`.

## Coverage, failures and provenance

`COMPLETED` means every **approved input** parsed, not complete image or estate coverage. Some parsed inputs yield `PARTIAL`; no parsed inputs yield `FAILED`. Missing selected files yield `UNAVAILABLE/NOT_FOUND`, not `NO_ASSET`. Unsafe links yield `UNSUPPORTED/LINK_OR_SPECIAL`; invalid metadata yields `INVALID/INVALID_FORMAT`; selected-file/fact limits yield `BUDGET_EXCEEDED/LIMIT`.

Root manifest, blob digest, layer, scope or structural failures refuse the collection (CLI exit 64); they do not produce a successful snapshot with empty facts. Failed per-input receipts never carry facts. `asset_absence_proven=false` always.

Coverage is `parsed_inputs / approved_inputs` with basis `APPROVED_METADATA_INPUTS_ONLY`. `whole_image_percent=null`, `full_image_software_complete=false`, `authenticity_verified=false`, `runtime_use=UNKNOWN`, `hardware_origin=UNKNOWN` and `production_execution_qualified=false` are non-promotable contract fields. Imported image evidence retains each fact's local `OBSERVED` metadata or `DECLARED` configuration basis; it does not become an attested observation of a running bank host.

## Next gate, not a bypass

The next integration work is tenant-scoped OCI target/job admission and durable evidence intake through the existing platform, with authorization/revocation/replay/expiry/database tests. That must not be enabled merely because these local parser tests pass. Independent expected-image truth, actual approved image formats, malicious-image parser testing and customer acceptance remain external release gates. Continue existing network/cloud work only after evaluating its actual evidence adapter gap; do not add another scanner simply to fill a capability matrix.
