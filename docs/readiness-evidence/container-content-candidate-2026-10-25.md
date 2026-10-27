# Local readiness — verified container content/runtime candidate

2026-10-25 UTC. Baseline `f18380f02b65c6a2b47da4b13f7febc3254ca87e`; branch `arena/bb4b80dd-cryproscan`.

## Decision: engineering delivered, production admission still blocked

Build on existing OCI metadata/custody and reuse existing Linux package/process parsers and official CycloneDX validator. Deliver bounded **verified layer bytes + virtual overlay + scoped dpkg/APK records + exact process/cgroup observation**. Wire fail-closed production admission policy and a stored-evidence blocker assessment. **Do not label the still-missing qualified production executor, independently verified runtime↔image binding, real-image acceptance or actual Windows qualification complete.**

No new service/table/dashboard/dependency, remote registry, privileged daemon/socket, active probe, image/package execution, workflow change or customer deployment. Source-lock inclusion is not source authenticity or qualified execution.

## Completed local validation

Counts overlap and must not be summed or converted into phase percentages.

| Gate | Result | Boundary |
|---|---|---|
| Selected broad Python | **2,181 passed; 10 skipped** | All inventory/shared/CBOM/container tests plus 13 selected host/collection API modules, not every repository Python/API test. Ten actual-Windows cases skip on Linux, not native PASS. |
| Owned disposable PostgreSQL 16.2 | **112 passed** | Seven new container custody/export/admission cases; server stopped, owned temporary directory absent, no owned server remained. Not customer database/production qualification. |
| Full frontend | **780 passed / 63 files** | Includes 104 existing HostEvidencePanel cases and 21 new content/runtime/display/download/context cases. Not real browser/deployed acceptance. |
| TypeScript / Vite build | **PASS / PASS** | Local build, not an approved release. |
| Ruff / format / whitespace | **PASS** | 22 changed/new product/test Python files; no workflows/requirements/dependency-lock changes. |
| pip consistency | **PASS** | Current `/home/user/qualify-venv`, not production/site qualification. |
| Five public schema/model/additive compatibility checks | **PASS** | Draft2020-12 and model equality. Remove only two new input literals/fact unions/four definitions: exactly pinned baseline f18380f0. All old fact shapes/defaults unchanged. |
| Existing source-lock inclusion | **PASS — 94 files** | Includes new content/runtime/shared-overlay/contracts/admission modules. No signature, independent approval or measured-worker claim generated. |
| Final focused source/CLI/OCI/API follow-up | **126 passed** | After final tar end-marker hardening, restoring existing sorted JSON-schema serialization and clarifying the opt-in CLI description. Semantics unchanged; source-lock/isolated-stage, old/new OCI and new API checks rerun against final bytes. |

The broad gate adds **59 new Python cases** (52 content/runtime/CLI/model/admission seams and seven API), seven PostgreSQL cases and 21 frontend cases. Portable synthetic/model-derived fixtures are not independently agreed expected truth or actual real-container/native-Windows qualification.

## Negative and control evidence

### Content verification and overlay

- Exact approved manifest/platform and existing double-sampled metadata checks precede layer reads. Each compressed/plain blob SHA/size and full uncompressed diff-ID must agree. Altered/missing/link blobs, wrong diff-ID, malformed/truncated tar, concatenated/nonzero trailers and gzip expansion overflow refuse, preserving no partial positive.
- Per-input **combined** 1 MiB and total 16 MiB caps remain unchanged. Raw reads, gzip expansion and selected output are charged; expansion overflow saturates the approved recorded-byte budget rather than producing an invalid over-budget snapshot. No global limit was increased to accommodate large images.
- Virtual in-memory overlay only, no tar extraction or host filesystem writes. Traversal/absolute members, special/sparse files, duplicate paths and invalid whiteouts refuse. Opaque/ordinary whiteouts act on lower entries before same-layer additions; both marker orders retain new records correctly. Deleted package databases contribute no stale packages.
- Image-internal symlink resolution and earlier same-layer file hardlinks operate only in the virtual view. Escapes, cycles, dangling database links, unresolved/non-file/forward/lower-layer hardlinks and writes/whiteouts through non-directory ancestors refuse rather than guess. The existing legacy merger also uses shared whiteout names and processes removals before additions.
- Reused dpkg/APK parsers produce database-record name/version metadata only. Each record binds the final logical source database SHA and writer layer; reordered/duplicated/promoted/changed source facts refuse strict scope/commitment validation. Malformed database is a gap, not empty software success.
- `layer_contents_verified`/virtual-view true are specific hash/view claims; materialization, complete package inventory, runtime-image/deployment/vendor verification stay false. Rootfs view hash is not permissions/ownership/xattrs, executable integrity, publisher authenticity or running-rootfs attestation. Zstd/RPM/language/binary/full-filesystem support is explicitly unqualified.
- Explicit CLI content/runtime opt-in, canonical reviewed target hash and exclusive output are tested. Old metadata wrapper refuses the new kinds; ordinary-user/platform/window/credential checks remain in existing collection guards.

### Runtime process observation

- Reuses bounded kernel Reader/process/boot/start helpers; exactly approved `/proc/<pid>/{stat,comm,cgroup}` plus fixed boot ID. No wildcard/list-all, environment/argument/memory inspection, process opening outside existing passive interfaces, namespaces/rootfs entry, daemon or socket.
- Exact PID/start/boot/cgroup ID required; changed/reused/zombie/out-of-scope incarnation, wrong/contradictory/unrecognized cgroup identity and byte exhaustion produce gaps, never container absence. Cgroup parsing detects nested contradictory IDs instead of consuming a delimiter and missing the second ID.
- Runtime-to-image digest remains OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED even with matching verified content. Process/cgroup observation is not independent engine authority, deployment identity or operational/crypto use; equal samples are not atomic/continuous truth.

### Custody, projections, UI and admission

- API uses original approval/intake/evidence with tenant/RBAC/integrity checks. Stored export/readiness succeed after source files are deleted and collectors are patched to fail on any call. No scan/evidence creation; only successful SBOM export audit.
- Official pinned CycloneDX 1.6 validation passes for image and packaged-record components. Invalid official validation is 503 without success audit. All failed content cannot turn a surviving runtime observation into empty successful package inventory. No dependency/supplier/full-image hash fiction; composition incomplete and original receipt evidence references retained.
- Foreign tenant/unselected administrator reads refuse; changed originals refuse both export and readiness. Readiness derives counts/gaps from retained imported originals and lists data and external qualification blockers. It never returns an authorization token or grants clearance.
- Frontend refuses malformed/promoted nested image/content/package provenance and process/image-binding claims. Positive explicit content export is tested, bound to current snapshot/profile; logout fences a pending response without download. No auto-collection/export or new dashboard.
- Universal `container` authorization invokes the empty **server-owned** admitted-profile policy. API and runtime offline-Linux wrappers reject both new kinds, so they cannot tunnel into admitted Linux support. Imported `production_execution_qualified: true` and a guessed environment enable flag cannot open admission. Existing global universal-production boundary remains unchanged.

## Development failures resolved, not hidden as passes

Initial focused tests exposed two defects: gzip's overflow sentinel was charged one byte beyond the allowed receipt bound, and a consuming cgroup-regex delimiter could miss a second nested container ID. Both were corrected before broad gates; focused cases now pass. API fixture collection originally preceded approval and correctly received the existing time-scope refusal; the fixture now approves before collection, with no weakening of product checks. Ruff removed one unused test import.

The broad run retains six existing API deprecation warnings plus a Pydantic serialization warning from an intentionally malformed synthetic resealing test; the model rejects that payload. These warnings are not native qualification. PostgreSQL cleanup again retains the existing pgserver closed-capture logger diagnostic (`ValueError: I/O operation on closed file`); output includes `server stopped`, 112 passes, zero exit and cleanup. `/home/user/cryptoscan-host-witness-rjt8mdoj` was independently verified absent with no owned server running. No unrelated harness rewrite or fabricated clean production result.

Final review also found that the standard tar reader accepts a file without its two end-marker blocks. The candidate now explicitly requires both zero blocks and has an unterminated-tar refusal case; the full selected Python gate was rerun (2,181 passes). The PostgreSQL/frontend gates retain their completed results; the final SQLite API follow-up rechecks the unchanged valid fixture/custody contracts.

Public schema files were finally normalized back to their existing `sort_keys=True` serialization to avoid unrelated key-order churn; JSON/schema semantics were unchanged. The 126-case final follow-up and compatibility/source-lock proof use the final bytes.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests services/container_scanner/tests \
  services/api/tests/unit/test_container_content_candidate.py services/api/tests/unit/test_oci_metadata_candidate.py \
  services/api/tests/unit/test_windows_metadata_candidates.py services/api/tests/unit/test_windows_tpm_candidate.py \
  services/api/tests/unit/test_windows_cng_candidate.py services/api/tests/unit/test_windows_image_candidate.py \
  services/api/tests/unit/test_windows_certificate_candidate.py services/api/tests/unit/test_linux_phase2_projections.py \
  services/api/tests/unit/test_linux_software_inventory.py services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py services/api/tests/unit/test_host_evidence.py \
  services/api/tests/unit/test_host_worker.py -q --junitxml=/home/user/container-python.xml
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software --include-linux-projections \
  --include-windows-certificate-candidate --include-windows-image-candidate --include-windows-cng-candidate \
  --include-windows-tpm-candidate --include-windows-metadata-candidates --include-oci-metadata-candidate \
  --include-container-content-candidate --junitxml=/home/user/container-postgres.xml
/home/user/qualify-venv/bin/python docs/readiness-evidence/container-content-candidate-2026-10-25/schema-check.py
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

## Outstanding requirements and operator boundary

[Guide 78](../bank-environment/78-verified-oci-content-and-runtime-candidate.md) and [API contract](../api-reference/container-content-candidate.md) describe exact use. Real operators must independently agree expected truth before measurement; no operator assignments, approved customer images/runtime, independent signatures/acceptance or actual Windows execution were supplied/performed. Do not send credentials/private keys or upload full/private-key-bearing images to public channels.

**Production admission remains unfulfilled** until a qualified executor/release, independently justified runtime↔image binding, real-image truth/acceptance and release/isolation/cancellation/resource/recovery controls are demonstrated and explicitly admitted. This is not a complete package inventory, complete Linux filesystem implementation, authenticated daemon/publisher, full six-BOM inventory, performance/SLA/HA/DR or bank acceptance. Windows/TPM qualification remains separately open; later phases are not newly completed.

## Retained artifacts

[Manifest](container-content-candidate-2026-10-25/manifest.json) binds changed source/docs/tests/schemas and 13 local validation artifacts. Console ANSI/trailing whitespace/blank EOF normalized; XML unchanged, schema-check helper retained and reproducible. Hashes support integrity review, not authenticity or independent qualification. Publication uses `[skip ci]` without workflow changes; external workflow behavior is not guaranteed.
