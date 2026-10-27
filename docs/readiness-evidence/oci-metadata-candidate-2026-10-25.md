# Local readiness — offline OCI image metadata candidate

2026-10-25 UTC. Baseline `838be60086eda2ec7aec2d790bf742244a6c6965`; branch `arena/bb4b80dd-cryproscan`.

## Decision and delivered scope

Reuse existing collection, custody, six-BOM classification, official schema validation and console; start the next missing universal-adapter engineering area rather than rebuild Linux/Windows. Deliver a **Phase 4 offline OCI manifest/config metadata candidate**, not full container/package inventory or an admitted executor. Actual Windows qualification remains external/open, including the TPM SDK/documentation discrepancy. Beginning later offline engineering does not waive qualification/admission prerequisites.

- Exact local Linux OCI manifest SHA-256 and amd64/arm64[/v8] selection; four bounded no-follow files sampled twice. Manifest/config digest and descriptor-size verification, strict source/resource/selected-metadata identity/receipt validation.
- Explicit layer/diff-ID/port/base-image declarations and false layer/filesystem/package/deployment/vendor verification; Env/Cmd/arbitrary labels are not emitted. No registry/network/socket/archive/layer reads or execution.
- Separate offline wrapper and hash-pinned target CLI with exclusive output. Existing container parser gains optional common exact selector; its legacy default is preserved. The universal Linux adapter and API explicitly refuse OCI bypass; `container` authorization remains future/409.
- Existing approved host custody/tenant/integrity inspection, SBOM/TechBOM references and software coverage classification. No new DB/table/service/dashboard or migration.
- Stored-only image-artifact SBOM route, incomplete composition and official offline CycloneDX 1.6 validation; successful export audited/no-store. No packages/dependencies/supplier/full-image hashes or promoted runtime assertions.
- Existing panel strict OCI guard, declared/unverified metadata display and explicit export bound to the inspected snapshot/profile.

## Completed local gates

Overlapping counts must not be summed or converted to phase-completion percentages.

| Gate | Result | Scope / limitation |
|---|---|---|
| Selected broad Python | **2,122 passed; 10 skipped** | Inventory, shared models, CBOM, existing container scanner and 12 selected host/collection API modules; not every Python/API test in the repository. Ten actual-Windows opt-in tests skip on Linux, not native PASS. |
| Owned disposable PostgreSQL 16.2 | **105 passed** | Includes seven OCI custody/export/admission cases; synthetic local DB only. Cleanup completed, owned directory absent and no owned server remained. |
| Full frontend | **759 passed / 62 files** | Includes 104 host-evidence-panel cases, 15 new OCI cases; not browser/deployed bank qualification. |
| TypeScript / Vite production build | **PASS / PASS** | Local validation/build, not an approved deployed release. |
| Ruff / format / diff whitespace | **PASS** | 19 changed/new product/test Python files, no workflow/dependency-lock changes. |
| pip consistency | **PASS** | Current `/home/user/qualify-venv`, not a production lock/site certification. |
| Five public v1 schemas | **PASS** | Model equality and Draft2020-12 checks; removing only OCI input/union/definitions exactly reproduces **pinned baseline 838be600…**. Existing fact shapes/defaults unchanged. |
| Existing source-lock inclusion | **PASS — 89 files** | Both new inventory/shared OCI modules included; no generated release signature, independent approval or measured execution. Direct candidate CLI is not claimed to execute a verified isolated stage. |
| Final parser/reader follow-up | **168 passed** | After final formatting-only blank line in existing parser: 51 OCI inventory cases plus 117 legacy container cases. No behavior changed after broad gates. |

The broad Python total adds 58 new OCI cases (51 inventory and seven API) and includes 117 existing container tests beyond the prior selected gate. PostgreSQL has seven new cases; frontend 15. These are synthetic/model-derived seam tests, not independently agreed operator truth or real-image acceptance.

## Negative/control evidence

### Reader and typed contracts

- Explicit digest/platform selection; duplicate/missing manifest descriptor refuses, never first-image fallback. Changed manifest/config bytes, descriptor sizes/platform/rootfs, bad media types, subject/artifactType, external/embedded descriptor content, malformed base digest/port declarations and inconsistent declarations produce gaps.
- No layer bytes required: the fixture declares a large nonexistent layer and still yields metadata with all content/filesystem/package/deployment verification flags false. That is intentional limited scope, not a verified image.
- Missing files, parent/file symlinks, hardlinks, malformed/duplicate/deep JSON and changed index samples refuse. Descriptor-relative existing regular-file reader is reused; no archive or decompressor is reached.
- Raw bytes from both four-file samples and selected JSON consume existing per-input/total limits. Exhaustion refuses without a partial positive. These caps/stability checks do not qualify atomic snapshots, internal resource/latency/isolation/cancellation or continuous monitoring.
- Strict fact validation rejects fabricated identity/commitment, out-of-approved-manifest/platform facts, duplicate positive facts and promoted layer/package/vendor/runtime/crypto claims. Algorithm/use/PQC stay UNKNOWN, policy NOT_EVALUATED.
- Wrapper requires `container`, actual/manifest Linux, only OCI inputs, matching environment/time and no credentials. Wrong target digest/output overwrite/expiry/credentials/excluded input/platform refuse; CLI is explicit offline only.

### Custody, export, UI and admission

- Original approval/intake/evidence retained under existing tenant boundaries. Stored snapshot/CBOM/image export succeed after fixture files are removed, with collection monkeypatched to fail if called. Exports create no scan/evidence rows; only successful audits.
- Image export passes the official CycloneDX 1.6 validator; failed official validation is 503 without a successful export audit. Failed image receipts remain gaps and all-failed export is 409, not empty success/image absence. A normal host CBOM can have zero crypto components without implying NO_CRYPTO.
- Foreign tenant and unselected administrator cannot export. Changed stored originals refuse integrity. Grouping refuses contradictory same-manifest descriptions instead of producing an authoritative merged artifact.
- Frontend labels declared ports and unverified layers/packages/runtime. Promoted verification/crypto/vendor/platform/hash/port/layer fields refuse; a download bound to another snapshot refuses. Existing private-context generation fencing remains, not an authentication substitute.
- Universal `container` and OCI-through-`offline_host` authorizations both remain 409. No registry calls, daemon/socket paths, production admission flags or worker execution capabilities were enabled. Source-lock shape/inclusion does not certify candidate execution or image publisher authenticity.

## Harness observations

PostgreSQL cleanup again emitted the existing pgserver logger diagnostic (`ValueError: I/O operation on closed file`) after pytest captured output. Retained output reports the owned `pg_ctl` stop result `server stopped`, 105 passed, zero process exit and completed cleanup. `/home/user/cryptoscan-host-witness-iecg78el` was independently verified absent, with no owned server running. This unrelated closed-capture logging issue was not relabelled a native/platform PASS or silently removed from retained logs. Existing Python deprecation and frontend environment advice are retained as warnings, not hidden failures.

One final Ruff format check identified only a missing blank line after the new lazy import in the existing image parser. It was formatted; final Ruff/format passed and all 168 relevant reader/container cases were rerun. Final source/doc/artifact bytes are recorded by the manifest below.

## Reproduce local validation

Use the repository's validation dependencies; no customer credentials/registry/database are needed. The pgserver harness explicitly owns disposable local state.

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests services/container_scanner/tests \
  services/api/tests/unit/test_oci_metadata_candidate.py services/api/tests/unit/test_windows_metadata_candidates.py \
  services/api/tests/unit/test_windows_tpm_candidate.py services/api/tests/unit/test_windows_cng_candidate.py \
  services/api/tests/unit/test_windows_image_candidate.py services/api/tests/unit/test_windows_certificate_candidate.py \
  services/api/tests/unit/test_linux_phase2_projections.py services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py \
  -q --junitxml=/home/user/oci-python.xml
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software --include-linux-projections \
  --include-windows-certificate-candidate --include-windows-image-candidate --include-windows-cng-candidate \
  --include-windows-tpm-candidate --include-windows-metadata-candidates --include-oci-metadata-candidate \
  --junitxml=/home/user/oci-postgres.xml
/home/user/qualify-venv/bin/python docs/readiness-evidence/oci-metadata-candidate-2026-10-25/schema-check.py
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

## Operator and advancement status

[Guide 77](../bank-environment/77-offline-oci-image-metadata-candidate.md), [API contract](../api-reference/oci-image-metadata-candidate.md) and [operator packet](../runbooks/offline-oci-metadata-candidate.md) document use and next work. No actual operator assignments, independent expected truth, customer images/hosts/registries or deployment were supplied/contacted in this increment. Do not send credentials/private keys. The candidate is not independently qualified or production-admitted.

**Next Phase 4 work:** compressed/uncompressed layer verification, bounded safe archive/decompression/overlay/whiteout handling, final-rootfs package/library/config evidence using existing utilities and Linux parsers, then independent real-image qualification and explicit admission. Network/cloud/HSM/vendor/correlation/production-hardening phases are not newly completed. No full six-BOM inventory, trusted publisher, running-workload identity, performance improvement, HA/DR/SLA or bank acceptance follows.

## Retained artifacts

[Manifest](oci-metadata-candidate-2026-10-25/manifest.json) binds this increment's changed source/docs/tests/schemas and 13 validation artifacts. Console ANSI/trailing whitespace/blank EOF normalized; XML and schema-check script retained verbatim. These hashes support integrity review, **not authenticity, independent approval or release signing**. Publication uses `[skip ci]` with no workflow changes; external workflows may handle that marker differently.
