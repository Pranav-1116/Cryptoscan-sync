# Local readiness — Phase 3 Windows CNG registration candidate

2026-10-25 UTC. Baseline `37776d0542186ca72e54219f60c50df2a1ba787a`; branch `arena/bb4b80dd-cryproscan`.

## Decision and delivered boundary

Publish a bounded **Windows candidate engineering increment**, not actual Windows qualification, a complete CryptoAPI collector or all-ten-phase completion. Exact fixed-provider/user-mode cipher/hash registration queries feed a new typed metadata fact through existing approval/custody/inspection/qualification/UI paths. Windows universal authorization remains blocked; no new service, table, dashboard or execution endpoint was created.

The reader uses documented NULL size-query and non-null caller-buffer forms, not native auto-allocation. Caller-owned buffer maximum 65,536 bytes, count/label bounds, nested pointer/alignment/span checks, NTSTATUS interpretation and explicit scope/commitment checks apply. No global provider enumeration, key/provider opening, crypto operation, registration mutation or target-image load is exposed. Registration labels do not become normalized algorithms, working capability, software versions, application use, hardware/key-origin or production traffic findings.

## Completed local gates

Counts overlap; **do not sum them**.

| Gate | Result | Meaning / limitation |
|---|---|---|
| Selected Python regression | **1,766 passed; 6 skipped** | Inventory/shared-model/CBOM plus selected Windows, Linux projections, foundation/coverage/host-evidence/worker API tests. Six actual Windows tests skip on Linux. Not all Python/all API tests. |
| Owned disposable PostgreSQL | **61 passed** | Existing host/coverage/Linux/certificate/module checks plus ten CNG custody/failure/scope/admission cases. Native interfaces are portable seams; no actual Windows execution. Owned cleanup completed. |
| Full frontend | **707 passed / 62 files** | Includes registration-only display and rejection of promoted/malformed CNG metadata. |
| TypeScript / build | **PASS / PASS** | Local typecheck/Vite build, not deployed bank acceptance. |
| Ruff / dependencies | **PASS / PASS** | Changed Python files and validation environment pip check. |
| Five public schemas/compatibility | **PASS** | Current model equality and Draft2020-12 checks; removing only new enum/union/definition exactly reproduces baseline. Existing HostFact/RuntimeFact/WindowsImageFact shapes/defaults unchanged. |
| Source-lock inclusion | **PASS** | Both new modules included by existing source-lock builder; 79 files. No signature, release approval or measured-execution claim generated. |

The selected Python total includes **81 new portable reader/API passes and one new native skip**. The ten PostgreSQL and sixteen frontend cases are within their respective totals. Initial focused/full runs are not additive gates. After the first complete regression, missing DLL/export acquisition was hardened to return an explicit interface gap and two portable tests were added; final Python/database reruns above are the publication gates. The unchanged frontend's full run remains its gate.

## Negative and custody witnesses

- Noncanonical/remote/provider/interface URI, wrong-platform success, elevation and expiry refuse. Budget exhaustion refuses before native query/allocation when possible. Size queries do not request native ownership transfer.
- Fixed DWORD/NTSTATUS, pointer-width structure sizes, explicit UTF-16 and System32 prototypes are tested through portable fixtures, not actual 32-/64-bit/ARM64 Windows.
- Missing DLL/export becomes UNAVAILABLE/INTERFACE_UNAVAILABLE. Denied/not-found/unknown/informational native status, unexpected successful size query, undersized/oversized/growing output, replaced pointer and malformed nested pointer graphs refuse.
- Null/unaligned/out-of-bounds structures, pointer arrays and labels; wrong/multiple interface or kernel data; zero/overflow counts; malformed UTF-16, unterminated/overlong/unsupported/duplicate labels never produce a positive fact.
- Snapshot interface/identity/provider/mode/platform, duplicate fact, selected-function list or digest mismatches fail. Algorithm, version, capability and runtime-use promotions fail. The model reconstructs selected metadata and binds it to the receipt digest.
- Independent expected-truth tooling now accepts only the bounded canonical new registration-label list alongside existing scalar assertions. Nested/arbitrary/duplicate/oversized list values remain refused. A hand-authored portable fixture verifies exact-label comparison and mismatch refusal; it is not an operator approval/native witness.
- Authenticated tenant-scoped intake and read/export retain IMPORTED transport, local metadata claims and false qualification flags. Cross-estate/unselected administrator reads refuse; changed originals fail integrity. Reads do not invoke CNG or create new scan/evidence records. Normal CBOM export auditing remains.
- `AES`/`3DES` registration labels still produce **zero CBOM components**, not crypto capability/use or “no crypto.” Universal Windows authorization remains 409/future capability.

The PostgreSQL console retains the **baseline pgserver logging-to-a-closed-pytest-capture-stream diagnostic during cleanup**. It is not suppressed or represented as a clean console. Tests/process exit succeeded, pg_ctl reported the server stopped and the owned temporary directory was removed. This is a validation-harness logging defect, not actual Windows evidence or proof of failed cleanup; product logging was not changed.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_windows_cng_candidate.py services/api/tests/unit/test_windows_image_candidate.py \
  services/api/tests/unit/test_windows_certificate_candidate.py services/api/tests/unit/test_linux_phase2_projections.py \
  services/api/tests/unit/test_linux_software_inventory.py services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py services/api/tests/unit/test_host_evidence.py \
  services/api/tests/unit/test_host_worker.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --include-windows-certificate-candidate --include-windows-image-candidate \
  --include-windows-cng-candidate --junitxml=/home/user/windows-cng-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

[Guide 74](../bank-environment/74-phase-three-windows-cng-registration-candidate.md) describes the operator-owned native fixture and actual Windows optional test. Operators approve complete independent expected truth before collection. Missing Windows/resource is SKIP, never native PASS. No credentials/private keys should be sent in chat or put in public evidence.

## Retained evidence and open gates

[`windows-cng-registration-candidate-2026-10-25/manifest.json`](windows-cng-registration-candidate-2026-10-25/manifest.json) commits source/doc and local test-artifact hashes. Console ANSI/trailing whitespace/blank EOF lines are normalized; JUnit XML is verbatim. Digests support integrity/review, not authenticity, organizational independence or bank acceptance.

Actual Windows version/architecture/ACL, native registry churn, internal allocation/activity, DLL/buffer lifecycle, native latency, isolation/cancellation and independent review are pending. The caller-buffer cap is not an OS-allocation/RSS/wall-clock guarantee. Registered metadata is not a tested algorithm implementation or invoked provider. A fixed provider name is not publisher/vendor authentication.

Broader reviewed CNG/legacy CAPI surfaces, TLS/listener attribution and TPM/firmware remain Phase 3 work. No complete Windows SBOM/graph, all-six-BOM completeness, crypto/key use, host authenticity, performance improvement, production admission, HA/DR, staffing SLA or bank acceptance follows from these tests. No workflow files changed; publication uses `[skip ci]`, not proof every external workflow honors it.
