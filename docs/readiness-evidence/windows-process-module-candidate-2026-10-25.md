# Local readiness — Phase 3 Windows process/module candidate

2026-10-25 UTC. Baseline `fe1bbaec49872ae04ee6da78d134d32a356dca4f`; branch `arena/bb4b80dd-cryproscan`.

## Decision

Publish a bounded Windows **candidate engineering increment**, not Windows-native qualification or all-ten-phase completion. No Windows host, account, process or customer deployment was contacted here; native behavior is exercised through explicit portable seams, with an actual Windows test skipped.

Implemented exact PID + string creation-FILETIME scope; query-limited + SYNCHRONIZE handle rights and zero-time liveness checks; two bounded Toolhelp module-table samples; before/after incarnation/image checks; byte/count/cleanup refusals; selected-metadata commitment reconstruction; a separate typed fact union; existing host custody/inspection/UI; qualification expected-field allowlists and five synchronized public schemas. No private-key API, VM_READ, target-image load, remote execution, new service/table/dashboard or Windows universal authorization was added.

## Completed local gates

Counts overlap; do **not** sum them.

| Gate | Result | Meaning / limitation |
|---|---|---|
| Selected Python regression | **1,685 passed; 5 skipped** | Inventory/shared-model/CBOM plus selected Windows, Linux projection, foundation/coverage/host-evidence/worker API tests. Five actual Windows tests skip on Linux. Not all Python/all API tests. |
| Owned disposable PostgreSQL | **51 passed** | Existing host/coverage/Linux/certificate checks plus 11 new module-candidate custody/failure/scope/admission cases. Native API results remain portable fixtures. Owned database cleanup completed. |
| Full frontend | **691 passed / 62 files** | Includes exact FILETIME text display and refusal of rounded/promoted software/crypto/module claims. |
| TypeScript / build | **PASS / PASS** | Local typecheck/Vite build, not a deployed bank UI. |
| Ruff / dependency check | **PASS / PASS** | Changed Python files and validation environment pip check. |
| Five public schema compatibility checks | **PASS** | Equal to current model schemas; Draft2020-12 checks pass. Removing only new literal/union/definition exactly reproduces baseline schemas. HostFact/RuntimeFact definitions/defaults unchanged. |
| Existing source-lock scope | **PASS** | Both new modules included; 77 source-lock files. No signature, release authorization or measured-execution claim generated. |

The selected Python run contains **70 new passing portable reader/API cases plus one native skip**, within its totals. Initial focused passes are not additive final gates. Fourteen frontend cases are new, within the frontend total. The initial complete frontend run passed 689 before two additional software-name/version promotion tests and their guard were added; the final rerun above is the publication gate.

## Important negative witnesses

- Canonical scope/range/type checks reject zero/overflow/aliased PID, noncanonical FILETIME, remote/extended URI, numeric FILETIME and wrong platform.
- Ordinary-user and expiry refusal happen before native open. Access denied, missing, unknown/cross-bitness and ERROR_BAD_LENGTH errors, empty tables, duplicate paths, malformed/remote paths, name mismatch, over-count and byte exhaustion emit no positive facts.
- Fixed-width ABI/UTF-16/prototype/System32 checks use portable fixtures. They do not execute real 32-bit/64-bit/ARM64 Windows.
- Handle-bound start/end creation/path/liveness and changed table checks refuse stale or changed evidence. A **signaled process with exit code 259** refuses; 259 alone is not a liveness proof. Portable close sequences include failure/budget paths; this is not real kernel handle-leak qualification.
- Facts cannot change PID, creation, algorithm/runtime-use, table cardinality or selected content/digest binding while preserving a valid receipt. A coherent changed path/identity with a stale source commitment also refuses.
- A crypto-named module stays algorithm/use UNKNOWN; it creates zero CBOM components. No version, supplier, HSM relationship, TLS listener or invocation is inferred.
- Authenticated intake/inspection/export retains IMPORTED transport/local claims. Cross-estate and unselected administrator reads refuse; changed retained originals fail integrity. Inspection/export invokes no collector and creates no new scan/evidence. The normal CBOM export audit event remains expected.
- Windows target registration does not imply execution admission: universal authorization remains 409/future capability.

The PostgreSQL console retains the **existing pgserver logging-to-closed-pytest-capture-stream diagnostic during cleanup** (also present in the baseline certificate run). It is not suppressed or represented as a clean console. All 51 tests and process exit succeeded, pg_ctl reported the server stopped, and the owned temporary directory was removed. This is a validation-harness logging defect, not a native Windows witness or evidence that cleanup failed; no product logging behavior was changed here.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_windows_image_candidate.py services/api/tests/unit/test_windows_certificate_candidate.py \
  services/api/tests/unit/test_linux_phase2_projections.py services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --include-windows-certificate-candidate --include-windows-image-candidate \
  --junitxml=/home/user/windows-image-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

Actual Windows fixture/operator commands are in [guide 73](../bank-environment/73-phase-three-windows-process-module-candidate.md). Operators approve independent expected truth first, run their packet and retain originals. Missing Windows or fixture is SKIP, never native PASS. No credentials/private keys should be sent in chat or included in public evidence.

## Retained artifacts and open gates

[`windows-process-module-candidate-2026-10-25/manifest.json`](windows-process-module-candidate-2026-10-25/manifest.json) commits source/doc and local test-artifact hashes. Console ANSI/trailing line whitespace is normalized; JUnit XML is copied verbatim. Hashes support integrity/review, not authenticity or independent human acceptance.

Native OS allocation/latency, architecture/cross-bitness, real ACL denial, churn, long paths, lifecycle/leaks and cancellation/isolation remain unqualified. Module-table samples are not atomic, complete mappings or continuous execution. Literal path hashes are not artifact hashes and drive-letter syntax is not physical-locality proof. Native CNG/CAPI metadata, TLS/listener attribution and TPM/firmware remain separate Phase 3 gates.

No Windows production admission, full Windows SBOM/graph, all-six-BOM completeness, crypto invocation, key origin, host authenticity, performance improvement, HA/DR, staffing SLA or bank acceptance follows from these local checks. No workflow files changed. Publication uses the requested `[skip ci]` marker, not a guarantee every external workflow honors it.
