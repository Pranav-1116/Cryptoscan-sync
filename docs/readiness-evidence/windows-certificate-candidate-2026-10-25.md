# Local readiness — Phase 3 Windows public certificate candidate

2026-10-25 UTC. Baseline `d1bf94fa0129143e3959644802793a7947918506`; branch `arena/bb4b80dd-cryproscan`.

## Decision and implementation

Publish a bounded **Windows candidate engineering increment**, not native Windows or bank/production qualification. Foundation and Linux work are reused; this is not a second universal architecture or a new service.

- Exact `WINDOWS_CERTIFICATE` local store resource, fixed locations/stores, SHA-1 locator plus required SHA-256 binding. Both are recomputed against returned DER locally; intake additionally binds fingerprint and DER-content commitment to the approved SHA-256.
- Crypt32 System32 loading, fixed-width ABI/function prototypes, read-only/existing store flags, bounded Python copy, duplicate-result refusal and explicit native-context/store ownership cleanup.
- Existing canonical public-certificate parser and fact shape reused. No enumeration interface, private-key/PFX APIs, store mutation, trust/chain/key-use inference, remote account or production job admission.
- Existing scoped approval/intake/inspection/officially validated CBOM flow retains original evidence. Reads never invoke the native collector again; normal CBOM export auditing remains intact.
- Five public JSON Schemas synchronized by enum-only extension. Existing fact/envelope fields/defaults unchanged. Older pinned-enum clients do not automatically support the new kind.

## Completed local gates

Counts overlap; do **not** sum them.

| Gate | Result | What it establishes / does not establish |
|---|---|---|
| Selected Python regression | **1,615 passed; 4 skipped** | All inventory/shared-model/CBOM tests plus selected Windows candidate, Linux software/relationships, foundation/coverage/host-evidence/worker API tests. Four actual Windows-native tests skip on Linux, including the new certificate-store witness. Not all Python/all-API tests. |
| Owned disposable PostgreSQL | **40 passed** | Existing host/coverage/Linux projection contracts plus six Windows candidate custody/failure/admission cases. Cleanup completed. Native results are injected portable fixtures, not a Windows database/native execution witness. |
| Full frontend | **677 passed / 62 files** | Existing UI regression; no new frontend source required because existing certificate fact shape is reused. |
| TypeScript / build | **PASS / PASS** | Local `tsc --noEmit` / Vite build; not a deployed bank UI. |
| Ruff / dependency check | **PASS / PASS** | Changed Python files and validation environment pip check. |
| Five schema/compatibility checks | **PASS** | Model schemas equal published schemas; Draft2020-12 schema checks pass. Removing only the new literal exactly reproduces baseline schemas; existing HostFact definitions/defaults unchanged. Runtime scope checking is stricter than the generic path schema. |
| Candidate source-lock scope | **PASS** | New native-reader source is included by existing lock builder; changed host/shared/schema files require a fresh approved release lock. No signature/approval generated. |

The selected regression contains **37 new passing portable reader/API cases and one new native skip**, within—not in addition to—the totals above. The earlier 28-pass portable run and focused API run are not additive final gates.

## Negative and custody witnesses

- Noncanonical/remote/incomplete URI, unsupported store, uppercase locator, missing required SHA-256, expiry and elevation refuse before opening a store.
- Denied/missing/unknown native errors, first/second lookup failure, duplicate match, changed SHA-1/SHA-256, zero/null/wrong-encoding/oversized context, fixed-budget exhaustion and malformed bound bytes do not emit positive facts.
- Native-like buffers stay alive in the fake ABI; second-find previous-context transfer is simulated explicitly. First/second-context and close/free failure paths are tested. These portable simulations are **not** proof of real native handle cleanup or actual ACL behavior.
- Snapshot fingerprint/content/platform mismatches fail; imported metadata retains local OBSERVED with IMPORTED transport and UNKNOWN runtime/PQC use.
- Actual authenticated tenant-scoped SQL intake/inspection/CBOM export is exercised with synthetic snapshots. Cross-estate/unselected administrator reads return 404; changed originals return 409; no new scan/evidence is created on export. The existing export adds its expected `host.export` audit event.
- Windows universal target authorization remains 409/future capability. No worker, remote mode, production execution allowlist or qualification gate changed.

The initial focused API test incorrectly assumed CBOM export created no audit event. The existing product correctly wrote `host.export`. The test was corrected to require unchanged scan/evidence counts **and one additional audit event**; no product audit behavior or guard was weakened. The failed initial output is retained as `initial-contracts.txt`, not represented as a passing run.

## Reproduce local checks

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_windows_certificate_candidate.py \
  services/api/tests/unit/test_linux_phase2_projections.py services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --include-windows-certificate-candidate \
  --junitxml=/home/user/windows-certificate-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

The real ordinary-user Windows fixture command and optional `CRYPTOSCAN_WINDOWS_CERTIFICATE_RESOURCE` test are in [guide 72](../bank-environment/72-phase-three-windows-public-certificate-candidate.md). Operators supply pre-reviewed expected truth and select an already-existing public certificate. Missing native platform/fixture is not a native PASS. No credentials or private keys should be sent in chat or included in public evidence.

## Integrity and outstanding gates

[`windows-certificate-candidate-2026-10-25/manifest.json`](windows-certificate-candidate-2026-10-25/manifest.json) hashes 19 source/doc files and 10 retained artifacts. Console text has ANSI escapes and trailing line whitespace removed; JUnit XML is copied verbatim. Digests support review/consistency, not authenticity, independent human status or bank acceptance.

Native provider allocation/search can happen before the bounded copy and native API calls do not yet have an independent wall-clock cancellation worker. Real Windows ACL, version/architecture, lifecycle/leak, isolation/cancellation and independent security review are pending. Loaded DLLs/process identity, CNG/CAPI provider metadata, negotiated TLS/listener relationships and TPM/firmware remain separate Windows gates.

No Windows machine, account, certificate store or customer deployment was contacted or mutated here. No private key, operator signature, release approval or human acceptance was manufactured. No workflow files changed; publication uses `[skip ci]`, not proof every external workflow honors it. No complete Windows inventory, all-six-BOM completeness, hardware/key origin, negotiated TLS, crypto invocation, host authenticity, HA/DR, staffing SLA or production qualification follows from these local tests.
