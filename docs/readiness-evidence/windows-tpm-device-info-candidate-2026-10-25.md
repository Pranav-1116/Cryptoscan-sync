# Local readiness — Phase 3 Windows TPM device-info candidate

2026-10-25 UTC. Baseline `0685f751bed7ba1092d96cc61704deab6b675c24`; branch `arena/bb4b80dd-cryproscan`.

## Decision and scope

Continue existing foundation/Linux/Windows collectors instead of rebuilding them. Add one exact local OS-selected TPM version-metadata candidate through existing approval, original custody, strict normalization, classification and UI. **Not actual Windows qualification, all-ten-phase delivery, full TPM/HSM discovery or production admission.** Universal Windows authorization remains blocked; no new service/table/dashboard/execution endpoint or customer deployment change.

`windows-tpm://local/device-info` / `WINDOWS_TPM_DEVICE_INFO` makes one System32 TBS call into a caller-owned four-uint32 output. Only supported structure version 1 and known TPM version 1.2/2.0 produce `WINDOWS_TPM_METADATA`. Ignore reserved output fields. No context/key/TPM command, firmware, attestation, capability, physical identity, supplier or application-use claim. HBOM/TechBOM classification does not invent CBOM/SBOM/NBOM/VBOM content or complete Windows exports.

## Completed local gates

Counts overlap; **do not add them**. Publication follows successful final runs, not the earlier focused/intermediate totals.

| Gate | Result | Limit |
|---|---|---|
| Selected Python regression | **1,810 passed; 7 skipped** | Inventory/shared models/CBOM and selected Windows/Linux/foundation/coverage/host-evidence/worker API contracts, not all Python/API tests. Actual Windows tests skip on Linux. |
| Owned disposable PostgreSQL | **70 passed** | Existing selected parity contracts plus nine new portable TPM custody/failure/tamper/admission cases. No real TBS hardware. Owned server stopped and temporary directory removed. |
| Full frontend | **720 passed / 62 files** | Includes 13 new TPM display/refusal cases; 65 total host-evidence-panel cases. |
| TypeScript / Vite build | **PASS / PASS** | Local engineering environment, not deployed bank acceptance. |
| Ruff / pip consistency | **PASS / PASS** | Changed Python files / validation environment, not release-image or signed-lock clearance. |
| Five public schemas | **PASS** | Current model equality and Draft2020-12 validity; removing only the new TPM input/union/definition exactly reproduces baseline. Existing fact schemas/defaults unchanged. |
| Source-lock inclusion | **PASS** | Both new modules included by existing builder (81 files); no signature, approval or measured execution fabricated. |

The Python total includes **44 new portable passes** (35 reader/model/fixture-runner, nine API) and one new native skip. Nine PostgreSQL and 13 frontend additions are already within their respective totals. A final portable expected-truth test was added after the first full Python run. UI validation was then tightened to refuse unknown TPM fields and promoted PQC/policy claims; the final full frontend was rerun. Earlier 1,809/716 totals are not the publication gates.

## Negative/custody witnesses

- Exact resource only. Remote/alias/query/wildcard/device-enumeration/key/command scope refuses. Platform, elevation and expiry guards prevent query.
- Portable ABI fixture checks four fixed uint32 values/16 bytes, System32 loader/prototype, zeroed output and uint32 TBS result rather than BOOL/GetLastError. It is not real Windows ABI/lifecycle evidence.
- Missing TPM/service/library/export and unknown native statuses yield gaps. Unknown layout/specification refuses. Native buffer and selected JSON budgets charge before their respective steps; a native-buffer limit refuses before query.
- Reserved values cannot become manufacturer/firmware/interface-origin facts. Unknown fact fields, promoted algorithm/runtime/capability, wrong scope/platform/identity, duplicate fact and changed selected JSON/receipt commitments fail validation.
- A hand-authored **portable** expected-truth plan passes exact specification/layout/false-capability assertions through the existing runner; changed layout/specification/capability and invented firmware expectations mismatch. Unrecognized assertion fields refuse. This is not operator approval or native qualification.
- Authenticated intake/read/export preserve IMPORTED transport, narrow OBSERVED OS metadata and false execution qualification. Cross-tenant/unselected-administrator reads refuse; changed stored originals return integrity refusal.
- Stored reads/CBOM export do not query TBS or create scans/evidence; normal export auditing remains. TPM specification produces zero CBOM crypto components, not NO_CRYPTO.
- Frontend verifies bounded supported metadata fields and rejects malformed layout/specification, promoted use/capability/identity/manufacturer/attestation/firmware/PQC/policy and unknown fields. Its label explicitly denies attestation, firmware or key-use inference.
- `hardware_metadata` mapping and HBOM/TechBOM classification are explicit; no production job is admitted to manufacture coverage from this candidate.

## SDK discrepancy and native boundary

The pinned SDK declares `Info` output and describes `structVersion` as 1. The pinned structure page instead says it must be set to `TPM_VERSION_20`. The candidate follows the output prototype/header and accepts returned layout 1 only; **this unresolved discrepancy is an actual native qualification blocker**, not hidden behind portable PASS. See [guide 75 and pinned sources](../bank-environment/75-phase-three-windows-tpm-device-info-candidate.md).

Native Windows/version/architecture/service/token/ACL cases, actual TPM 1.2/2.0/default virtualized environments, independent OS truth, lifecycle/internal native work/allocation/latency, isolation/cancellation, source approval and separate operator/assessor/bank review remain pending. Caller-buffer/JSON caps are not native wall-clock/RSS/OS-allocation guarantees. A version metadata hash is not a TPM quote or host authenticity.

Broader CAPI/CNG, negotiated TLS/listener relationships and justified firmware/hardware identity remain Phase 3 work. Full later container/network/cloud/HSM/vendor/correlation/hardening phases are not declared complete. No complete six-BOM inventory, performance improvement, HA/DR, SLA or site acceptance follows.

## Validation environment and disclosed diagnostic

Fresh dependencies were installed from this repository's unpinned requirements; they differ from earlier validation environments and are **not claimed to match a deployed release lock**. Retained package list/toolchain provide reproducibility context without credentials. Requirements/lockfiles/workflows were not changed to hide this. Local `pip check` and selected regressions pass; release-image/site acceptance remains independent.

The PostgreSQL console retains the baseline pgserver **logging-to-a-closed-pytest-capture-stream `ValueError` during cleanup**. It was not suppressed or represented as a clean console. Tests exited zero; pg_ctl reported server stopped, the owned temporary directory was verified removed and no owned server remained. This is a validation-harness diagnostic, not Windows evidence; unrelated harness/product logging was not rewritten.

Before this increment, the sandbox's older snapshot was reconciled with the already-published baseline using exact ancestor/blob proofs and external backups. The baseline tree was verified clean before TPM implementation. That was recovery of published work, not a new product feature or unexplained deletion.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_windows_tpm_candidate.py services/api/tests/unit/test_windows_cng_candidate.py \
  services/api/tests/unit/test_windows_image_candidate.py services/api/tests/unit/test_windows_certificate_candidate.py \
  services/api/tests/unit/test_linux_phase2_projections.py services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py -q \
  --junitxml=/home/user/windows-tpm-python.xml
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --include-windows-certificate-candidate --include-windows-image-candidate \
  --include-windows-cng-candidate --include-windows-tpm-candidate \
  --junitxml=/home/user/windows-tpm-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

Actual operator-owned Windows packet and opt-in test are in [guide 75](../bank-environment/75-phase-three-windows-tpm-device-info-candidate.md). Approve independent expected truth **before** measurement. Missing Windows/reviewed resource is SKIP, never native PASS. Do not send credentials/private keys or create keys/devices merely for a passing fixture.

## Retained evidence

[`windows-tpm-device-info-candidate-2026-10-25/manifest.json`](windows-tpm-device-info-candidate-2026-10-25/manifest.json) lists source/doc/artifact digests. Console ANSI/trailing whitespace/blank EOF are normalized; XML is verbatim. Hashes support integrity, not authenticity, independent acceptance or signed collector-release approval. Publication uses `[skip ci]`, with no workflow edits; this is not proof every external workflow honors that marker.
