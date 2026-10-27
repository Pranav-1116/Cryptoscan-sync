# Local readiness — approved single TLS session candidate

2026-10-25 UTC. Baseline `eaf1902cad138aee0826ea6ee6331a2b7c95d6be`; branch `arena/bb4b80dd-cryproscan`.

[Implementation/limits](../bank-environment/79-approved-single-tls-session-candidate.md) · [Operator packet](../runbooks/approved-single-tls-session-candidate.md) · [API](../api-reference/tls-session-candidate.md).

## Decision: next missing engineering delivered, production remains blocked

The existing foundation/Linux/Windows/container candidate work was not rebuilt. Add the missing Phase 5 **single approved negotiated TLS session**, reusing existing public certificate parsing, host receipts, evidence custody, six projection classification, official CycloneDX validation and existing UI. No new database/service/dashboard/dependency/workflow, bank endpoint, credentials/private keys or production configuration change.

All active test connections were to generated synthetic certificates on disposable **owned loopback** TLS servers. This is real local TLS transport, not actual bank/Windows/production qualification. Evidence shape, hashes and a signing key do not authenticate an originating executable/host or prove full external target consent.

## Completed validation

Counts overlap; do not sum gates or turn them into phase-completion percentages.

| Gate | Result | Scope / limitation |
|---|---|---|
| Final selected broad Python | **2,235 passed; 10 skipped; 7 warnings** | Shared models, all inventory/CBOM/container tests and 14 selected host/collection API modules. Not every Python/API/network-scanner test in the repository. Ten native-Windows cases skip on Linux, not PASS. |
| Final focused TLS | **54 passed; 6 existing API warnings** | 49 inventory/model/CLI/engine/budget/negative cases and five SQLite custody/export/admission cases; included in broad count. |
| Expanded owned PostgreSQL 16.2 regression | **229 passed; 6 existing API warnings** | All existing host/association/foundation/worker/qualification/surface/Linux/Windows/container optional parity flags plus five new TLS cases. More historical modules were selected than in the prior 112-case container run; **not 117 new TLS cases**. |
| Final owned PostgreSQL host+TLS follow-up | **27 passed; 6 existing warnings** | 22 host custody regressions plus all five TLS cases after final engine/error-classification changes; same cleanup diagnostic, zero exit and owned directory removed. |
| Full frontend | **802 passed / 64 files** | 22 new TLS metadata/promotion/profile/snapshot/offline-export cases plus existing suite. Not real-browser/deployed acceptance. |
| TypeScript / Vite build | **PASS / PASS** | Local compile/build, not an independently approved release. |
| Ruff / format / whitespace | **PASS** | 19 changed/new product/test Python files. No workflow/requirements/dependency-lock edits. |
| pip consistency | **PASS** | Current qualification virtualenv, not site/runtime qualification. |
| Five public schema/model/additive checks | **PASS** | Draft2020-12, model equality; exact reversal of only new TLS definitions/unions/input/reason/operation literals reproduces pinned baseline, with old single-operation const restored from enum. All old fact shapes/defaults unchanged. |
| Existing source-lock inclusion | **PASS — 96 files** | Includes both shared TLS contract/setup and inventory TLS engine. No release signature, measured execution, independent approval or admission generated. |

The final 27-case owned PostgreSQL host+TLS follow-up reruns all five TLS cases after final no-certificate/selected-byte-budget diagnostic hardening; see the retained artifacts. The expanded PostgreSQL and frontend runs preceded those narrow engine/budget classification changes. Final selected Python/focused tests recheck final bytes and unchanged valid-session/custody contracts. No bank deployment/performance/SLA/HA/DR clearance follows from these gates.

## Negative/control demonstrations

### Authorization and target

- Require exact numeric endpoint, canonical reviewed SNI, TLS 1.2/1.3 and expected peer SHA-256. DNS/discovery is patched to raise while real owned-loopback TLS succeeds. One connection and exact SNI are observed; no application data is sent.
- Reject DNS destination, noncanonical IPv4/port, unsupported version, wildcard/trailing-dot/uppercase/IP SNI, multicast/unspecified destination and scoped/link-local IPv6. Canonical IPv6 resource parsing is tested; a **real IPv6 connection is not qualified** by that syntax test.
- Reject wrong method/operation/address/environment, credential reference, exclusion, future start and expired approval before allocating a socket. Bare host collection returns active-authority denial; offline-Linux/container wrappers refuse. Network and offline-host-tunneled API authorization both return 409 without probing.
- CLI requires acknowledgment and correct reviewed target hash. Wrong hash, existing output and symlink refuse before active work; exclusive output never overwrites originals. A second invocation cannot silently repeat the probe into the same output.

### Bounded transport and evidence

- Real TLS 1.2 and 1.3 handshakes negotiate against a synthetic RSA-certificate peer without DNS/client identity/application request. Public certificate key metadata stays separate from negotiated suite/group/signature and application use.
- Wrong pin/version, stalled server, low budget and expiry preserve explicit failed receipt/gap with no positive fact/content hash. No retry/fallback/absence claim. Socket context closes on failures.
- Synthetic partial-send/receive accounting consumes exactly the allowed budget and closes the socket; a monotonic-expiry seam stops I/O; pre-socket expiry allocates none. Missing peer certificate is correctly `UNAVAILABLE / TLS_HANDSHAKE_FAILED`, not byte exhaustion.
- Fresh exact-version contexts, no ticket reuse/key log, no CA/hostname validation; forced use/trust/completeness flags, changed byte counts, impossible TLS 1.3 suite/strength, changed certificate scope and resealed out-of-scope facts refuse. Combined wire/DER/selected commitments reconcile.
- NBOM/CBOM/TechBOM only; no SBOM/HBOM/VBOM invention. Other TLS versions, application identity, key-exchange/signature group, runtime/library/HSM use and PQC readiness remain UNKNOWN. Coverage uses the compatible network-evidence slot with actual input kind; no OS-listener/whole-surface claim.

### Custody, export and UI

- Approve before collection, import through existing host custody, then patch probing to fail on any stored read. Export still succeeds from retained originals, validates against official CycloneDX 1.6, creates no new scans/evidence and audits only successful export.
- Separate endpoint service/protocol/certificate references retain original evidence IDs, selected/snapshot/target commitments and IMPORTED versus local OBSERVED provenance. Incomplete composition; no fabricated operational dependencies or complete software inventory.
- Foreign tenant/unselected administrator, changed originals, all-failed sessions and forced schema validation failure refuse; no successful export audit for schema failure/all-failed evidence.
- Existing UI renders one pinned session with CA/hostname/revocation/other-version/group/application limitations; rejects promoted fields and extra nested certificate fields. Explicit export checks live response, exact profile and current snapshot before download. No UI probe/discovery control.

## Development notes, not hidden failures

Initial focused runs passed; Ruff subsequently found one unused test import, removed before the final gates. Documentation index wiring initially referenced nonexistent per-directory README files; no such files were created, and links now use the actual main/bank/readiness indexes. A final review separated a missing peer certificate from size exhaustion and moved TLS engine initialization under its transport-error handler; regression added. Final byte-budget review also moved selected-metadata charging before profile-shape validation, so exhausted combined bytes remain BUDGET_EXCEEDED rather than INVALID; a near-limit regression was added. Final broad/focused/PostgreSQL follow-up gates use that change. One in-progress final regression run was deliberately stopped before restarting against that change; only the completed final 2,235-pass log is retained.

The seven Python warnings are six existing API/dependency deprecations/field-shadow notices and the existing intentional malformed nested OCI resealing serializer warning. The malformed payload is rejected, not accepted as provenance. PostgreSQL retains the existing pgserver closed-capture cleanup logger diagnostic (`ValueError: I/O operation on closed file`); the expanded run reports `server stopped`, 229 passes and zero exit. Its owned `/home/user/cryptoscan-host-witness-jtpma9cl` directory was independently verified absent with no owned server remaining. This is not warning-free production qualification.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests/test_tls_session.py \
  services/api/tests/unit/test_tls_session_candidate.py -q
/home/user/qualify-venv/bin/pytest shared/shared_models/tests services/inventory/tests services/cbom/tests services/container_scanner/tests \
  services/api/tests/unit/test_collection_foundation.py services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py \
  services/api/tests/unit/test_linux_software_inventory.py services/api/tests/unit/test_linux_phase2_projections.py \
  services/api/tests/unit/test_windows_certificate_candidate.py services/api/tests/unit/test_windows_image_candidate.py \
  services/api/tests/unit/test_windows_cng_candidate.py services/api/tests/unit/test_windows_tpm_candidate.py \
  services/api/tests/unit/test_windows_metadata_candidates.py services/api/tests/unit/test_oci_metadata_candidate.py \
  services/api/tests/unit/test_container_content_candidate.py services/api/tests/unit/test_tls_session_candidate.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-associations --include-foundation --include-worker --include-qualification --include-surface-coverage \
  --include-linux-software --include-linux-projections --include-windows-certificate-candidate \
  --include-windows-image-candidate --include-windows-cng-candidate --include-windows-tpm-candidate \
  --include-windows-metadata-candidates --include-oci-metadata-candidate --include-container-content-candidate \
  --include-tls-session-candidate --junitxml=/home/user/tls-postgres.xml
cd frontend && npm test -- --run --maxWorkers=2 && npx tsc --noEmit && npm run build
```

The retained `tls-session-candidate-2026-10-25/schema-check.py` uses the pinned baseline and verifies existing defaults/source-lock inclusion. Logs/JUnit, static/pip/schema results and SHA manifest are engineering records, not externally signed bank acceptance. Final outstanding gates remain independent endpoint truth, actual IPv6/provider/rotation/permissions/resource/cancellation acceptance, reviewed release/executor, full-target external custody and server-owned production admission, plus earlier actual Windows/container qualification.

Final PostgreSQL cleanup: `/home/user/cryptoscan-host-witness-pvji0cj7` absent. No owned PostgreSQL process remained. The 27-case follow-up overlaps the 229-case expanded gate.
