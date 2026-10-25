# Local readiness — bounded Windows metadata and operator preflight

2026-10-25 UTC. Baseline `72a440d42b0ea0a26f85bcc4c7f7e0a421558f31`; branch `arena/bb4b80dd-cryproscan`.

## Decision

Publish a bounded Phase 3 engineering increment, **not completed Windows qualification, a completed container adapter, all-ten-phase delivery or production clearance**. Reuse existing collection/custody/projections/console/assigned-human workflows.

Delivered:

- Exact current-user legacy CAPI default-provider selection for five named types, no context/provider/key acquisition or mutation.
- Five more fixed-provider user-mode CNG registration interfaces (seven total), retaining existing bounded pointer/buffer/source guards and UNKNOWN use/capability semantics.
- Exact local IPv4/IPv6 owner-PID TCP listener table capture, fixed native layouts, two bounded samples and strict selected metadata/rows. No packets/sockets/process opening, TLS, process incarnation or application-use edge.
- Existing native CLI preflight/binding with independently reviewed target/plan/source identifiers, strict public schema and explicit false native/independence/production/container claims. It dispatches nobody and is not NativeEvidence.
- API custody/tenant/tamper/export/admission tests, UI display/refusal, schema/expected-truth extensions and operator packet documentation. No service/table/dashboard/execution endpoint/migration.

## Final completed local gates

Counts overlap; do not sum them or translate them into phase-completion percentages.

| Gate | Result | What it does not prove |
|---|---|---|
| Selected Python regression | **1,947 passed; 10 skipped** | Not all Python/API tests. Ten actual-Windows cases skip on Linux; no Windows native success is claimed. |
| Owned disposable PostgreSQL | **98 passed** | Portable Windows seams, not real Windows or customer database qualification. Owned server stopped/temp directory removed. |
| Full frontend | **744 passed / 62 files** | Includes 89 host-evidence-panel cases; not deployed bank acceptance. |
| TypeScript / Vite build | **PASS / PASS** | Local build, not an approved release image. |
| Ruff check/format / pip consistency | **PASS / PASS** | 21 changed/new Python files and current validation environment, not a release-lock/site certification. |
| Schema/model/compatibility | **PASS** | Five additive v1 schema updates plus new preflight schema; Draft2020-12/model equality. Removing only new input/union/definition/five CNG-interface values exactly reproduces baseline; old fact defaults remain unchanged. |
| Source-lock inclusion | **PASS** | Existing builder includes new modules/preflight schema (87 files), not an externally signed release or measured source execution. |

Within the Python total are **137 added portable passes**: 79 CAPI/TCP reader/model/guard, 25 preflight/truth/CLI, five extended-CNG and 28 API contracts. Three new opt-in actual-Windows cases account for the increase from seven to ten skips. Twenty-eight new PostgreSQL and 24 frontend cases are already within their totals.

After the initial selected run, preflight was hardened so source digest and shape validation use the **same read's immutable bytes**, not a second path read. A no-native/token-call, one-read witness was added and the final full selected Python suite was rerun. The earlier 1,946 total is not the publication gate; unchanged API/database and frontend code retain their completed gates.

## Negative/control evidence

### Native readers and normalization

- Exact local resource/type/family only; remote/encoded/query/trailing-slash/key/command/wildcard alternatives refuse. No global provider discovery, explicit machine-context retry, key context, TCP connection-state/UDP/module table, remote host or active probe.
- CAPI prototype/System32/BOOL/GetLastError/UTF-16 byte lengths and all five provider-type mappings are portable ABI fixtures. Missing DLL/export/default metadata and access denial remain explicit gaps. Odd/over-budget/growing/unterminated/embedded-NUL/invalid-UTF16/control-character labels or changed samples refuse.
- CNG fixture covers the five new interface constants using the existing caller-owned buffer parser. Registration labels still produce no algorithm/capability/use claims.
- TCP portable fixtures cover 24-/56-byte layouts, Windows AF=2/23, owner-PID listener class, direct uint32 error, size/span/count/state checks, low-WORD network-order ports including ignored high bits, IPv4/IPv6 and empty tables. Oversized/truncated/growing/non-listener/changed/invalid-length/null-query-success results refuse. Missing/denied/unknown interface never becomes NO_NETWORK.
- Pre-query, post-query selected-JSON and total budgets refuse without a partial positive. Platform/elevation/expiry guards prevent native calls. Caps do not prove bounded internal native activity, allocation/RSS or latency/cancellation.
- Strict fact/snapshot validation refuses changed source digest/receipt commitment, scope/type/family/platform, duplicate facts, invented firmware/identity/algorithm/runtime/capability claims. Table rows/count/canonical uniqueness and selected JSON reconstruct independently.
- Empty successful tables retain one query-metadata fact with zero rows and false absence/TLS/process-identity flags, not a manufactured endpoint. A reported PID is not an executable/process incarnation or application relationship; stable samples are not atomic/continuous truth.

### Preflight and independent expected truth

- Pure preflight binds canonical target/plan and exact source-file identifier before acquisition, requires existing OS/SCM scope and explicit new-metadata expectations, validates bounded flat TCP rows and refuses promoted/ill-typed/unknown assertions.
- Canonical TCP truth accepts only four known scalar fields, supported canonical IP/scope/port/PID bounds, ≤256 unique sorted rows; arbitrary/nested/list/duplicate/boolean-numeric/scoped-IP assertions refuse.
- Changed plan/source/target commitments, missing OS/expected inputs, missing exact rows, wrong counts, promoted TLS and nested rows refuse. Changed retained packet refuses; exclusive output prevents overwrite.
- CLI preflight succeeds without Windows, native token checks, collection or dispatch and emits only `PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR`. Its four clearance/execution claims remain false. A Linux native invocation produces no fake Windows evidence.
- Fixture-runner roundtrips include new facts/row assertions and mismatch refusal. These are hand-authored/model-derived **portable synthetic witnesses**, not independent operator expected truth or native approval.
- Source-lock shape/path/digest checks use one source read, but the identifier is still operator supplied. It is not proof that execution used the reviewed code; external signing/verified staging/worker provenance remain separate gates.

### Product custody, UI and admission

- Tenant-scoped approval/intake/stored reads/export retain IMPORTED transport, narrow OS claims and false Windows qualification. Foreign/unselected-administrator reads refuse. Changed stored originals refuse integrity.
- Stored reads/export invoke no CAPI/TCP/CNG code and create no scans/evidence; normal CBOM export audit remains. Selection/registration/table metadata creates zero CBOM crypto components, not NO_CRYPTO.
- UI refuses invalid/promoted/unknown provider/table fields, counts/family/row bounds/duplicates, TLS/process-identity/absence/policy claims. It supports new CNG interfaces, explicit empty tables and IPv6 scope, shows at most ten table rows and retains explicit metadata-only limitations.
- Universal Windows authorization remains 409/future capability for new inputs. Separate negative tests retain the same refusal for container/network/cloud/HSM/hardware/vendor methods. No preflight result activates another phase or production execution.

## Environment and disclosed diagnostic

Uses the existing recreated validation venv installed from unpinned requirements; packages/toolchain are retained. Passing pip consistency/regressions is **not** proof it matches a deployed signed release lock. Requirements, lockfiles and workflows were not changed to hide dependency drift.

The owned PostgreSQL console retains the baseline pgserver **logging-to-a-closed-pytest-capture-stream `ValueError` during cleanup**. It is not suppressed or represented as a clean console. Tests exited zero, pg_ctl reported server stopped, `/home/user/cryptoscan-host-witness-cvwfmvnb` was verified removed and no owned server remained. This unrelated harness diagnostic is not actual Windows evidence or a reason to manufacture a native PASS.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_windows_metadata_candidates.py services/api/tests/unit/test_windows_tpm_candidate.py \
  services/api/tests/unit/test_windows_cng_candidate.py services/api/tests/unit/test_windows_image_candidate.py \
  services/api/tests/unit/test_windows_certificate_candidate.py services/api/tests/unit/test_linux_phase2_projections.py \
  services/api/tests/unit/test_linux_software_inventory.py services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py services/api/tests/unit/test_host_evidence.py \
  services/api/tests/unit/test_host_worker.py -q --junitxml=/home/user/windows-next-python.xml
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --include-windows-certificate-candidate --include-windows-image-candidate \
  --include-windows-cng-candidate --include-windows-tpm-candidate --include-windows-metadata-candidates \
  --junitxml=/home/user/windows-next-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

## Actual operator and advancement status

[Guide 76](../bank-environment/76-bounded-windows-metadata-and-operator-preflight.md) and the [operator runbook](../runbooks/windows-bounded-qualification-packet.md) are the handoff, not proof somebody ran it. Actual named assignments, approved fixtures/time/expected truth, secure channel, genuine native returns and separate independent decisions were not supplied or executed in this engineering session. No credentials/private keys were requested; no customer deployment changed and nobody was automatically contacted.

Remaining native compatibility/version/architecture/token/ACL/service/failure/lifecycle/internal work/latency/isolation/cancellation checks and the TPM SDK/documentation discrepancy stay open. Firmware/hardware identity, negotiated TLS and stable application/process/listener/crypto-use relationships require additional justified evidence. This increment does not claim all possible Windows surfaces are implemented.

**Container universal advancement was not performed past the missing Windows gate.** Existing container/network/cloud utilities remain reusable, not newly completed universal adapters. Subsequent phases need their own exact scope, parser/authorization/evidence safety and acceptance contracts. No complete six-BOM inventory, attested host/physical device, performance improvement, HA/DR/SLA or bank acceptance follows.

## Retained artifacts

[`windows-bounded-metadata-2026-10-25/manifest.json`](windows-bounded-metadata-2026-10-25/manifest.json) commits source/doc/test-artifact digests. Console ANSI/trailing whitespace/blank EOF normalized; XML verbatim. Digests support integrity/review, not authenticity, independence or release signatures. Publication uses `[skip ci]` without workflow changes; not a claim that every external workflow honors the marker.
