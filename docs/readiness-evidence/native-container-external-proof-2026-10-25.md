# Local validation — native container and external proof paths

2026-10-25 UTC. Baseline `a434e5eb3415c4506563a833d105b7b9f1c7e0b5`; branch `arena/bb4b80dd-cryproscan`.

[Guide82](../bank-environment/82-native-container-and-external-proof-paths.md) · [Operator packet](../runbooks/native-container-and-external-proof-paths.md) · [Contracts](../api-reference/native-container-and-external-proof-paths.md).

## Actually executed

**Real ordinary-user Linux namespace-container execution, not just OCI parsing.** The host has no Docker/Podman, but unprivileged user namespaces and private mount/PID/network/IPC/UTS namespaces were available. The new fixed-scope runner compiled its owned static C fixture, constructed a real OCI layout, checked layer/diff-ID/package truth with the existing product collector and actually ran the fixture as PID1 in a read-only chroot with six distinct namespaces.

Normal and held runs passed: own executable inode, predefined package database bytes, outside sentinel denied, root write EROFS, socket/mount EPERM, effective capabilities zero, no-new-privileges,256MiB allocation denied under128MiB AS and excess FDs denied under32-FD limit. The held child was killed through a pinned pidfd after ancestry recheck, reaped, and the owned directory removed. CPU2s limit was configured, not CPU-exhaustion/throughput measured. This is the exact tiny trusted fixture, **not a Docker/Kubernetes/customer arbitrary-code executor or production sandbox certificate**.

**Actual software RSA PKCS#1/SHA256, RSA-PSS/SHA256 and P-256 ECDSA/SHA256 operation signatures** and both Ed25519 application/provider logger signatures verified. SDK adapter tests used injected clients and actual software signatures, not a real AWS account/physical HSM. Wrong algorithm/key/context/signature/time/roots refuse; the live tool's durable attempt fence prevents retry after an ambiguous provider/SDK failure.

**Signed two-asset ×six-surface fixture register** reconciled12 REQUIRED units with original byte commitments. This is a public signed-claim fixture, **not actual whole-estate data** or producer measurement/organizational authority proof. Missing returns produce unknown counts and a blocked report; no zero-software inference.

**Not executed:** customer application/provider endpoint, physical HSM, native Windows, Docker/Kubernetes/customer container release, authoritative real estate closure, independent assessor/bank acceptance or production admission. No credentials/private keys, privileged runtime install, customer change or workflow/CI dispatch. Existing Windows skips are not PASS.

## Completed gates

Overlapping gates, not totals to add.

| Gate | Result | Boundary |
|---|---|---|
| Selected broad Python | **2,433 passed /12 skipped /7 warnings** | All shared/inventory/CBOM/container/keyassure tests,16 collection/host/TLS API modules and two HSM API modules. Actual new namespace test explicitly enabled and executed. Not every repository/API/scanner test. |
| Skips | **10 actual-Windows;2 missing-PyKCS11 adapter fixtures** | Not native Windows, PKCS#11 device or hardware qualification. |
| New Python cases | **45 passed** |Operation-v2 public crypto/context/keys; exact approved SDK mechanisms; two-asset six-surface source/signature/denominator controls; CLI/replay/refusal; actual native namespace/cancel/cleanup. |
| Final affected rerun | **131 passed /2 skipped /6 warnings** |Final proof/legacy HSM/v1/CLI controls including actual namespace run;2 PyKCS11 skips, not hardware evidence. |
| Owned PostgreSQL16.2 | **36 passed /6 warnings** |Existing host/TLS/actual-hybrid custody parity; no new API/service/production admission. Cleanup confirmed. |
| Full frontend | **828 passed /67 files** |Existing UI unchanged; regression only, not browser/native acceptance. |
| TypeScript /Vite | **PASS /PASS** |Local compile/build, not release clearance. |
| Six new schemas /all18 previous schema bytes | **PASS** |New schemas match models/Draft2020-12. Every previous schema—including v1 operation and old facts—is byte-for-byte baseline-identical. |
| Existing collector source lock | **113 files** |Includes three new shared modules and six schemas; not SDK/native-dependency/host attestation. Qualification scripts/C fixture remain engineering artifacts pinned separately by plan/artifact hashes, not a qualified worker release. |
| Ruff /format /C warnings /whitespace /pip | **PASS** |Changed Python files/helpers; C fixture compiled static with Wall/Wextra/Werror. No base requirements/lock/workflow change. |

The native report retains its **original typed HostSnapshot and predefined plan**, their canonical commitments, source/image/binary hashes and both actual child observations. A final standalone CLI run and original snapshot/plan commitment check passed after embedding those originals. The final affected rerun covers final report bytes. No static binary/image/private signing key or large package dataset is retained in Git.

## Adverse controls exercised

- V1 remains accepted only under v1 approval and keeps old schemas/defaults; v2 does not accept evidence-selected trust roots. Public DER private material, wrong public fingerprint/key/context/mechanism/nonce, forged operation/logger signatures and expired/future event refuse.
- Exact immutable ARN/region and explicit approved algorithm required before provider work; missing supported algorithm makes no Sign call. Nonempty invalid signatures/changed algorithms cannot be success. Failed SDK initialization consumes one authorization attempt; repeat attempt makes no new SDK call; synthetic credential-like exception text is withheld.
- Register cannot omit assets/surfaces, duplicate units, change register hash or make all units N/A. Duplicate/foreign/future/cross-plan/cross-release returns, wrong producer signatures, corrupted/extra sources refuse. Missing returns leave all observed counts null and overall coverage blocked.
- Existing outputs cannot be overwritten; wrong approved hashes refuse before SDK/namespace work; v2 operation replay uses the existing durable local ledger. Hash/source checks are integrity and scope binding, not authenticity or measurement attestation.
- Actual namespace case requires explicit `CRYPTOSCAN_RUN_OWNED_NAMESPACE_TEST=1`; absent opt-in is a skip, never an executed PASS. Failed compiler/platform/kernel/control/truth/cleanup refuses. Source copies/hash checks precede compilation; executable namespace/rootfs assertions precede result creation; cancellation signals a pinned owned child, not an arbitrary recycled PID.
- Existing Windows/container admission allowlists remain closed. Generic estate signed records/supporting reports create no observed facts, standard BOM claim, HSM-use edge or software/estate completeness flag.

## Development notes and retained limits

Initial native tool preflight exposed that chroot was present at `/usr/sbin/chroot` but not on PATH. An initial URI omitted the existing required OCI `local/` selector and was refused; it was corrected before successful collection/execution. Wall/Wextra/Werror exposed a signed-size comparison in the new C fixture, corrected before the passing run. A new model field originally shadowed `register`; it was renamed `asset_register` before publication, avoiding a new warning.

The seven broad warnings are existing API/dependency deprecation/shadow notices plus the deliberate malformed OCI serializer warning; no warning-free production claim. Actual namespace fixture is AMD64/Linux only, needs permitted rootless namespaces/static toolchain/pidfds, and does not certify general seccomp syscall completeness, hostile compiler inputs, native dependency integrity or arbitrary-code escape resistance. Output/FD/AS/cancellation assertions belong to this known payload; CPU performance and user's p95/p99/>=20% improvement targets were not measured.

Software surface records are signed producer claims; their generic source semantics are not auto-parsed/attested. A valid signature cannot establish physical HSM residence or customer application truth. External actual hardware/vendor/model/firmware audit, authoritative estate/exception registers, actual Windows execution and separate independent reviews remain required. No workaround changes those requirements.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
CRYPTOSCAN_RUN_OWNED_NAMESPACE_TEST=1 python -m pytest \
  shared/shared_models/tests/test_operation_evidence_v2.py \
  shared/shared_models/tests/test_software_estate.py \
  services/keyassure/tests/test_approved_operation_capture.py \
  services/inventory/tests/test_owned_namespace_container.py \
  services/inventory/tests/test_external_proof_clis.py -q
python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-tls-session-candidate --include-tls-key-share-candidate \
  --include-tls-hybrid-candidate --junitxml=owned-proof-postgres.xml
cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build
```

See the [operator packet](../runbooks/native-container-and-external-proof-paths.md) for reviewed-plan-first native/live/estate commands; do not use the engineering witness generator as a customer collector or copy its ephemeral fixture public roots into a real approval. Retained logs/JUnit/public vectors/source-lock/schema proof and SHA manifest provide local reproducibility/integrity only, not independent native/physical-HSM/bank acceptance.

## Retained public artifacts

[Original public functional vectors/native snapshots](native-container-external-proof-2026-10-25/functional-witness.json) · [standalone native CLI return](native-container-external-proof-2026-10-25/native-cli-result.json) · [source/artifact integrity manifest](native-container-external-proof-2026-10-25/evidence-manifest.json). Twenty-three retained files include the helper source, public vectors, original typed snapshots/plans, logs/JUnit, schema/source-lock/static/pip/cleanup/link checks and manifest. The manifest is integrity, not signer authenticity or acceptance.
