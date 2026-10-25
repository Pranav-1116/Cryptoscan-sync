# Local validation — TLS 1.3 selected-group evidence

2026-10-25 UTC. Baseline `a6fcc06322a6a1192fe560a416ca977272afd81d`; branch `arena/bb4b80dd-cryproscan`.

[Guide 80](../bank-environment/80-tls13-selected-group-evidence.md) · [Operator packet](../runbooks/tls13-selected-group-evidence.md) · [API](../api-reference/tls13-selected-group-evidence.md).

## Delivered scope, not blanket closure

Implement an explicit additive TLS 1.3 public ServerHello selected-group profile through the existing target/receipt/evidence/export/UI pipeline. A real owned-loopback handshake now observes X25519 group ID 29 separately from the RSA certificate and TLS cipher. This closes **that specific negotiated-group unknown**. It does not close application/HSM operation use, complete software coverage, actual hybrid implementation/interoperability, Windows/container qualification, independent bank acceptance or production admission.

No new service/database/dashboard/dependency/workflow, no customer endpoint, credentials/private keys, application request, group/version enumeration or production configuration change. Hybrid codepoint cases are **synthetic parser vectors**, not actual PQC execution. Runtime SSL: **OpenSSL 3.0.20, 7 Apr 2026**; the new profile does not upgrade or qualify that provider.

## Completed gates

Counts overlap and must not be summed.

| Gate | Result | Boundary |
|---|---|---|
| Selected broad Python | **2,283 passed; 10 skipped; 7 warnings** | Shared models/all inventory/CBOM/container tests and 15 selected host/collection API modules; not every repository/API/network-scanner test. Native-Windows skips are not PASS. |
| New checks included above | **44 inventory/parser/model/CLI + 4 API cases** | New classical transport and synthetic hybrid/HRR/malformed vectors; no actual hybrid/native/production acceptance. |
| Owned PostgreSQL 16.2 custody | **31 passed; 6 existing warnings** | 22 host, five prior TLS-session and four new selected-group API parity cases. Not the previous expanded 229-case gate; earlier result remains historical. |
| Full frontend | **818 passed / 65 files** | 16 new selected-group rendering/promotion/raw-structure/download cases; not real-browser/deployed acceptance. |
| TypeScript / Vite build | **PASS / PASS** | Local compile/build, not release clearance. |
| Ruff / format / whitespace | **PASS** | 18 changed/new product/test Python files plus retained schema-proof script; no workflow/dependency-lock edits. |
| pip consistency | **PASS** | Existing qualification virtualenv only. |
| Five model/schema/Draft/additive proofs | **PASS** | Remove only new input discriminator, fact union member/definition: exactly reproduces pinned baseline schemas. All old fact shapes/defaults, including old TLS UNKNOWN fields, unchanged. |
| Existing source lock | **PASS — 97 files** | Includes shared public-wire parser/new fact and inventory transport. Hash/source inclusion is not authenticity, qualified execution or independent approval. |

## Demonstrated controls

- Real owned-loopback TLS 1.3 handshake, exact peer pin, no DNS; one connection; raw final hello group/cipher agrees with engine result. RSA certificate remains separate from observed X25519. Overall PQC/app/operation/server-signature assessment stays UNKNOWN.
- Explicit new kind/resource and `--include-key-share`; old wrapper refuses before connecting. Bare collection cannot activate networking; offline wrapper/API tunneling and all network job authorization refuse. TLS 1.2 resource cannot claim this profile.
- TCP/record fragmentation, HRR as a request only, final selection after retry, compatibility CCS, retry/group/cipher mismatch, repeated retry and zero-record flood limits. Oversized/truncated/duplicate/unsupported extensions, invalid suite and known classical share lengths never produce positive parser evidence.
- Hybrid IDs 4587/4588/4589 use a pinned public OpenSSL registry mapping; unknown IDs stay unrecognized, not presumed classical or PQC-safe. Synthetic share bytes exercise framing/interpretation only, never a functioning KEM claim.
- Re-sealing wrong group ID/name/classification/hash, HRR-as-final, promoted app/PQC readiness/complete-group flags refuses. Combined wire+DER+final-public-hello+selected byte counts reconcile against receipt and existing limits.
- Existing host approval occurs before collection; original snapshot is imported with IMPORTED transport/local OBSERVED claim. Stored export succeeds with probing patched to fail, validates official CycloneDX 1.6, creates no new scan/evidence and audits successful export only.
- Foreign tenant/unselected administrator, changed original evidence and forced schema failure refuse. The new type contributes only NBOM/CBOM/TechBOM, not complete SBOM/HBOM/VBOM or operational dependency fanout.
- Existing UI shows raw-selected group with registry basis and limitations; rejects false group/readiness/use/basis/raw metadata; explicit export must match current snapshot. No new discovery or admission button.

## Development notes and retained warning debt

Initial local wiring placed the opt-in constructor on the wrong adjacent collector; the first direct smoke call correctly failed, and the constructor was moved before the passing transport/tests. No incomplete result was published. Old Windows collector behavior is unchanged and covered by the selected regressions.

Seven Python warnings are the six existing API/dependency deprecation/field-shadow notices plus the existing intentional malformed OCI resealing serializer warning; its malformed payload is rejected. PostgreSQL retains pgserver's existing closed-capture cleanup logging diagnostic (`ValueError: I/O operation on closed file`); tests exit zero, report server stopped and owned directory removal. No unrelated logger/harness rewrite or warning-free production claim.

Raw ServerHello contains public random/compatibility session ID/public key-share bytes, not session secrets. These are still correlation-sensitive metadata and require explicit reviewed retention. Original public target consent, measurement origin, release/provider correctness, native memory/CPU isolation/cancellation and endpoint authenticity are not independently authenticated by a hash or these fixtures.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests/test_tls_key_share.py \
  services/inventory/tests/test_tls_session.py services/api/tests/unit/test_tls_key_share_candidate.py \
  services/api/tests/unit/test_tls_session_candidate.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-tls-session-candidate --include-tls-key-share-candidate --junitxml=/home/user/key-share-postgres.xml
cd frontend && npm test -- --run --maxWorkers=2 && npx tsc --noEmit && npm run build
```

The selected broad gate reuses the previous guide's full four Python test trees/14 API modules and adds `test_tls_key_share_candidate.py`. Retained logs/JUnit, schema-proof script, static/pip results and SHA manifest are local engineering evidence, not an independent native/bank qualification signature. Independent actual endpoints/providers/IPv6/hybrid/HRR/ACL/resource/release acceptance and earlier Windows/container gates remain open. Application/HSM use requires actual time/operation-bound evidence; software completeness requires an agreed multi-surface denominator. See Guide 80's gap-by-gap table rather than treating this one improvement as universal completion.

Cleanup checked: `/home/user/cryptoscan-host-witness-4gjbpdmc` absent. No owned PostgreSQL server remained. The final 102-case focused rerun (six existing API warnings) also passes against final product bytes; it overlaps the broad gate.
