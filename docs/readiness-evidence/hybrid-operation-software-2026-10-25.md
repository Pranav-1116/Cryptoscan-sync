# Local validation — actual hybrid / operation correlation / software truth

2026-10-25 UTC; baseline `7b06710118fa5efd14bad223e543176544df15bd`; branch `arena/bb4b80dd-cryproscan`.

[Guide 81](../bank-environment/81-actual-hybrid-operation-and-software-truth.md) · [Operator packet](../runbooks/hybrid-operation-software-evidence.md) · [Contracts/API](../api-reference/hybrid-operation-software-evidence.md).

## Executed functional witnesses

- **Actual owned TCP hybrid TLS:** both peers completed TLS 1.3, group **X25519MLKEM768 /4588**, `TLS_AES_256_GCM_SHA384`; product collector matched the independently constructed fixture's public DER pin, one literal loopback connection, no application payload. Public provider: pyOpenSSL26.4.0 / cryptography50.0.2 / embedded OpenSSL4.0.3,29Sep2026. Existing stdlib provider is not upgraded. This now goes beyond the earlier in-memory-only proof and Guide80 synthetic hybrid vectors.
- **Actual software operation signatures:** ephemeral Ed25519 challenge plus application/provider log signatures verified against separately supplied distinct public pins; original evidence bound to exact approval/scope/window. No actual customer application/HSM/provider was invoked; hardware/application execution remain unverified. This is a verifier functional witness, not a physical HSM witness.
- **Actual scoped software records:** literal `/var/lib/dpkg/status` **266,494bytes**, **283 installed name/version records**, exact match to a separately invoked read-only `dpkg-query`; source unchanged before/after measurement. Product collection does not invoke dpkg-query. Separate implementation is not independent human review; whole-host/language/runtime/container/firmware coverage remains unverified.
- **Actual availability check:** Linux kernel, no `docker`, `podman`, `wine`, `pwsh`, `softhsm2-util`, `pkcs11-tool` on PATH, no Docker/Podman socket. This is availability evidence, **not native Windows/container/HSM qualification**. No privileged runtime installed or CI/workflow dispatched.

The retained [functional summary](hybrid-operation-software-2026-10-25/functional-witness.json) keeps public hashes/counts/provider strings and explicit limitations, not actual package database contents or signing/private keys. Its [reproduction helper](hybrid-operation-software-2026-10-25/functional-witness.py) is an owned-sandbox engineering helper using ephemeral test fixtures, **not a customer collection packet**. Do not treat its hashes as signer authenticity or independent acceptance.

## Completed gates

Counts overlap, not additive totals.

| Gate | Result | Boundary |
|---|---|---|
| Selected broad Python | **2,388 passed /12 skipped /7 warnings** | All shared/inventory/CBOM/container/keyassure tests,16 collection/host/TLS API modules and two HSM API modules. Not every repository/network-scanner/API test. |
| Skipped broad cases | **10 actual-Windows;2 missing-PyKCS11 adapter fixtures** | Neither category is PASS or actual native/HSM acceptance. Actual new hybrid cases executed with optional provider installed. |
| New Python cases included above | **47** |13 operation signatures/roots/context;12 software/CLI/replay/denominator;14 hybrid transport/CLI/shape;3 legacy HSM boundary;5 hybrid API custody/export/admission. |
| Owned PostgreSQL16.2 | **36 passed /6 warnings** |22 host +5 old TLS +4 selected-group +5 actual-hybrid custody cases. Actual hybrid over owned loopback, disposable DB; no customer/native acceptance. |
| Final affected/control rerun | **207 passed /2 skipped /6 warnings** |Overlaps broad; final hybrid/operation/software/HSM/TLS/API bytes. Skips are missing PyKCS11, not physical HSM proof. |
| Full frontend | **828 passed /67 files** |10 new hybrid-promotion/HSM-label cases; existing UI only, not real-browser/deployed acceptance. |
| TypeScript / Vite | **PASS /PASS** | Local compile/build only. |
| Ruff / format / whitespace | **PASS** |25 changed/new Python files; no workflow changes. |
| pip consistency | **PASS** | Reviewed development virtualenv, not dependency/native/FIPS qualification. |
| Five existing schema reversals +three new schemas | **PASS** | Existing roots exactly reproduce baseline after removing hybrid kind/reason/fact; all old fact shapes/defaults unchanged. All eight match models and Draft2020-12. |
| Existing source lock | **PASS —104 files** |Includes new shared/inventory modules and three new public schemas. Not provider-dependency attestation, native execution or reviewer authenticity. |

Final focused rerun and link/manifest/static proof results are retained alongside the broad logs. The broad gate expanded the previous four test trees/API selection with keyassure/HSM coverage; its extra105 passes are **not all105 newly written cases**. The exact new-case count is47.

## Demonstrated adverse controls

- Missing/unsupported provider refuses before allocating a socket; old wrapper/CLI refuses the new profile without explicit opt-in. Existing offline/bare collection cannot activate networking; both network and offline-host API tunnel authorization remain denied.
- Actual classical fallback completes no hybrid success; wrong peer pin leaves no positive fact/export; one connection/no implicit retry. CLI acknowledgement/output reservation/no-overwrite are exercised on actual hybrid TCP.
- Re-sealed false completion, classical group/provider, promoted readiness/application use, measured-execution claim and wrong hybrid share size reject. Existing public framing/HRR/byte/expiry guards continue through regression. New subtype contributes exactly CBOM/NBOM/TechBOM, not invented SBOM/HBOM/VBOM.
- Stored successful hybrid export works with probing patched to fail, validates official CycloneDX1.6, creates no new scan/evidence and audits successful export only. Wrong tenant/unselected platform admin, changed original evidence and forced official-schema failure refuse.
- Operation signature, both logger signatures, exact application/key/operation/nonce/approval digests, roots, time window/future event and unknown/private fields are tested. Atomic local replay/no-overwrite refuse; the verifier never calls a provider. Software-only signatures do not promote physical/app execution.
- Agreed software denominator includes every approved package input. Missing/extra/duplicate/version/source-hash/input/source-kind/manifest and failed-source cases cannot become completeness. Retained comparison works after original package source deletion, proving no rescan.
- Legacy HSM nonempty fake signature stays explicitly unverified; challenges differ per call; pre-scrub private exposure stops further operation and discards attributes; error text does not retain synthetic credentials. Existing HSM UI labels reported metadata/unverified receipts instead of “proves in-boundary use.”

## Honest incompleteness

Actual Windows/operator returns, independently bound real container images/runtime/limits and physical HSM/customer application evidence were not available. Existing packets, expected truth and independent review/admission remain required. The new Ed25519-only public verifier does not parse arbitrary RSA/ECDSA/vendor audit formats, certify enrollment/custody or attest application execution. Local ledger is not distributed replay prevention. Expected package truth remains operator-supplied/not independently authenticated; matching283 records is not complete estate software coverage.

No all-capability/all-protocol claim, application/physical-HSM edge, complete six-BOM inventory, production network job admission, native resource/cancellation guarantee, FIPS/readiness/side-channel proof or performance improvement is asserted. User's agreed p95/p99/>=20% performance targets were not measured by these correctness tests. Workflows/CI remain untouched; publication uses `[skip ci]`.

## Development notes / warning debt

An initial hybrid CLI test omitted the existing required acknowledgement; it correctly refused without TCP and the test was fixed to exercise the intended profile refusal. An initial UI test used the wrong existing label/receipt shape; it was corrected to use the existing private-scope/stored-response harness. The final full frontend, not that failed attempt, is retained. Final review also made failed software inputs report unknown (`observed_records=null`) with no missing/unexpected assertions; only committed PARSED sources receive record deltas. The full Python gate was rerun after that hardening. Malformed reseal test dictionaries initially triggered extra certificate serializer warnings; tests now preserve typed certificates.

The seven broad warnings are existing API/dependency deprecation/shadow notices plus the deliberate malformed OCI resealing serializer warning. Two PyKCS11 fixtures remain skipped because PyKCS11 is absent, separate from the10 Windows skips. No warning-free/native/production claim. Owned PostgreSQL exited zero, reported cleanup, and no owned DB directory/process remains. No customer deployment was touched.

## Reproduce

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
# Optional provider must be installed in this reviewed interpreter to execute actual-hybrid cases.
python -m pytest shared/shared_models/tests services/inventory/tests services/cbom/tests \
  services/container_scanner/tests services/keyassure/tests -q
python -m pytest services/api/tests/unit/test_tls_hybrid_candidate.py \
  services/api/tests/unit/test_hsm_check_live_mode.py services/api/tests/unit/test_hsm_ct_scan_runs.py -q
python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-tls-session-candidate --include-tls-key-share-candidate \
  --include-tls-hybrid-candidate --junitxml=owned-hybrid-postgres.xml
cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build
```

The PostgreSQL acknowledgement preserves the existing disposable/synthetic-custody harness boundary; its hybrid connection is real TCP but owned, not a customer/native qualification. Optional-provider tests skip on environments without the reviewed provider; never count those as executed hybrid success. The retained schema proof and SHA manifest pin source/artifacts for review, not authenticity.
