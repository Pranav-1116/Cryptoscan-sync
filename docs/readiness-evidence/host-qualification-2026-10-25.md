# Native evidence, TPM quote verification and independent qualification — 2026-10-25

**Delivered: executable qualification/verification packet. Not delivered: genuine positive native systemd/DMI/TPM/Windows evidence, verified hardware origin or independent full-worker production clearance.** Those require approved external environments and actual reviewers. Nothing in this increment converts absent devices, a software signature or a signed assertion into those results.

[Operator guide 67](../bank-environment/67-native-quotes-and-independent-qualification.md) contains commands, formats, scope, recovery and external handoff requirements. Published base: `a932bd06457bf71608419adb391e5c886b4b5152`.

## Built and exercised

1. **Original native capture:** existing explicit ordinary-user collectors, pre-supplied target/expected-truth commitments, retained typed snapshots and real category requirements. Windows must run on Windows; all approved inputs must match, not just a generic PASS field. Systemd/DMI/TPM metadata and narrow Windows SCM/OS coverage are distinct from full OS/worker qualification. Source-lock hashes are explicitly operator-supplied identifiers, not running-code measurements.
2. **TPM 2.0 quote verifier:** raw TPMS_ATTEST/TPMT_SIGNATURE parsing with strict bounds; approved AK PEM/qualified signer, SHA256 PCR bank/selection/values/composite, safe clock, reset/restart and firmware policy; RSASSA RSA-2048/3072/4096 and P-256 ECDSA. Unsupported algorithms, malformed/trailing data and invalid signatures refuse.
3. **Challenge/replay lifecycle:** random verifier nonce, maximum five-minute aware interval, tenant/host/policy/target/source/snapshot/worker-claim binding; Linux owner/mode/no-follow state checks; atomic one-time consumption with a durable retained report. Two concurrent valid submissions accept once. Invalid signatures do not consume. Output-copy failure is recoverable from the accepted marker, not by replay.
4. **Independent external record verification:** complete native + worker/host/custody/recovery/adversarial matrix, exact SHA256-addressed original artifacts, pre-pinned native plans/source identifiers, and separate approved assessor and bank-acceptor signatures over policy/index/release/tenant/campaign/check/time commitments. Missing/changed artifacts, unknown/reused identity/key, invalid signature, native gaps, unresolved checks and expired/future review block acceptance.
5. **Eight strict public schemas**, three CLIs and an operator guide. No private signer, TPM key creation, device simulator, automatic enrollment, remote discovery, new fleet service, production profile or database migration is introduced. All six BOM observation/provenance rules remain unchanged.

A valid quote under an operator-pinned AK does **not** prove the key was generated/protected by a TPM. EK certification/credential activation, measured boot/event-log/executable/dependency provenance and protected custody are not implemented here. Binding a snapshot hash into a quote does not prove the collector produced it correctly or that its facts originated on that host. TPM clock checks are not attested UTC. `hardware_origin_verified`, `measured_executable_verified` and `attested_utc_clock` remain false.

The review verifier proves which approved keys signed which retained bytes. It cannot establish organizational independence, employment, truthfulness, deployment properties or operational completeness from arbitrary worker logs. Non-native worker/host/custody checks remain explicitly external reviewer assertions over their evidence. Both `full_worker_production_clearance` and `production_execution_qualified` remain false; existing production admission is not modified.

## Final validation

| Gate | Result |
|---|---|
| Selected shared-model/native-inventory regression | **922 passed, 3 Windows-native skipped**, 0 failures/errors, 28.30 s |
| New protocol/CLI cases within that regression | **89 passed**; software-generated cryptographic/native-record positives, not genuine hardware qualification |
| Public contracts | **8** schemas match their model schemas and pass Draft 2020-12 schema checking |
| Ruff / pip consistency | **PASS / PASS** |
| Full API/PostgreSQL/frontend suites | **Not rerun**; no earlier counts relabeled as current results |
| Genuine positive TPM/Windows/independent acceptance | **Not available / not supplied** |

Artifacts: [Python log](host-qualification-2026-10-25/python.txt), [JUnit](host-qualification-2026-10-25/python.xml), [validation metadata](host-qualification-2026-10-25/validation.json), [Ruff](host-qualification-2026-10-25/ruff.txt), [pip consistency](host-qualification-2026-10-25/pip-check.txt), [isolated validation environment](host-qualification-2026-10-25/validation-environment.txt), [source/artifact commitments](host-qualification-2026-10-25/manifest.json).

The validation environment was rebuilt for this workspace, not installed into a customer environment. An initial broad run passed 919 tests but failed one existing graph-classifier import because `pydantic-settings` was absent. Installing that already-declared dependency and rerunning produced the final zero-failure result above. Two later issuer-boundary cases are included in the final 922-pass/89-new count. No product dependency manifests were changed to fix the environment.

## Actual current-host evidence, not simulated native positives

[Read-only replay](host-qualification-2026-10-25/run-environment-witness.py) and [actual output](host-qualification-2026-10-25/environment.json) use the new native-capture CLI with explicitly scoped engineering-negative plans:

| Requested native category | Actual result here |
|---|---|
| Named systemd `dbus.service` | Exit **2**; UNAVAILABLE / INTERFACE_UNAVAILABLE; zero facts |
| DMI metadata | Exit **2**; UNAVAILABLE / NOT_FOUND; zero facts |
| TPM0 metadata | Exit **2**; UNAVAILABLE / NOT_FOUND; zero facts |
| Windows category on this Linux host | Exit **64**; refused, no native artifact |

Those diagnostic plans are not independently approved acceptance plans. No bus/device/Windows runtime was installed or simulated to manufacture a pass. Temporary public artifacts are created in an owned directory and removed; the recorded cleanup check found no remaining owned environment-witness directories. Public-only test signatures use disposable in-memory keys. No private key, login credential, EK certificate or customer evidence is persisted in this bundle.

Cryptographic positives in tests are intentionally software-generated RSA/ECDSA quote structures and Ed25519 review fixtures. The assertions explicitly check that successful signature verification does **not** set hardware-origin, organizational-independence or production-clearance flags. Native-record fixtures likewise test parser/commitment/decision logic, not execution on Windows, systemd or a TPM.

## Negative controls

- Freshness: expired, future and naive verifier time; oversized/invalid challenge lifetime; exact tenant/host/policy/target/source/snapshot/worker-claim/campaign/nonce/challenge-ID binding.
- Quote semantics: wrong magic/type/signer/extraData, PCR bank/count/mask/selection/composite, unsafe/changed clock/reset/restart/firmware, truncated/oversized/trailing bytes, changed signature/key/algorithm and PCR policy aliases.
- State/IO: bad directory mode, symlink/hard-link challenge, path traversal, changed challenge identity, oversized state, bounded regular public reads, duplicate consumption, failed output copy and no consumption on signature failure.
- Independent review: changed/missing/extra artifacts, absent/repeated/unknown reviewer, identical reviewer key, missing role, signed rejection/FAIL/NOT_RUN, stale/future review, wrong tenant/campaign/release/policy/index, changed native plan/source identifier, cross-category evidence and native gaps even when review statements are re-signed by trusted disposable test keys.
- Native capture: original retained receipts rather than a self-reported pass; exact target/plan/snapshot/window/category; strict scalar type matching; missing TPM does not become absence/qualification, and Linux cannot satisfy native Windows capture.

## Repository preservation and publication scope

The restored workspace initially showed 1,752 pending paths because its local Git index/HEAD described the original supplied checkout (`d70bdf3f`), while working files represented the already-published session tip. The remote session branch was verified as `a932bd06`. Git metadata/index were aligned to that precise published tip using **mixed, not hard, reset**. SHA-256/link/missing-state comparisons verified **4,321 working paths unchanged** by that operation. There were no staged user changes; after reconciliation only this increment's new files remained pending. No user files, workflows, deployments, package manifests or existing implementation files were reverted or rewritten.

This packet changes only new verification/capture/IO/test/schema/document/evidence files and the bank guide index/acceptance ledger. Source and artifact hashes are provenance/integrity commitments, not independent authentication of this report or acceptance by a bank.

## Replay and the next required external step

From the repository root, approved validation Python on PATH:

```bash
PATH=/home/user/qualify-venv/bin:$PATH \
  bash docs/readiness-evidence/host-qualification-2026-10-25/run-tests.sh \
  --junitxml=/home/user/qualification-replay.xml
/home/user/qualify-venv/bin/python \
  docs/readiness-evidence/host-qualification-2026-10-25/run-environment-witness.py
```

Do not point the native replay at customer systems or silently broaden its resources. The next operational step is execution on approved ordinary-user Linux systemd/DMI/TPM2 and Windows hosts, using independently agreed expected truth and externally established public AK/PCR policy; then real assessor/bank-acceptor signatures and a full deployed-worker assessment. Request only public evidence exports—not private keys or host/GitHub credentials. The supplied tools can verify those artifacts when provided, but this local run cannot replace them. No Phase 4/production adapter is enabled, and no whole-bank coverage, crypto/PQC invocation, SLA/uptime, performance improvement or customer acceptance is claimed.
