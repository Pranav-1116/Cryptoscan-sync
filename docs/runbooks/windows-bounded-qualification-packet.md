# Operator packet — bounded Windows metadata qualification

**Status: engineering handoff; real operators, real Windows returns and independent acceptance are pending.** This packet does not dispatch work, create user assignments, grant production access or enable containers. Do not send credentials, private keys or TPM authorization secrets.

## A. Required people and prerequisites

Use the existing [assigned-operator workflow](../bank-environment/68-assigned-operator-qualification-workflow.md) and [approved host handoff](approved-host-qualification-handoff.md), not a parallel campaign/service.

1. The bank owner chooses actual active tenant-user assignments, approved fixtures, source release, ordinary-user account, change/time window and bank-approved evidence channel. Assignments do not notify people; the owner must distribute and schedule the work through their actual process.
2. The verifier/reviewer independently agrees expected truth **before the run**. Operators must not generate expected values from the collector output being tested. Use independently reviewed existing fixture facts and retain that review's evidence reference.
3. Preserve OS and named-SCM inputs in the Windows target. Add only exact approved existing certificate, process/module, CAPI/CNG, TPM and/or TCP table resources. Do not manufacture a TPM/key/certificate/listener fixture on a customer deployment.
4. Agree failure cases and expected limitations in an authorized disposable/controlled environment. Do not stop services, change CSP registration, elevate privileges, alter customer devices/firewall or create traffic without separate explicit approval.
5. Retain the reviewed **canonical NativePlan digest** and the SHA-256 of the **exact source-lock file bytes**. These are public integrity identifiers, not approval signatures or evidence that the lock's source actually ran. Source-lock shape/path checks do not replace external release signatures/verified staging.

The target/plan are operator-owned inputs; no live tenant IDs, hostnames, certificate selectors, process creation times, provider truth or TCP rows are supplied by the engineering sandbox. No demonstration plan should be submitted as an actual bank approval.

## B. Independent assertions for the expanded scope

A pattern is a partial expected-fact assertion, not permission to promote metadata into use. For each requested new metadata input, preflight requires exactly one expected fact and explicit `algorithm: UNKNOWN`, `runtime_use: UNKNOWN`, `capabilities_observed: false`.

| Input | Additional pre-agreed truth |
|---|---|
| `WINDOWS_CAPI_DEFAULT_PROVIDER` | Kind, exact numeric provider type, `CURRENT_USER` context and independently known default-provider label |
| `WINDOWS_CNG_REGISTRATION` | Kind, exact selected interface and bounded canonical sorted registration-label list |
| `WINDOWS_TCP_LISTENERS` | `WINDOWS_TCP_LISTENER_TABLE`, exact family, count and sorted unique flat row list; `tls_observed: false`, `process_identity_verified: false` |
| `WINDOWS_TPM_DEVICE_INFO` | `WINDOWS_TPM_METADATA`, supported output layout 1 and independently reviewed specification `1.2` or `2.0`; resolve SDK/documentation discrepancy |

TCP row shape: `address` (canonical unscoped IP), `port` (1–65535), `owning_pid` (uint32), `scope_id` (uint32, zero for IPv4). Exact current PIDs/table state can change; agree a controlled, non-mutating fixture/window or retain mismatch as a gap. Do not weaken the plan after seeing a result just to obtain PASS. Empty expected rows must independently describe the sampled table and still do not prove network/asset absence.

Native `NativePlan` schema remains `cryptoscan.native-fixture/v1`. Reviewers calculate its canonical identifier from the validated model using `shared_models.tpm_quote_verification.sha`, not an arbitrary raw-JSON file hash. Source-lock identifier is different: SHA-256 of exact file bytes. Default normalization/key order means the two hash procedures are not interchangeable.

## C. Preflight — no native calls, no dispatch

Run from the approved checkout/environment. These variable names represent **already reviewed public identifiers**; the tool does not populate or approve them:

```powershell
python scripts/capture_native_qualification.py `
  --category windows `
  --target reviewed-windows-target.json `
  --plan reviewed-windows-plan.json `
  --source-lock reviewed-source-lock.json `
  --approved-plan-sha256 $ReviewedCanonicalPlanSha256 `
  --approved-source-lock-sha256 $ReviewedSourceLockFileSha256 `
  --preflight-only `
  --output new-windows-preflight.json
```

Preflight can run on the review workstation, including Linux. It validates the exact target/plan/source identifiers, mandatory OS/SCM scope, supported assertion shape and the explicit new metadata expectations. Hash and source-lock shape checks use the same immutable read. Source-lock paths use the existing release allowlist. No source lock is signed or native execution measured by this step.

Successful output is **`PREFLIGHT_ONLY_AWAITING_REAL_WINDOWS_OPERATOR`**, not native PASS. `native_execution_performed`, `independent_approval_verified`, `production_execution_qualified`, `container_admission_granted` are false. Unknown/promotion/mismatch refuses with exit 64, no substituted observations. Output uses exclusive creation; a retry cannot overwrite an earlier packet. Hash equality is not proof of organizational independence or host authenticity.

The packet is a separate strict public artifact, not `NativeEvidence` and not one of the four required native returns. It must never be used to satisfy `native_windows`, freeze an incomplete native index or authorize a collector.

## D. Actual Windows run — assigned ordinary-user operator

After the existing assignments/approvals/channel are valid, an assigned operator runs on the **actual approved Windows fixture**, in its approved window:

```powershell
python scripts/capture_native_qualification.py `
  --category windows `
  --target reviewed-windows-target.json `
  --plan reviewed-windows-plan.json `
  --source-lock reviewed-source-lock.json `
  --approved-plan-sha256 $ReviewedCanonicalPlanSha256 `
  --approved-source-lock-sha256 $ReviewedSourceLockFileSha256 `
  --preflight-packet new-windows-preflight.json `
  --output new-windows-native-evidence.json
```

Before acquisition, changed validated target/plan commitments, exact source-file bytes or the packet's bound fields refuse rather than regenerating a favorable packet. Packet models normalize strict fields; the comparison binds its target/plan/source/ordered input identifiers, not a signature over arbitrary formatting.

- Real native acquisition still checks ordinary-user/platform/scope/time/budgets and returns explicit gaps.
- Exit 0: scoped native assertions matched; not production clearance, full-worker attestation or bank approval.
- Exit 2: a bounded native result was retained but gaps/truth mismatch remain. Preserve that unfavorable original; do not rewrite it.
- Exit 64: pre-acquisition/runtime/output refusal; no native success substitute. On Linux this cannot produce a fake Windows result.
- Native internal work/latency/isolation/cancellation remains a separate witnessed qualification. Caller-buffer limits do not guarantee interruption of a stuck native call.

Optional narrow native tests, only for independently reviewed existing resources:

```powershell
$env:CRYPTOSCAN_WINDOWS_METADATA_RESOURCE = "windows-capi://local/current-user/rsa-aes/default-provider"
python -m pytest services/inventory/tests/test_windows_metadata.py -k native_operator -q
```

For the corresponding table tests, set exactly `windows-sockets://local/ipv4/tcp-listeners` or `windows-sockets://local/ipv6/tcp-listeners`. Nonmatching/unprovided resource or non-Windows is SKIP, never native PASS. Existing CNG/certificate/process/TPM opt-in tests remain separate and require their own reviewed selectors; do not infer their success from one new test.

## E. Return originals and keep the gate closed

1. Preserve exact native output bytes, exit status, review/change/source references and separately controlled native lifecycle/negative evidence. Public-only review is required; metadata can be confidential even without keys.
2. The assigned Windows operator returns the exact native artifact through the existing campaign's approved channel. Preflight is supporting context only, never a replacement for native originals.
3. The assigned verifier reconciles all required native categories and fourteen checks in the existing immutable index. Missing/negative evidence remains missing/negative.
4. Separate pinned assessor and bank-acceptor statements are still required. Software roles, hashes and two signatures alone do not establish organizational independence, hardware origin, host trust or a bank's deployment approval.
5. Universal Windows and later adapter admission stays closed. **Do not start/enable the container universal adapter as though this packet completed Phase 3.** The next engineering phase reuses existing OCI/artifact utilities only after the required scope/advancement decision; it needs its own safety, typed-evidence, authorization and qualification contract.

Current source and local validation: [guide 76](../bank-environment/76-bounded-windows-metadata-and-operator-preflight.md), [readiness report](../readiness-evidence/windows-bounded-metadata-2026-10-25.md). No actual operator run, notification, customer deployment mutation or independent acceptance was performed by this engineering turn.
