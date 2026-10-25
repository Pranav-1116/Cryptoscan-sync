# Approved-host qualification — operator handoff

**Execution status: awaiting named host operators, approvals and reviewers.**
This is the handoff for running the implemented packet, not evidence that anyone has run or accepted it. Runtime/tool baseline: `73818352d629b3dbeced631ebed1542f889a2d43`.

Use [guide 67](../bank-environment/67-native-quotes-and-independent-qualification.md) for contract details and limits. Complete the [intake form](../templates/host-qualification-intake.md) before scheduling. Never send host passwords, login tokens, private keys or TPM authorization secrets.

## 1. Assign owners and freeze scope before execution

| Role | Required responsibility |
|---|---|
| Bank/change owner | Approve exact hosts, metadata resources, account permissions, time window, data handling and stop conditions |
| Linux operator | Run approved systemd/DMI/TPM metadata capture on a genuine Linux host with those interfaces |
| TPM/enrollment custodian | Independently establish AK/host association and approved PCR/counter baseline; obtain the fresh quote through the approved external agent |
| Windows operator | Run native SCM/OS capture on a real Windows host using an ordinary approved account |
| Verifier operator | Protect trusted public policies/state; issue/consume the challenge and verify original artifacts |
| Independent assessor | Inspect actual environments, worker/control-plane behavior and retained evidence; make a real signed decision |
| Bank acceptor | Independently decide whether the scoped evidence satisfies the bank's agreed acceptance criteria |

Do not invent names, approvals or separation of duties. Verify organizational independence outside the software. The assessor and bank acceptor must have distinct pinned signing identities/keys. The collector operator must not replace their decisions with self-approval.

Before collection, agree and retain:

- Tenant/campaign/system/host identities; explicit service names, DMI/TPM resources and collection windows.
- One target and expected-truth plan for each of `systemd`, `dmi`, `tpm`, `windows`; independently approved **canonical plan digests** and platform source-lock identifiers.
- The Windows plan must include both the approved named `WINDOWS_SERVICE` and fixed `WINDOWS_OS_RELEASE` inputs. This is a narrow native profile, not all Windows surfaces.
- Known expected facts/counts, not values inferred after seeing output. Missing/denied inputs are blockers, not absence proofs.
- Trusted enrollment and acceptance policies, real reviewer public keys and the agreed worker/adversarial test procedure.
- Stop contact and conditions: expired/changed approval, unexpected host/PCR/counter state, denied/unavailable interface, invalid signature or out-of-scope output.

**Public artifact** means no private cryptographic material, not permission to publish bank metadata. Agree an approved secure transfer channel. Original snapshots may contain internal labels/paths. Agree allowable fields before collection; changing or redacting signed/hashed originals invalidates their commitments and requires fresh review.

## 2. Linux operator — three explicit native captures

Use the approved Python 3.11+ environment and reviewed runtime checkout. Stay unprivileged. Do not install a fake TPM, create a service, broaden permissions, restart anything or use root as a fallback to obtain a pass.

Run the following command **separately** for `systemd`, `dmi` and `tpm`, with the corresponding approved files and digest. Shell variables below must be supplied by the change owner; they are not fabricated defaults.

```bash
python scripts/capture_native_qualification.py \
  --category "$CATEGORY" \
  --target "$APPROVED_TARGET_JSON" \
  --plan "$APPROVED_TRUTH_JSON" \
  --approved-plan-sha256 "$PREAPPROVED_CANONICAL_PLAN_SHA256" \
  --source-lock "$APPROVED_PLATFORM_SOURCE_LOCK" \
  --output "$NEW_NATIVE_EVIDENCE_JSON"
```

Retain the exact JSON output, stdout summary, exit status, approved target/plan and approval reference for each run. Use a new output filename; never overwrite an original.

- **0:** scoped native evidence matched. Still requires review; not full-host or production clearance.
- **2:** actual gap/truth mismatch. Retain it, stop claiming qualification, notify the owner.
- **64:** invalid/refused OS/scope/output. Investigate; do not bypass the check.

Required public returns: `systemd-native.json`, `dmi-native.json`, `tpm-native.json` and their run records. Names are handoff conventions; preserve the actual original bytes.

## 3. Windows operator — actual Windows execution

Run in an approved ordinary Windows account, not an elevated shell. The Windows build/account/ACL and tool environment must be recorded by the operator and assessed independently. Linux emulation or a Linux-generated JSON fixture is not native Windows evidence.

```powershell
py -3 scripts\capture_native_qualification.py `
  --category windows `
  --target $ApprovedWindowsTargetJson `
  --plan $ApprovedWindowsTruthJson `
  --approved-plan-sha256 $PreapprovedCanonicalPlanSha256 `
  --source-lock $ApprovedWindowsSourceLock `
  --output $NewWindowsEvidenceJson
$CaptureExitCode = $LASTEXITCODE
```

Use the agreed Python version; `py -3` is illustrative launcher syntax, not permission to use an unreviewed interpreter. Retain `windows-native.json`, stdout, exit status and approval/run record. Apply the same 0/2/64 interpretation. Do not enable a Windows worker adapter or claim the Linux sandbox qualifies Windows.

## 4. Verifier and TPM custodian — fresh quote round trip

The verifier's local challenge store is Linux-only and requires a protected owner/mode-0700 directory. Provision its parent and policy through the approved operating procedure. Do not share state write access with the evidence producer.

The custodian must supply an independently established **public** AK policy: tenant/host association, AK public PEM, qualified signer name, approved SHA256 PCR values/indices, reset/restart counters and minimum clock/firmware state. The tool does not perform EK certificate validation or credential activation. Do not learn a baseline by accepting whatever the device returns.

Prepare `quote-scope.json` with actual campaign/tenant, target, source-lock, snapshot and worker-claim digests. The claim digest is public metadata, not the worker's process-memory secret. Identify exactly which host/result the quote covers: a Linux quote does not attest a different Windows machine or every artifact in a campaign. To bind a worker result, use the actual approved worker snapshot and committed claim; do not substitute an unrelated native-capture snapshot.

Only when the custodian is ready to respond within the five-minute lifetime:

```bash
python scripts/verify_tpm_host_quote.py \
  --state "$PROTECTED_QUOTE_STATE" --policy "$TRUSTED_ENROLLED_AK_POLICY" \
  issue --scope "$APPROVED_QUOTE_SCOPE" --output "$NEW_CHALLENGE_JSON"
```

Send the challenge through the approved channel. The external TPM agent must quote the exact `qualifying_data_hex` bytes and return:

- `quote.attest`: raw **TPMS_ATTEST**, no TPM2B length wrapper;
- `quote.signature`: **TPMT_SIGNATURE**, not a bare/DER-only signature;
- `quoted-pcr-values.json`: the exact SHA256 index/value map covered by that quote.

Use the custodian's reviewed TPM agent/tool version. Do not expose a private AK or authorization secret. These tools do not run a TPM command or create/enroll a key.

```bash
python scripts/verify_tpm_host_quote.py \
  --state "$PROTECTED_QUOTE_STATE" --policy "$TRUSTED_ENROLLED_AK_POLICY" \
  verify --challenge-id "$ISSUED_CHALLENGE_ID" \
  --attestation "$QUOTE_ATTEST" --signature "$QUOTE_SIGNATURE" \
  --pcrs "$QUOTED_PCR_JSON" --output "$NEW_QUOTE_VERIFICATION_JSON"
```

Exit 0 verifies the enrolled-key quote and consumes that challenge once; exit 64 refuses it. Retain the challenge, quote files, policy reference and verification report. If final output creation fails after consumption, recover the existing protected `{challenge_id}.accepted.json` report; do not delete state or replay. A genuinely expired unused challenge needs a new verifier-issued challenge and fresh quote, not a timestamp edit. An incomplete acceptance marker requires explicit operator review.

A passing quote does not prove hardware origin, measured application execution, snapshot truth or attested UTC. Those limitations must remain in the assessment.

## 5. Assess the full deployed worker — do not stop at native metadata

Use the independently agreed test procedure, exact deployed release/configuration and approved test data. The following are required evidence categories, **not pre-filled PASS decisions**:

- Native systemd, DMI, TPM and Windows original artifacts.
- Host enrollment and quote/PCR/replay controls, including genuine hardware-origin limitations.
- Worker authority/revocation/tenant isolation and actual runtime isolation.
- Cancellation, parent/child death, cleanup and residual temporary-artifact handling.
- Evidence integrity/export, protected signer custody/revocation, recovery and adversarial retest.

Use guide 66's controlled worker workflow only in an expressly approved development/qualification environment; do not disable production enforcement or change customer deployment configuration to make it run. Windows standalone native results do not establish a qualified Windows worker. Retain real commands/actions, results, failure cases, scope and assessor observations. Repository unit tests or a general infrastructure certificate do not replace this assessment.

## 6. Independent decisions and verification

Freeze the original public artifacts in a protected transfer directory, each named by its exact lowercase SHA256. Prepare the agreed `qualification-policy.json` and `evidence-index.json`; the index must include every required check and all four native artifacts. Hash **raw artifact bytes**; plan/model commitments use the specified canonical representation, not a hash of arbitrarily formatted JSON.

The assessor and bank acceptor each inspect the evidence and complete their own review statement. They must use REJECT, FAIL or NOT_RUN when appropriate. They sign the canonical UTF-8 statement bytes externally, producing the approved Ed25519/base64 envelopes. No software or assistant should generate their decisions or hold their private keys.

Return `external-signed-reviews.json` and verify:

```bash
python scripts/verify_independent_host_qualification.py \
  --policy "$TRUSTED_QUALIFICATION_POLICY" --index "$FROZEN_EVIDENCE_INDEX" \
  --reviews "$EXTERNAL_SIGNED_REVIEWS" --artifacts "$PUBLIC_ARTIFACT_DIRECTORY" \
  --output "$NEW_VERIFIED_REVIEW_RECORD"
```

Exit 0 records a scoped externally signed acceptance record; exit 64 blocks it. It does not verify organizational independence or operational completeness automatically, and does not enable production.

## 7. Return packet and decision to move forward

Return via the approved channel:

- Completed intake/run record and original approvals/plans/policy references.
- Four original native artifacts with operator run records and explicit failed/denied results, if any.
- Challenge, raw public quote/signature/PCR files and verification report for the identified host/result.
- Original full-worker/custody/recovery/adversarial assessment artifacts.
- Trusted public policy, frozen index, separate signed reviews and verified review record.
- Known limitations, unresolved findings, explicit rejection/NOT_RUN decisions and reviewer remediation requirements.

Do **not** send verifier state write access, private keys, passwords, bearer tokens or TPM authorization values. Public trust anchors must be authenticated through the agreed enrollment/approval channel, not trusted merely because a sender included them.

**Move-to-next condition:** actual approved-host evidence and actual independent decisions have been received, verified and their scope/limitations accepted. A passing packet is a retained acceptance record, not authority to flip production flags. A separate production-adapter/deployment decision is still required. Until then the status is **WAITING FOR EXTERNAL EXECUTION/REVIEW**, not complete.
