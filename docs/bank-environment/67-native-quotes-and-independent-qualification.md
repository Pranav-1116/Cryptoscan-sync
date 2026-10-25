# 67. Native capture, challenge-bound TPM quotes and independent qualification records

This increment builds executable evidence tools for the remaining gates after [66](66-verified-local-host-worker.md). It does **not** manufacture genuine native execution, a TPM enrollment, independent assessors, bank acceptance or full-worker production clearance.

## What is implemented and what is not

| Implemented | Exact boundary |
|---|---|
| Native evidence capture | Existing ordinary-user collectors, explicit target and pre-supplied expected truth; original snapshot retained, not merely a PASS label |
| Native evidence verification | Target/manifest/snapshot/window commitments, exact ordered receipts and scalar truth, real category-specific interface requirements |
| TPM quote verifier | Raw TPMS_ATTEST + TPMT_SIGNATURE; SHA256 RSASSA RSA-2048/3072/4096 or P-256 ECDSA; pinned AK and qualified signer; exact PCR selection/values/composite; safe clock, reset/restart and firmware policy |
| Freshness and replay | Verifier-generated five-minute challenge, tenant/host/policy/target/release/snapshot/worker-claim binding, atomic one-time local acceptance marker and durable report |
| Independent evidence record | Complete native/worker matrix, SHA256-addressed retained bytes, two separate approved Ed25519 identities/roles, scope/release/tenant/policy/index/expiry checks |
| Fail-closed outputs | Missing native evidence, changed PCRs, invalid signature, replay, unresolved checks or missing reviewer blocks; no production adapter activation |

**Not implemented or claimed:** EK certificate-chain validation, credential activation proving AK hardware enrollment, remote measured boot/executable/dependency verification, event-log reconstruction, a trustworthy UTC clock, protected key custody, organizational independence verification, or automatic production enablement. A software key can produce a well-formed signed quote fixture: tests deliberately demonstrate that `quote_signature_verified` must not become `hardware_origin_verified`.

The tools run locally and read public artifacts. They do not discover hosts, create TPM keys, read private keys, invoke arbitrary commands, elevate privileges or install a simulated device. No new fleet service, migration, workflow or production profile is added. Existing NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM semantics remain unchanged: these qualification records do not manufacture BOM observations or crypto/PQC invocation claims.

## 1. Actual native capture on the approved OS

Prepare the existing `TargetSpec` and a `NativePlan` before collection, with exact input IDs, target digest, nonempty scalar expected facts and reviewer reference. Supply an independently agreed plan digest, not one learned by accepting whatever the collector returns. The CLI verifies the supplied commitment; it cannot itself prove when or by whom that approval happened.

Use the [native plan schema](../../shared/shared_models/shared_models/schemas/native-evidence-plan-v1.schema.json), [retained evidence schema](../../shared/shared_models/shared_models/schemas/native-evidence-v1.schema.json) and the explicit resource scopes from guides 63–66.

- `systemd`: actual `LINUX_SERVICE`, a fixed approved `systemd://name.service`, and `SYSTEMD_READ_ONLY` service metadata.
- `dmi`: actual `linux-hardware://dmi` / `SYSTEM_DMI` metadata.
- `tpm`: actual `linux-hardware://tpmN` / TPM-major-version metadata. This is **not** a cryptographic quote or hardware enrollment.
- `windows`: a native Windows run containing both the approved named `WINDOWS_SERVICE` and fixed `WINDOWS_OS_RELEASE` declarations. This narrow profile does not qualify every Windows collector, registry provider, store, module, listener or denial case.

```bash
python scripts/capture_native_qualification.py \
  --category systemd \
  --target /approved/systemd-target.json \
  --plan /approved/systemd-truth.json \
  --approved-plan-sha256 "$PREAPPROVED_PLAN_SHA256" \
  --source-lock /approved/platform-source-lock.json \
  --output /approved/systemd-native-evidence.json
```

Run separate DMI/TPM plans on an actual approved Linux host exposing those interfaces. Run the Windows category on Windows with approved Windows inputs; Linux refuses it rather than skipping to success. Exit 0 means only `PASS_SCOPED_NATIVE_EVIDENCE`. Exit 2 retains actual gap/truth-mismatch evidence; exit 64 refuses invalid/unavailable OS/scope/output. Every approved input must have a successful exact expected-truth receipt, and an unrelated OS-file fixture cannot satisfy systemd/DMI/TPM/Windows category coverage.

The producer retains a public snapshot bounded to 2 MiB, not raw source files. No private material, serial discovery or broad scan is introduced. `source_lock_sha256` is an **operator-supplied identifier**, not proof of the running executable; the evidence explicitly carries `OPERATOR_SUPPLIED_IDENTIFIER_NOT_MEASURED_EXECUTION`. Native capture is the existing standalone collector, not a claim that Windows/systemd are supported by the Linux worker sandbox. `native_system` is a producer assertion checked for consistency, not a remotely attested platform proof. External independent assessment must investigate falsified or compromised producers.

## 2. Trusted TPM enrollment policy, never self-selected quote keys

An authorized enrollment process must independently establish the AK public key, qualified name, tenant/host association, PCR baseline and reset/restart state. A nonce and signature do not replace that process. This repository does not supply the missing EK/credential-activation trust ceremony.

Provision the verifier's [QuotePolicy](../../shared/shared_models/shared_models/schemas/tpm-quote-policy-v1.schema.json) from that process. It includes:

- exact `tenant_id` (explicitly nullable for a platform estate) and `host_id`;
- `enrollment_reference`, public AK PEM and SHA256 qualified signer name (`000b` + 32-byte digest);
- exact SHA256 PCR index/value map (indices 0–23, no leading-zero aliases);
- approved reset/restart counts, minimum TPM clock and firmware value.

Only RSA RSASSA/SHA256 with exponent 65537 and P-256 ECDSA/SHA256 are supported. PSS, other curves/banks, multiple banks, ambiguous structures and trailing data refuse. Do not weaken the policy to match observed drift: firmware/PCR/reset changes require explicit independent reassessment. TPM clock checks are not an attested UTC clock.

Keep the policy, local state parent, output directory and installed verifier under restricted operator control. The current CLI's challenge store requires Linux, exact owner and mode 0700; state entries are 0600, no-follow, single-link regular files. This is local verifier state, not a distributed authority or defense against a compromised verifier, hostile same-UID process, replaced filesystem/OS or unauthorized policy edits. Native Windows evidence can be transferred as public artifacts to this verifier; no Windows ACL qualification is asserted.

## 3. Issue, quote externally, verify and consume once

Provide an exact scope JSON with `campaign_id`, `tenant_id`, `target_sha256`, `source_lock_sha256`, `snapshot_sha256` and `worker_claim_sha256`. Use actual approved digests, not labels or arbitrary placeholders. The worker claim is the previously committed claim digest, not its process-memory secret.

```bash
mkdir -m 700 /approved/quote-state
python scripts/verify_tpm_host_quote.py \
  --state /approved/quote-state --policy /approved/enrolled-ak-policy.json \
  issue --scope /approved/quote-scope.json --output /approved/challenge.json
```

The verifier supplies challenge ID, random nonce, enrolled host, policy digest and aware issue/expiry times. A caller cannot select the nonce or override verifier fields, and cannot change the enrollment tenant. The lifetime is at most five minutes.

An approved external TPM agent uses **the exact `qualifying_data_hex` bytes from the output** as TPM qualifying data. The value is SHA256 of a domain-separated canonical challenge, not just its random nonce. Capture:

1. raw **TPMS_ATTEST** beginning with TPM_GENERATED magic — no TPM2B length wrapper;
2. **TPMT_SIGNATURE**, not a naked RSA signature or DER-only ECDSA signature;
3. JSON containing the exact SHA256 PCR index/value map covered by the quote.

Use a reviewed external tool/version that exports those structures. The verifier neither runs a TPM command nor accepts a quote-provided replacement public key. It cannot perform a live quote here without a genuine enrolled TPM endpoint.

```bash
python scripts/verify_tpm_host_quote.py \
  --state /approved/quote-state --policy /approved/enrolled-ak-policy.json \
  verify --challenge-id "$VERIFIER_CHALLENGE_ID" \
  --attestation /approved/quote.attest \
  --signature /approved/quote.signature \
  --pcrs /approved/quoted-pcr-values.json \
  --output /approved/quote-verification.json
```

Signature validity alone is insufficient: nonce/scope, enrolled qualified signer, PCR selection, approved values/composite, safe clock and approved counters/firmware must match. All binary fields/lengths are bounded. A failed proof does not consume the challenge. Two concurrent valid proofs yield one accepted durable record; a replay refuses with exit 64.

A consumed marker is also the retained acceptance report: `{challenge_id}.accepted.json`. If final output creation fails, recover that **existing** report from the protected state store; do not reset or replay the challenge. A crash during marker write may leave an incomplete marker that blocks replay. Resolve that only through explicit operator review, not automatic deletion/retry. A crash between challenge creation and output publication can similarly leave an unused challenge; it expires, rather than being silently reused.

Exit 0 is `VERIFIED_ENROLLED_KEY_QUOTE`, **not** physical-host or production clearance. The report keeps `hardware_origin_verified`, `measured_executable_verified`, `attested_utc_clock` and `production_execution_qualified` false. Even a genuine TPM quote binding a snapshot hash does not prove the collector executed correctly, that those facts originated on that host, or that approved PCRs uniquely identify the current application.

## 4. Retain independent assessment, do not self-approve

Provision a trusted [AcceptancePolicy](../../shared/shared_models/shared_models/schemas/qualification-policy-v1.schema.json) containing tenant, campaign/scope, release digest, all four preapproved native plan/platform-source-lock digests, and separate assessor/bank-acceptor public keys. Reviewer identities and keys must be distinct. Operator trust and real organizational separation must be established outside this verifier.

Prepare an [EvidenceIndex](../../shared/shared_models/shared_models/schemas/qualification-index-v1.schema.json). Store each referenced **original public byte artifact** under its exact lowercase SHA256 filename in a protected artifact directory. The complete required matrix is:

- native systemd, DMI, TPM and Windows;
- host enrollment and quote/PCR/replay controls;
- worker authority, isolation, cancellation and cleanup;
- evidence/export, key custody, recovery and adversarial retest.

Every gate requires a nonempty bounded artifact list. Native gates must reference their original typed native artifacts and pass actual receipt/expected-truth consistency checks; a signed checkbox or a generic `PASS` JSON is insufficient. Other worker/enrollment checks are retained **external reviewer assertions over evidence bytes**: the tool cannot automatically determine that an arbitrary log establishes full operational clearance. Assessors must examine the actual control plane, OS, deployment, custody and adversarial behavior.

The assessor and bank acceptor each produce a [ReviewStatement](../../shared/shared_models/shared_models/schemas/qualification-review-v1.schema.json) binding exact policy, release, tenant, campaign and index digests, per-check decisions, evidence reference and aware time window (maximum seven days). They must make their own decisions after inspecting the evidence. There is no generated all-PASS review or in-product private-key signer. Both external identities sign the canonical UTF-8 statement bytes produced by `shared_models.tpm_quote_verification.canonical`; envelopes use raw Ed25519 signatures in canonical base64. Supply the resulting list of [signed review envelopes](../../shared/shared_models/shared_models/schemas/qualification-signed-review-v1.schema.json).

```bash
python scripts/verify_independent_host_qualification.py \
  --policy /approved/qualification-policy.json \
  --index /approved/evidence-index.json \
  --reviews /approved/external-signed-reviews.json \
  --artifacts /approved/public-artifacts \
  --output /approved/verified-scoped-review.json
```

The verifier reads only explicitly addressed files, never discovers arbitrary paths or follows archive/remote links. Bounds are 256 artifacts, 2 MiB each, 16 MiB total. It rejects missing/changed artifacts, wrong tenant/campaign/release/plan, native gaps, unknown/reused reviewer identity, signature failure, expired/future review, REJECT, FAIL and NOT_RUN. Current trusted policy changes (including reviewer withdrawal) invalidate old commitments; a sender's bundled policy is not automatically trusted.

Exit 0 records `VERIFIED_SCOPED_EXTERNAL_ACCEPTANCE_RECORD`. It proves which pinned keys signed which original bytes, not employment, organizational independence, truthfulness or physical host identity. `full_worker_production_clearance` and `production_execution_qualified` remain false. Review verification is intentionally idempotent until policy/expiry changes; TPM nonce consumption is intentionally one-time.

## 5. Actual environment and next execution step

The [current execution report](../readiness-evidence/host-qualification-2026-10-25.md) distinguishes software protocol positives from current-host native gaps. Genuine systemd/DMI/TPM/Windows results cannot be built into existence here.

To finish the external gate, provide approved host operators with these tools and independently agreed plans: Linux with actual systemd/DMI/TPM2 access, a real Windows host/account, an externally established AK/PCR policy, and independent assessor/bank-acceptor review. Return **public evidence exports only**, never private keys or login credentials. Then verify the original artifacts and quote/review proofs. Separately qualify the full deployed worker and its production admission adapter; this packet deliberately does not add an environment flag or policy shortcut that enables it prematurely.
