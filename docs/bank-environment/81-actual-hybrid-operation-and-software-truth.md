# 81. Actual hybrid TLS, signed operation correlation and agreed software truth

This increment moves beyond the synthetic hybrid parsing in [Guide 80](80-tls13-selected-group-evidence.md). It implements three bounded improvements, not universal bank/Windows/container/HSM qualification.

[Operator packet](../runbooks/hybrid-operation-software-evidence.md) · [Contracts and stored API](../api-reference/hybrid-operation-software-evidence.md) · [Retained engineering evidence](../readiness-evidence/hybrid-operation-software-2026-10-25.md).

## What actually ran

| Request | Executed improvement | What is still not proven |
|---|---|---|
| Actual hybrid-PQC negotiation | **Both peers completed real TLS 1.3 X25519MLKEM768 over owned loopback TCP**, through the product collector, numeric endpoint and exact certificate pin. CLI, import, stored export and tenant/custody negatives are tested. | Customer interoperability, provider correctness/FIPS/side channels, PQC authentication, all groups, production acceptance. |
| Application/HSM operation evidence | New verifier checks a real challenge signature and two separately pinned signed application/provider logs bound to that exact operation. Actual software Ed25519 signatures executed locally. | No actual HSM or customer application ran. Signed logs prove signed correlated claims, not truthful application execution, physical custody or organizational independence. |
| Complete software coverage | New plan defines **every approved package-database input** and expected name/version record multiset. Actual sandbox dpkg evidence matched **283 installed records** from a separate `dpkg-query` implementation; source stayed unchanged. | This is exact agreed package-record coverage, not complete software discovery. Language dependencies, unpackaged/loaded code, containers and firmware remain unassessed; independent human truth review is pending. |
| Genuine Windows/container qualification | Existing native capture, pinned-source/truth and independent review workflow stays required. Availability was checked: Linux; no Windows/container runtime tools or runtime sockets. | **Not executed or qualified.** Neither fixture success nor running inside a sandbox substitutes for native Windows or independently bound container/image acceptance. |

No credentials/private keys were requested, exported or retained. Test signing/certificate keys are ephemeral in memory. No customer endpoint, privileged runtime installation, workflow/CI dispatch, new service/database/dashboard or production configuration change.

## 1. Explicit actual-hybrid profile

```text
kind: NETWORK_TLS13_HYBRID
resource: tls-hybrid://127.0.0.1:443/sni/service.example/version/TLSv1.3/group/X25519MLKEM768/peer/sha256/<64-hex-reviewed-peer-pin>
collection_method: network
allowed_operations: [OBSERVE_APPROVED_TLS_SESSION]
CLI opt-in: --include-hybrid --acknowledge-active-tls
```

Address above is illustrative: the owned fixture uses a fresh OS-assigned loopback port. Obtain approval for the actual numeric address/port, SNI, public certificate pin, exact version/group, retention, window and full target digest **before** measuring.

The public pyOpenSSL MemoryBIO adapter is lazy/optional; [requirements-hybrid-tls.txt](../../requirements-hybrid-tls.txt) pins the tested operator environment. SDK >=26.4.0 and embedded OpenSSL >=3.5 are required. Actual local execution used **pyOpenSSL 26.4.0 / cryptography 50.0.2 / OpenSSL 4.0.3 (29 Sep 2026)**, not the stdlib's OpenSSL 3.0.20. Base dependencies/workflows are not upgraded.

The public SDK has no group setter here: **the provider's default offer is used, then the collector requires observed group 4588 and the finished exact-pin session**. It does not secretly use CFFI/ctypes/private ABI to force groups. A completed classical session produces `UNAVAILABLE / TLS_REQUIRED_GROUP_NOT_SELECTED`, no positive hybrid fact and no automatic retry. That is not evidence the server lacks PQC.

The new fact requires the registered final public ServerHello, correct suite/group/hash and **1,120-byte server share** (32+1,088 public bytes). Local handshake completion is enforced by the collector; imported completion/version fields remain producer claims. Provider identity is explicitly `SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION`.

Reuse all prior controls: one literal numeric TCP connection; no DNS/proxy/discovery/application request; explicit preflight; no tickets/reuse/key logging; 8-second driver deadline, 2-second socket calls, 512 steps; combined existing wire/DER/hello/canonical-byte cap. These are not native CPU/RSS/cancellation qualification. Old wrappers refuse the new profile before connecting. Bare/offline collection and server network-job authorization cannot activate it.

An RSA certificate is still separate from hybrid key exchange and the TLS cipher. Server CertificateVerify scheme, application use and overall PQC assessment remain UNKNOWN. Provider versions do not attest the wheel, hardware, host or release. Inherited readiness/implementation/all-groups/application-identity flags remain false.

## 2. Operation-bound public verification, not a boolean receipt

`shared_models.operation_evidence` and `scripts/verify_operation_evidence.py` add a narrow **Ed25519-only public verification profile**:

1. Separately review/pin an approval with application ID, provider key ID, operation ID, fresh 32-byte nonce, time window and **three distinct public keys**: application logger, provider logger and operation signing key.
2. Canonical challenge includes approval hash and exact operation/scope. No arbitrary message or evidence-supplied key is accepted.
3. Verify the operation signature with the approved operation key.
4. Verify both signed logs with their respective approved logging keys; require correct distinct event type, exact approval/application/key/operation, mechanism, message/signature digests, SUCCESS and bounded times.
5. Atomically record acceptance once in an owned private local ledger. Missing/changed roots, forged signatures, wrong operation/challenge, expiry/future logs, replay and existing outputs refuse.

The script **does not sign or call a provider**. Operators arrange a separately authorized operation/audit capture using their existing approved application/provider process. Only public keys, challenge signature and signed public metadata cross this interface. RSA/ECDSA/vendor-audit formats are unsupported here, not silently treated as verified.

A positive result says `operation_signature_verified=true`, `application_provider_logs_correlated=true`, `source_basis=IMPORTED_SIGNED_CLAIMS`. It keeps `hardware_backing_verified=false`, `application_execution_attested=false`, `application_uses_physical_hsm=UNKNOWN`, organizational independence false and production qualification false. Logs controlled by one party can still lie; key enrollment, custody, native audit extraction and independent review remain external requirements. A digest pins a reviewed object, not its authenticity.

The local replay fence is single-authority Linux file state, not a distributed ledger. Pure verification is repeatable; replay prevention belongs to the CLI ledger. Do not delete accepted markers to retry. If output publication fails, the retained accepted result is authoritative and needs investigation/recovery rather than re-execution.

### Existing HSM path strengthened without disguising old claims

The legacy connectivity checker now uses fresh domain-separated challenges, detects private-material exposure **before scrubbing**, discards exposed attributes/stops further signing and withholds SDK error text. An exposure yields UNDETERMINED residence, not proof of software or absence. It adds explicit false verification flags and UNKNOWN application/HSM use.

For compatibility, old `hardware_backed` is still **provider-metadata classification** and `sign_challenge=OK` still means a nonempty response, not cryptographic verification. New basis fields say exactly that; the existing HSM UI now labels provider-reported hardware and unverified receipts, removing the false “proves in-boundary use” wording. LIVE queries do not themselves establish application use; SUBMITTED booleans are not accepted by the new verifier.

## 3. Exact agreed software denominator

`SoftwareTruthPlan` is a separate reviewed register: exact host-manifest hash, reviewer reference, every approved `DPKG_STATUS`/`APK_INSTALLED`/`RPM_SQLITE` input, independently committed source hash and expected package name/version records. Duplicate counts matter; wrong versions, added/omitted records or inputs cannot disappear through deduplication.

`reconcile_software_truth.py` only reads retained typed snapshot + plan; it never reads the original package database, runs package managers, discovers hosts or changes an existing snapshot/BOM. A complete exact match requires PARSED receipts, source commitment and exact multiset equality for every package input. A failed/inaccessible input is a coverage gap, never package absence. Scope/source/manifest mismatch refuses; a valid comparison with discrepancies returns a blocked report and nonzero status.

Success means `MATCHED_AGREED_PACKAGE_RECORD_SET`, **not an independent complete-estate claim**. The report names unassessed surfaces and leaves whole-host inventory completeness, reviewer identity and production execution unverified. Expected truth is operator-supplied and not authenticated merely by matching a hash. Creating expected rows from the measured snapshot does not constitute independent truth.

The executed sandbox comparison used the real 266,494-byte dpkg status file and separate read-only `dpkg-query`, not synthetic stanzas. It is a separate-implementation functional witness, **not independent human review, native container-image qualification or bank acceptance**. Product collection itself continues to parse literal metadata without invoking package tools; ambiguous multiarch identities remain unsupported rather than merged.

## 4. Six-BOM and evidence boundaries

The new TLS fact follows existing target → receipt → imported evidence → normalized identity → stored projection/export/UI. It contributes only **NBOM, CBOM, TechBOM**. SBOM, HBOM, VBOM receive no invented relationship or completeness. The existing official-CycloneDX-1.6 gate remains mandatory for stored TLS export, with unchanged tenant/RBAC/custody/audit behavior.

The two new offline verification reports are supporting qualification artifacts, **not newly observed collectors, standard BOMs, automatic `USES_HSM` edges or native/production admissions**. Existing software SBOM stays incomplete. No extra automatic fanout turns a package/declared provider into application crypto use.

## Ten-step acceptance checklist

1. Agree each numeric TLS target/public pin and software/app-operation denominator.
2. Pin the operator provider/source environment; don't equate hash with attestation.
3. Run the explicit one-session hybrid profile, not broad scanning.
4. Require the same pinned finished handshake and observed 4588; refuse fallback.
5. Import through existing tenant/approval custody and official-schema stored export.
6. Review operation approval/public keys before the operation, not from its result.
7. Verify challenge + both logs, then consume local replay state once.
8. Reconcile every agreed package input; preserve gaps and unknown surfaces.
9. Have assigned operators run the existing actual Windows/container packets with independent expected truth/review. No simulated/native label substitution.
10. Review retained results and adverse tests; production admission and performance/independent acceptance remain separate. No p95/p99 or >=20% performance improvement is claimed by these correctness witnesses.
