# 82. Native container execution and external proof paths

This builds the next executable pieces requested after [Guide81](81-actual-hybrid-operation-and-software-truth.md). It does **not** invent customer access, a physical HSM, an authoritative estate register or a Windows machine.

[Operator packet](../runbooks/native-container-and-external-proof-paths.md) · [Contracts](../api-reference/native-container-and-external-proof-paths.md) · [Retained validation](../readiness-evidence/native-container-external-proof-2026-10-25.md).

## What changed, and what actually executed

| Requested outcome | New implementation/execution | Boundary |
|---|---|---|
| Customer application / physical HSM | Public operation-v2 verification supports RSA PKCS#1/SHA256, RSA-PSS/SHA256 and P-256 ECDSA/SHA256, alongside unchanged v1 Ed25519. New one-attempt, approved immutable-key AWS KMS capture calls the existing adapter and verifies the returned signature against the independently pinned public key. | Local tests used real software signatures/injected SDK responses, **not a customer account or physical HSM**. A probe is not customer application use. Actual app/provider signed logs and independent hardware/custody evidence remain required. |
| Whole-estate software | New closed register requires **every registered asset × all six software surfaces**, expected records, original source commitments, release/window and enrolled producer signatures. Missing assets/surfaces/returns, altered sources and cross-release statements block. | This reconciles signed claims against an agreed denominator; it cannot discover an omitted estate, prove producer truth or turn lockfiles into installed/runtime use. Whole-estate completeness remains false. |
| Genuine container qualification | **Actual ordinary-user Linux namespace containers ran** with private user/mount/PID/network/IPC/UTS namespaces, read-only rootfs, cap drop, no-new-privileges and syscall denials. Real memory/FD negative probes, cancellation and cleanup passed. Product OCI layer/diff-ID/package parsing matched the running fixture's expected database bytes. | This qualifies functional controls of the tiny **owned unshare/chroot fixture only**. Not Docker/Kubernetes, customer images, an arbitrary-code executor or production admission. Independent external review remains pending. |
| Genuine Windows qualification | Existing real-Windows preflight/native capture/independent-review packet remains required and usable; no Linux substitution or CI dispatch was introduced. | **Not executed here.** The host is Linux. Native Windows tests remain skipped, not passed; original operator artifacts are still needed. |

No credential/private key was requested or retained, no cloud provider was contacted, no privileged runtime installed, and no workflow/CI dispatch performed. Test signing keys are ephemeral software keys; generated C binaries/rootfs images stay in owned temporary directories, not Git. No new service/database/dashboard or automatic `USES_HSM` edge.

## 1. Actual Linux namespace-container witness

The earlier “Docker/Podman unavailable” observation was correct but insufficient to test all runtime options: actual probing found that **rootless user and other kernel namespaces are available**. The new runner uses those existing kernel capabilities, not Wine/proot/emulated observations or a JSON field saying “native.”

`scripts/qualify_owned_namespace_container.py` has a fixed owned-fixture scope and a reviewed plan hash. It:

1. Requires ordinary-user Linux x86_64 and existing gcc/unshare/mount/chroot tools. It creates only a new disposable directory below the operator home; no customer rootfs/path or arbitrary command is accepted.
2. Copies the approved C source into that owned directory, rechecks its hash, compiles a static fixture, and constructs a small real OCI layout with the binary and a predefined package database.
3. Runs the existing `OfflineContainerCollector`, checking actual blob/diff-ID/content parsing and expected package name/version. This is still the existing virtual product content profile, not a new production executor.
4. Actually launches a chrooted PID1 in six new Linux namespaces, with a read-only bind-mounted rootfs. Kernel namespace inode IDs must differ from the parent's, the running executable inode must match the owned fixture, and bytes read inside the container must match the independent predefined database.
5. Drops effective capabilities, sets no-new-privileges and a source-bounded seccomp deny filter. Socket/mount attempts must fail; the owned outside sentinel must be inaccessible and rootfs writes must fail EROFS. This filter/tiny fixture is **not certification of a general hostile-code sandbox**.
6. Applies AS128MiB, FD32, output64KiB and CPU2s limits. A256MiB allocation and excess-open-file probe must actually fail. CPU limit is configured, **not a measured throughput/CPU-exhaustion qualification**.
7. Runs a deliberate held instance, observes the wall timeout and kills the owned namespace init using a pinned pidfd after ancestry recheck. The parent reaps the child; temporary directories are removed. Unexpected timeout/truth/control/cleanup failure is nonzero, never skip-to-PASS.

The image/database are deliberately controlled fixture content, not an actual vendor-distribution package census. The execution is genuinely native; the fixture is not a customer deployment. No runtime-image attestation, firmware/FIPS, live Docker/containerd binding or existing production-admission flag is upgraded by this result.

## 2. Operation signatures common to HSM integrations

New `OperationApprovalV2` pins canonical **public SPKI DER**, its SHA256, mechanism, two distinct public Ed25519 logger roots, app/key/operation IDs, public nonce and window. Existing v1 schemas/defaults are unchanged. V2 refuses private DER, wrong key type/curve/fingerprint, weak RSA sizes, wrong operation context, forged/uncorrelated logs and expiry/future events.

Supported operation mechanisms:

- RSA PKCS#1 v1.5 +SHA256, RSA2048–8192/e65537.
- RSA-PSS +SHA256, MGF1/SHA256 and **exact32-byte salt**.
- ECDSA +SHA256 on **secp256r1/P-256**; DER signature format.

The two logger signatures remain Ed25519. A valid operation signature is not enough: the original signed application and provider statements must bind the same approval, operation, public key identity, exact message/signature hashes, mechanism and bounded times. A successful result remains **IMPORTED_SIGNED_CLAIMS**, not hardware attestation, organizational independence or attested application execution.

### One-attempt live capture, not a fabricated app trace

`capture_approved_hsm_operation.py` accepts only an approved `HsmOperationRequest`: AWS KMS, exact immutable key ARN, matching region and v2 approval/public key. It reserves a private new output and durable attempt marker **before** provider work. Alias keys/custom endpoints are refused. SDK retries are disabled; connect/read timeouts are bounded. Existing SDK authentication stays in the operator's approved environment; no credential/PIN command arguments or provider exception text are emitted.

The existing AWS adapter now accepts the exact approved algorithm instead of silently using the first advertised algorithm. Missing/mismatched mechanisms and invalid/nonempty signatures refuse. The result retains only the verified public signature and bounded proof metadata. A crash, unavailable SDK/provider or ambiguous timeout consumes that attempt: investigate and obtain a new approval, don't retry the same request in fresh state directories.

This capture is explicitly `OPERATOR_INITIATED_PROVIDER_CHALLENGE_NOT_CUSTOMER_APPLICATION_TRACE`. It does **not** manufacture application/provider log signatures. To establish actual customer application correlation, the authorized application must emit its real signed trace and the provider/auditor must independently return the matching original evidence. Physical HSM proof additionally needs exact vendor/model/firmware/mechanism, trusted device/provider provenance and independent custody review; a KMS signature or `HARDWARE` attribute alone cannot establish that.

## 3. Multi-asset, six-surface software denominator

New `SoftwareEstatePlan` freezes an asset register and hash, release, reviewer reference, window and exactly one scope for every asset ×:

1. OS packages.
2. Language dependencies.
3. Unpackaged binaries.
4. Loaded code.
5. Container images.
6. Firmware.

Each REQUIRED unit pins a nonempty expected record multiset and original source hash. A pre-reviewed NOT_APPLICABLE unit must be explicit, record-free and explained; all-N/A assets cannot qualify. N/A counts stay separately visible, not silently removed from totals. Each bounded register supports at most20 assets/120 units and20,000 aggregate expected records; it is not a scalable whole-bank discovery service or proof that an external asset register omitted nothing.

Each signed return binds the whole plan/release, asset/surface, source hash, capture time, status and records. Producer keys come from the reviewed register, never from the packet. Original source bytes are retained and checked; duplicate/unreferenced/cross-scope/corrupt data refuses. Matching uses multisets including content/version/duplicate counts. Non-measured/failed/missing returns have unknown observed counts, not zero-software/absence assertions. DECLARED_ONLY cannot satisfy a measured unit.

Crucially, **the generic verifier checks signatures, bytes/commitments and reported record equality, not arbitrary vendor-source semantics**. It does not parse all firmware/language/runtime formats, attest that a producer truthfully measured them, authenticate the register's organizational authority or treat signed lockfile claims as runtime proof. Use the existing stronger package/OCI parsers where supported, retain their original outputs, and get independent review. The new generic reports support that process rather than creating AI-manufactured observations.

An all-match report says `MATCHED_AGREED_SIGNED_REGISTER` with `agreed_register_record_sets_matched=true`. It **always keeps `whole_estate_software_complete=false`**, producer measurement truth and register authority unverified. Closing actual whole-estate completeness needs the actual authoritative estate/exception register, real native source coverage on all applicable surfaces and independent acceptance—not a synthetic signed fixture.

## 4. Existing custody and six-BOM architecture preserved

These are operator proof/qualification paths. No new network-job admission, privileged worker, imported completeness flag, standard-BOM claim or automatic graph edge is introduced. Original facts remain the source for NBOM/CBOM/TechBOM/HBOM/VBOM/**SBOM** projections; generic signed estate records do not become observed software facts. Existing official-schema export and tenant/RBAC/custody behavior remains covered by regression.

Windows and container server admission remain closed. The new namespace result does not qualify a Windows host, Docker/Kubernetes executor or physical HSM. Existing independent assessor/bank-acceptor signatures remain separate; source hashes are integrity/approval bindings, not measurement attestation or corporate independence.
