# Architecture, provenance and isolation

## Three planes, no hidden truth shortcut

1. **Fixture plane:** deterministic organizations, systems, apps, services, dependency/provider graphs, network topology, public certificates, BOMs and intentionally conflicting declarations. IDs are stable and bank-scoped. The normal static scanner sees materialized source files only.
2. **Control plane:** independent source-template semantic expectations plus 35 difficult-case expectations per bank. The parent scorer reads these *after* collection. They are neither passed to the scanner nor reachable through its permitted paths. Sentinel-read denial is actually exercised inside the child. A public scenario's existence is not a discovery result.
3. **Measurement plane:** raw real collector findings, guard receipts, CPU/RSS/wall measurements and accuracy reports. These are distinct from generated runtime/network declaration exports. External normalized observations may be evaluated with `compare-facts`; the sandbox never manufactures such observations from the oracle.

No CryptoScan core logic is altered to improve these scores. Current static scoring is **algorithm-family per file**, not evidence of end-to-end CBOM correlation, ownership, key size, runtime attribution, production accuracy or operational capacity. Composite labels such as `SHA256withRSA` normalize to both families. Precision is TP/(TP+FP), recall TP/(TP+FN); negative-file FPR uses **completed negative files only**. Failed or missing negatives do not become true negatives. Missing positive findings remain false negatives and separately count as failed/missing files. A zero denominator produces null, not 100%.

## Evidence and BOM semantics

Evidence rows preserve ID, source, collector, timestamp, target, system, application, process, network endpoint, component, evidence type, raw reference, normalized fact, confidence and provenance. Generated timestamps use the explicit **2030 simulated clock**; actual executions retain their own wall-clock observations. `CONFIGURED`, `IMPORTED` and `VENDOR_DECLARED` fixture facts do not become `NETWORK_OBSERVED` or `RUNTIME_OBSERVED`. A field named `simulated_evidence_type` is explicitly a scenario model, not the row's actual evidence classification.

| BOM | Generated role | What it does not prove |
|---|---|---|
| NBOM | Zones, topology edges, endpoints and paths | Reachability, negotiated ciphers or packet capture |
| CBOM | CycloneDX 1.6 cryptographic-asset declarations | Actual use, completeness, algorithm implementation or FIPS validation |
| SBOM | CycloneDX 1.6 + SPDX 2.3 application/container/OS package exports | Loaded or executed dependency |
| TechBOM | Provider/library/version/dependency metadata | Active provider resolution |
| HBOM | Synthetic HSM/device/firmware/capability records | Real hardware interrogation or accreditation |
| VBOM | Fictional vendor product/capability assertions | Independent validation of vendor claims |

Offline official document schemas validate CycloneDX and SPDX documents. The four other projections are lab JSONL formats, **not claims of official universal BOM-schema certification**. Stale, duplicate, incomplete and conflicting declarations remain distinct. Different scopes/layers are not automatically contradictions: edge TLS termination and backend transport can differ legitimately. Same-scope conflicts preserve provenance; no automatic winner is fabricated.

The actual public PKI is root → intermediate → issuing → leaves. Certificate signatures are Ed25519, including leaves with public RSA/EC keys. SHA-1 signature scenarios are **declarations only**, not actual SHA-1-signed PEMs. Expiration/rotation labels use the simulated epoch; they are not assertions of wall-clock validity. Private keys are never serialized to the estate.

## Static isolation boundary

The child preloads normal scanner modules, then applies Landlock, `NoNewPrivs`, stackable seccomp, CPU/address-space/file-size limits and a scrubbed environment. Allowed paths are staged source, required scanner/package paths and runtime libraries, not the repository root, harness or oracle. Address-space limit is 2 GiB; CPU limit 600 seconds; per-file output limit 256 MiB; parent wall deadline 600 seconds with process-group termination. Socket creation is denied. The receipt must actually exist before the parent reports network denial; a pre-guard import failure remains UNKNOWN. The collector has a two-second per-file timeout.

This is a local, ordinary-user Linux containment measure, **not VM-grade confidentiality or a security certification**. The host kernel is trusted; host metadata side channels and malicious native-code exploits are not independently qualified. Do not accept arbitrary hostile estates. Boundary setup failure aborts collection; there is no host-wide scanner fallback.

## Actual live sample, separate from the generated estate

A diskless QEMU guest with **no external NIC**, loopback only, 256 MiB RAM and one TCG CPU ran two fixed TLS endpoints and the unchanged production TLS handshaker. TLS 1.2 and 1.3 negotiations and Python/OpenSSL SHA-256/HMAC operations were actually exercised. A refused service produced FAILED, not absence. Parent boot/network/mount identities remained unchanged.

The TLS handshaker had a **pre-existing user working-tree modification**, preserved and not published by this increment. “Unchanged” means not changed by the sandbox; the measured bundle binds that workspace hash, not necessarily clean HEAD. See the readiness source-provenance receipt; clean-published-checkout live requalification remains pending.

This is a narrow sample, **not 150 live banks**. The runtime operation witness is ordinary Python/OpenSSL, not the normal runtime-agent pipeline. Peer certificate authentication is not verified by this discovery handshaker. TLS 1.0/1.1, mTLS, SSH, IKE/IPsec, database/MQ/Kafka protocols, Java/.NET/Go/Rust runtime activity, actual HSM/PKCS#11 operations and PQC negotiation were **not executed**. HSM/KMS/payment/network protocol records outside that sample are declarations. PQC maturity 0–5 is a declared scenario label, not implemented cryptography.

## Packaging and review

Optional Compose packaging serves only the read-only public dashboard: nonroot, dropped capabilities, no-new-privileges, 128 MiB, 0.5 CPU, 32 PIDs, read-only filesystem, internal network and loopback published port. It never mounts `control`. Docker was unavailable here; this recipe is **not deployment-tested**. Its base image must be preloaded locally; no image pull is authorized. Native VM assets have pinned hashes, not independently verified signatures. SPDX schema provenance is retained; upstream license/provenance and independent security reviews remain release gates, not implied approvals.
