# OS & Kernel Intelligence Engine — Plan

## 1. What this engine does

The ZELNX OS & Kernel Intelligence Engine turns OS and kernel state into
evidence-backed cryptographic intelligence: OS identity, Kernel Crypto
API registrations, module state, provider/crypto-library inventory,
certificate metadata, disk-encryption metadata, hardware trust and
coverage (docs/os-kernel-intelligence/01_PRODUCT_SPEC.md).

## 2. Sequence (§15 — binding)

1. audit existing OS/hardware/network/binary discovery — DONE (this
   build): host_collection/oci_collection/windows_tpm hold the shared
   evidence spine; no kernel-crypto collectors existed;
2. kernel/OS crypto collectors — DONE for Phase 1 (this build);
3. map findings to the shared evidence model — DONE: findings carry
   observation type, source, digest, classification, limitations;
4. ONE canonical model — DONE: OSInventory/OSFinding (§10 shape);
5. Linux read-only collection first — DONE (§15 step 5);
6. integrate SBOM/CBOM/HBOM/TechBOM — NOT IMPLEMENTED;
7. test against actual local Linux configuration — DONE: the test
   battery runs the collector against the LIVE host and against the
   recorded real-host corpus;
8. eBPF runtime — NOT IMPLEMENTED (Tier 2, separately approved);
9. Windows/macOS after shared model validation — NOT IMPLEMENTED.

## 3. Future phases (recorded, not delivered)

- DB persistence (os_assets…os_coverage) and API routes;
- OS-CRYPTO-001…018 detection rules as evidence-backed checks;
- risk model R=f(S,E,X,B,C) with preserved factors and model version
  (never a multiplied "scientifically validated score");
- Tier 2 eBPF runtime monitoring with filters/retention/sampling;
- Windows (CNG/BCrypt/NCrypt/Schannel/CryptoAPI/CSP/KSP) and macOS
  (Security framework/Keychain APIs — protected storage files are never
  scraped) adapters.

## 4. House rules (standing)

- read-only by default; kernel instrumentation requires separate
  approval; never install a permanent kernel module;
- unavailable is recorded, never treated as disabled; a failed command
  is "unavailable or permission-denied", never proof of absence;
- /proc/crypto is an inventory of registered implementations — runtime
  usage is never confirmed (`runtime_usage_confirmed: false`);
- no secrets are ever collected: no plaintext, private keys, passwords,
  tokens, decrypted data, TLS session secrets, HSM material or full I/O
  buffers;
- randomness is never declared secure/insecure from one entropy counter;
- AF_ALG is never blanket-recommended for disabling — assess kernel
  version and use case;
- the three TLS findings stay distinct: supported / enabled-by-config /
  observed-negotiated;
- findings, not verdicts; severity is computed, never named.
