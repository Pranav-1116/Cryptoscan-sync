# ADR-015: Deterministic (no-AI) Universal Cryptography Scanner

- **Status**: Accepted
- **Date**: 2026-08-31
- **Applies to**: `services/universal_crypto`, `services/api` (`/crypto`), `services/database` (migration 0037)
- **Spec**: Universal Cryptography Scanner (§1–§36), with the AI-assisted
  classification layer (§32) **excluded by explicit user requirement** —
  "now build this but dont use ai".

## Context

The platform must discover and classify cryptography across every source it
touches — source code, binaries, shared libraries, package dependencies,
configuration, certificates, key *metadata*, trust stores, TLS/SSH/IPsec,
databases, HSMs/TPMs, network devices, cloud, containers/Kubernetes,
firmware metadata, CI/CD and IaC — and continuously answer two questions:

1. **What crypto exists** (algorithm, primitive, protocol, library,
   implementation, key, certificate, provider, capability)?
2. **How risky is it** — classical status, quantum-vulnerability, PQC
   readiness, agility, weak/deprecated per policy, misconfiguration,
   custom-crypto, randomness, key lifecycle — with a confidence that is
   *explainable* and a *live* picture that is always current?

The spec's §32 proposed an AI-assisted secondary reasoning layer. The user
explicitly rejected any AI: every stage must be a pure function of evidence
and explicit catalogs.

## Decision

### 1. Deterministic catalog-driven engine — no AI anywhere

Every detector is a pure function of (input, catalog, policy). No learned
models, no heuristics trained on data, no probabilistic classifiers.
"Unknown" is a first-class answer (`UNKNOWN_CRYPTO_OPERATION`,
`PQC_UNKNOWN`, `ImplementationClass.UNKNOWN`) — the engine never guesses
and never labels unknown crypto secure or insecure.

### 2. Registry with lifecycle status, not a boolean

`universal_crypto/registry.py` extends the shared algorithm registry with
NIST lifecycle/status: ML-KEM-512/768/1024 → STANDARDIZED (FIPS 203),
ML-DSA-44/65/87 → STANDARDIZED (FIPS 204), SLH-DSA-128S/192S/256S →
STANDARDIZED (FIPS 205), HQC-128/192/256 → SELECTED_FOR_STANDARDIZATION
(2025); Kyber/Dilithium/SPHINCS+ are LEGACY aliases. Quantum status per
family (NIST IR 8547): asymmetric → QUANTUM_VULNERABLE (Shor),
symmetric/hash/MAC/KDF/XOF → QUANTUM_SAFE (Grover). Every entry carries its
CycloneDX cryptography-registry OID so the CBOM speaks the ecosystem's
representation.

### 3. Semantic detection over name-matching

Source detection (§4/§5) matches whole-file text with whitespace-tolerant,
dotted API patterns per language (18 languages), but reports only real API
call sites: comment lines and `custom_hash`-style definitions are never
auto-classified. Library fingerprinting (§6/§8) keys off
imports/symbols/APIs/dependency manifests/version strings; binary
detection (§7) tags evidence levels (STRING < SYMBOL < IMPORT < CONSTANT <
FINGERPRINT) and never claims certainty from a string match alone.
Runtime observation (§9/§27) separates *loaded* from *used*: capabilities
(support) and usage (exercised) are separate datasets.

### 4. Policy-driven weak/deprecated classification

No universal "weak/strong" judgment (§22): the same algorithm can be
ALLOWED under NIST and DEPRECATED under EU (e.g. RSA-2048). Policies are
explicit tables (NIST/FIPS/PCI-DSS/EU/UAE/ORG/BANK/CUSTOM) selected per
scan; `custom_rules` extends CUSTOM.

### 5. Explainable confidence, calibrated on a labeled corpus

Confidence (§28) is a weighted fusion of evidence classes (AST 30 /
LIBRARY 20 / BINARY 20 / CONFIG 15 / RUNTIME 15; confirmatory kinds +10;
bands CONFIRMED ≥95 / HIGH ≥85 / MEDIUM ≥70 / LOW ≥50). The weights are
**fitted deterministically** to a 50-case labeled calibration corpus
(`accuracy_data/calibration_corpus.json`) via coordinate ascent — the fit
is reproducible and stays within one step of the spec-seeded defaults.
Every finding carries WHAT / WHERE / HOW_DETECTED / WHY_CLASSIFIED /
EVIDENCE / CONFIDENCE / IMPACT / RECOMMENDATION.

### 6. Ground-truth accuracy platform

`accuracy_data/datasets/{known_crypto,known_noncrypto,obfuscated,
custom_crypto,real_world}` hold labeled cases; the §33 evaluator computes
per-category and overall precision / recall / F1 / FPR / FNR / coverage /
unknown-rate with vocabulary-based true negatives. Empty-vs-empty cases
count as perfect (nothing expected, nothing missed).

### 7. Live engine with persistent journal + versioned CBOM

§34/§35: events → `LiveCryptoStateEngine` (journal + `state_at()` replay)
→ targeted recalculation (CERT_RENEWED → signature change → PQC status →
risk) → `LiveCbomProducer` (CycloneDX 1.6, serial
`urn:uuid:live-cbom-{asset}-{version}`, cryptography components with OIDs)
→ risk 0–100 (vulnerable+used +40, vulnerable+unused +20, vulnerable
readiness +30, expiring/revoked cert +10, unknown-crypto +10; HIGH ≥70 /
MEDIUM ≥40 / LOW >0 / NONE). Persistence: migration 0037
(`crypto_live_states` + `crypto_live_events`) + `CryptoRepository`; the
database is the current truth, the journal reconstructs any past state.
API: `/api/v1/crypto/live/*` with RBAC `crypto.read` (all roles) /
`crypto.manage` (superadmin, ciso, security_analyst) / `crypto.ingest`
(superadmin, ciso, scanner).

## Consequences

- **Positive**: fully deterministic and auditable; explainable findings;
  no hallucinated "secure/insecure" labels; accuracy is measurable and
  regression-tested (all detection datasets at precision/recall/F1 1.0,
  FPR 0.0; mean F1 1.0 across the five datasets); the live engine gives a
  continuous, versioned CBOM that tracks certificate/algorithm changes.
- **Negative**: no semantic reasoning beyond the catalogs — novel or
  obfuscated patterns surface as UNKNOWN_CRYPTO_OPERATION and require deep
  binary/AST/runtime/human review (a queue is provided, but the AI layer
  that could pre-classify it is deliberately absent).
- **Negative**: catalog coverage must be maintained as algorithms and
  policies evolve; new protocols/libraries need catalog entries + labeled
  cases before they can be scored.
- **Safety**: private keys and secret material are never collected
  (§14); trust-store analysis reports anchors only.

## Alternatives considered

- **AI-assisted secondary classification (§32)**: rejected by the user —
  "dont use ai". Would have added semantic generalization at the cost of
  determinism, explainability and auditability.
- **Static boolean PQC flag**: rejected — lifecycle (standardization
  status) and per-family quantum status are separate concerns.
- **Name-grep detection**: rejected — false positives from comments/docs
  and false negatives from cross-line imports motivated the semantic +
  evidence-fusion design.
