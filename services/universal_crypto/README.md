# Universal Cryptography Scanner

Deterministic, **no-AI** cryptography discovery and classification across
every source the platform touches — source code, binaries, shared
libraries, package dependencies, configuration, certificates, key
*metadata*, trust stores, TLS/SSH/IPsec, HSMs/TPMs, cloud, containers,
Kubernetes, firmware metadata and infrastructure-as-code.

Implements the Universal Cryptography Scanner spec (§1–§36) with the
AI-assisted classification layer (§32) **excluded**: every stage is a pure
function of evidence and explicit catalogs. "Unknown" is a first-class
answer — the engine never guesses and never labels unknown crypto secure
or insecure.

## Layout

| Module | Spec | What it does |
| --- | --- | --- |
| `registry.py` | §2 | Algorithm registry with NIST lifecycle/status (FIPS 203/204/205, HQC) + CycloneDX OIDs |
| `discovery.py` | §1 | 25 discovery sources, drafts, cross-source correlation |
| `ast_engine.py` | §4/§5 | Semantic detection, 18 languages, whitespace/quote tolerant, comment & custom-def filtering |
| `library_fingerprints.py` | §6/§8 | Library → version, evidence classes, CONFIRMED_IMPLEMENTATION |
| `binary_engine.py` | §7 | ELF/PE/WASM symbols/imports/strings/constants; evidence levels |
| `runtime_engine.py` | §9/§27 | Loaded vs used; capability ≠ usage |
| `protocol_engine.py` | §10–§12 | TLS (IANA suites + ServerHello), SSH, IPsec/VPN |
| `certificate_intel.py` | §13–§15 | Certificates, key metadata (never secrets), trust stores |
| `dependency_graph.py` | §16 | App → library → protocol → algorithm CBOM graph |
| `classification.py` | §17/§18 | 10 categories; quantum status + migration priority |
| `pqc_readiness.py` | §19 | CLASSICAL…PQC_READY + replacement → compatibility → readiness |
| `agility.py` | §20 | Crypto agility 0–100 (hard-coded 15 / configurable 75 / abstraction 95) |
| `hardcoded.py` | §21 | Hard-coded crypto → migration risk |
| `weak_crypto.py` | §22 | Policy-driven (NIST/FIPS/PCI-DSS/EU/UAE/ORG/BANK/CUSTOM) |
| `misconfig.py` | §23 | TLS/cert/DH/SSH/VPN/mode checks |
| `custom_crypto.py` | §24 | KNOWN_LIBRARY…UNKNOWN (never auto-labeled) |
| `randomness.py` | §25 | Weak RNG flagged only when it feeds crypto material |
| `key_lifecycle.py` | §26 | generate→store→use→rotate→backup→revoke→destroy |
| `confidence.py` | §28 | Weighted fusion (AST 30/LIB 20/BIN 20/CONFIG 15/RUNTIME 15) + deterministic calibration |
| `findings.py` | §29 | WHAT/WHERE/HOW/WHY/EVIDENCE/CONFIDENCE/IMPACT/RECOMMENDATION |
| `correlator.py` | §30 | Doc-mention suppression, dedupe, weak tagging |
| `unknown_detector.py` | §31 | UNKNOWN_CRYPTO_OPERATION queue → deep analysis |
| `accuracy.py` | §33 | Ground-truth platform: precision/recall/F1/FPR/FNR/coverage/unknown-rate |
| `live/` | §34/§35 | Event bus → state journal → targeted analysis → CycloneDX 1.6 CBOM → PQC risk |
| `simulator.py` | §36 | What-if migration projections |
| `cli.py` | §36 | `python -m universal_crypto.cli scan|accuracy` |

## Quick start

```bash
# scan source files/directories (auto-detects language by extension)
PYTHONPATH="$(ls -d shared/* services/* | tr '\n' ':')" \
  .venv/bin/python -m universal_crypto.cli scan services/scanner --policy NIST

# scan a full §36 JSON request
.venv/bin/python -m universal_crypto.cli scan request.json --policy FIPS

# machine-readable export for CI (full report as JSON)
.venv/bin/python -m universal_crypto.cli scan request.json --json -o report.json

# run the ground-truth accuracy platform
.venv/bin/python -m universal_crypto.cli accuracy
.venv/bin/python -m universal_crypto.cli accuracy --dataset certificates
```

## Accuracy

`accuracy_data/datasets/{known_crypto,known_noncrypto,obfuscated,
custom_crypto,real_world,weak_crypto,pqc_classification,certificates,
implementations}` hold labeled cases (9 datasets, 88 cases — the
certificate cases are real DER certificates, implementation cases cover
the §24 classifier); the §33 evaluator computes per-category and overall
metrics with vocabulary-based true negatives (`weak_crypto` exercises the
§22 policy classifier, `pqc_classification` the §18 quantum classifier —
including the honesty rule that unknown algorithms stay PQC_UNKNOWN).
Current regression targets (guarded by `tests/test_accuracy.py`):
all nine datasets at precision/recall/F1 = 1.0, FPR = 0.0;
`known_crypto` per-category (algorithm/protocol/library) F1 = 1.0.

## Live engine + API

Events (`CERT_NEW`, `CERT_RENEWED`, `ALGORITHM_DETECTED`,
`LIBRARY_UPGRADED`, `PQC_CAPABILITY_CHANGED`, …) drive a persistent
state journal; every ingest recomputes quantum status, readiness, agility
and risk and freezes a new versioned CycloneDX CBOM. API:
`/api/v1/crypto/live/*` (RBAC `crypto.read` / `crypto.manage` /
`crypto.ingest`), persistence via migration `0037` + `CryptoRepository`.
See `docs/decisions/ADR-015-universal-crypto-engine.md` and
`docs/api-reference/rest-api.md`.

## Tests

```bash
make test   # includes services/universal_crypto/tests (134 tests)
```
