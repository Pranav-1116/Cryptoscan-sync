# Combined architecture — Network + Cloud + Vendor + Hardware + Cryptography in one system

The final architecture combines the five scanner domains under one control
plane (`services/universal_platform`). Everything below is **deterministic,
no AI** — the AI-assisted layer (§26 of this architecture) is excluded by
explicit product requirement; "unknown" is a first-class honest answer.

```
                    ZELNX CONTROL PLANE (services/universal_platform)
                              │
       ┌──────────────┬───────┼───────┬──────────────┐
       │              │       │       │              │
     Network        Cloud   Vendor  Hardware     Crypto
  (network_scanner) (cloud_scanner) (universal_vendor) (universal_crypto)
       │              │       │       │              │
       └──────────────┴───────┼───────┴──────────────┘
                              │
                    UniversalDiscoveryEngine   (§1 discover→identify→correlate→verify→monitor)
                              │
                       PlatformEventBus        (§18/§19 events → state → change → targeted rescan)
                              │
                         DriftEngine           (§20 baseline vs live, 9 categories)
                              │
                    CombinedBomProducer        (§21/§22 CycloneDX 1.6 CBOM + HBOM)
                              │
                     PlatformRiskEngine        (§29 eight-factor risk)
                              │
                   BlastRadiusAnalyzer         (§30 impact queries)
                              │
                    PlatformWhatIfEngine       (§31 what-if + migration plan)
                              │
                      SecurityControls         (§33 enforcement)
                              │
                       EvidenceChain           (§23 SHA-256 chained evidence)
```

## Section map

| § | Requirement | Implementation |
|---|---|---|
| 1 | Universal Discovery Engine (28 asset types, discover→identify→correlate→verify→monitor) | `universal_platform/discovery.py` — domain adapters (network/cloud/vendor/hardware/crypto) normalize into canonical assets (`assets.py` catalog, 40+ types), cross-domain correlation via identity keys (cert↔endpoint/lb/cloud, vm↔host, vendor↔product, hsm↔host), verification (SUSPECT not dropped), monitor plan |
| 2 | Universal Network Scanner (TCP/IP, IPv4/6, VLAN, routing, DNS, NAT, SD-WAN, device discovery, topology, segmentation) | `services/network_scanner` — `GlobalNetworkDiscoveryEngine` (SAFE/DEEP/AGGRESSIVE modes with authorization), TLS/SSH/IPsec/DNSSEC scanners, passive + active discovery, enterprise live agent |
| 3 | Universal Vendor Scanner (vendor-independent plugin framework) | `services/universal_vendor` — `VendorPluginFramework` (`plugin.py`, `plugins/`, `sdk.py`, `scan_modes.py`), fingerprint → capability → configuration → crypto detection |
| 4 | Universal Cloud Scanner (AWS/Azure/GCP resources, KMS/HSM/cert services) | `services/cloud_scanner` — aws/azure/gcp adapters, IaC, org discovery, `scan_live` (credential-scoped, read-only) |
| 5 | Universal Hardware Scanner (CPU…crypto accelerators; identity/firmware/capabilities/drift) | `services/universal_vendor/.../hardware/` — agent/network/API discovery, fingerprinting, TPM/HSM/secure-element, firmware, HBOM, live edge + drift |
| 6 | Cryptography Scanner (algorithms incl. PQC, versioned registry) | `services/universal_crypto` — registry (FIPS 203/204/205, HQC lifecycle, CycloneDX OIDs), 9-dataset accuracy platform |
| 7 | Multi-layer detection + evidence fusion → confidence | `universal_crypto` — 25 discovery sources, weighted fusion (`confidence.py`), correlator |
| 8 | Crypto library detection | `universal_crypto/library_fingerprints.py` (OpenSSL…PKCS#11, versions, evidence classes) |
| 9 | Source-code scanner (17→18 languages) | `universal_crypto/ast_engine.py` (18 languages incl. Dart, whitespace-tolerant, §5 precision) |
| 10 | Binary scanner (ELF/PE/Mach-O/WASM/firmware) | `universal_crypto/binary_engine.py` — imports/exports/symbols/strings/constants/fingerprints |
| 11 | Runtime scanner (capability vs usage) | `universal_crypto/runtime_engine.py` |
| 12–14 | TLS / SSH / VPN-IPsec scanners | `universal_crypto/protocol_engine.py` — IANA suites + ServerHello parse, SSH KEX/ciphers/MACs, IKEv2/ESP/AH |
| 15–16 | Certificate intelligence + trust store | `universal_crypto/certificate_intel.py` — lifecycle, SAN/EKU, trust chain, `expected_roots`, unexpected/untrusted/legacy anchors |
| 17 | Crypto dependency graph | `universal_crypto/dependency_graph.py` + `services/graph_engine` |
| 18 | Live 24/7 scanner (all domains → event bus → state → targeted scan → CBOM/HBOM) | `universal_platform/events.py` + per-domain live engines (crypto `live/`, hardware `live/`, network enterprise agent, cloud enterprise collector) |
| 19 | Event-driven scanning (NEW_DEVICE…VENDOR_CONFIGURATION_CHANGED) | `universal_platform/events.py` — 15 event types, owning-domain dispatch, targeted analysis steps |
| 20 | Drift detection (9 categories) | `universal_platform/drift.py` + `services/drift` |
| 21 | Live CBOM (CycloneDX-based) | `universal_platform/bom.py` + `universal_crypto/live/cbom.py` (CycloneDX 1.6, registry OIDs) |
| 22 | Live HBOM | `universal_vendor/.../hardware/hbom.py` + combined in `universal_platform/bom.py` |
| 23 | Evidence engine (asset/source/timestamp/observation/evidence/method/confidence/prev/current + hash chain) | `universal_platform/evidence.py` (SHA-256 chain, verify) + `services/evidence` |
| 24 | Accuracy engine (precision/recall/F1/FPR/FNR/coverage/unknown-rate per category) | `universal_crypto/accuracy.py` — 9 labeled datasets / 88 cases, mean F1 1.0; per-category algorithm/protocol/certificate/library/implementation/weak_crypto/pqc |
| 25 | Unknown crypto engine (AST→binary→library→runtime→human; never force classification) | `universal_crypto/unknown_detector.py` — UNKNOWN_CRYPTO queue, deep-analysis steps, human review; AI step excluded |
| 26 | AI crypto intelligence | **excluded by user requirement** (candidate → deterministic verification → finding only) |
| 27 | PQC readiness (current→quantum→alternative→library/hw/vendor/protocol→difficulty; 6 outputs) | `universal_crypto/pqc_readiness.py` + `universal_vendor/.../hardware` PQC verdicts |
| 28 | Crypto agility 0–100 | `universal_crypto/agility.py` + `services/agility` |
| 29 | Risk engine (8 factors → CRITICAL/HIGH/MEDIUM/LOW) | `universal_platform/risk.py` + `business_context` prioritization |
| 30 | Blast-radius analysis | `universal_platform/blast_radius.py` (BFS over correlation graph, business impact) |
| 31 | What-if crypto analysis → migration plan | `universal_platform/whatif.py` (checks deps/libraries/hardware/vendor/cloud, honest UNKNOWN) + `universal_crypto/simulator.py` |
| 32 | Global/enterprise architecture | this document + `universal_platform/engine.py` (`platform_pipeline`), API `/api/v1/platform/*` |
| 33 | Enterprise security controls | `universal_platform/security.py` (read-only default, scope, exclusions, maintenance windows, emergency stop, secrets never stored) + API RBAC |

## Using it

```bash
# one-shot pipeline (security gate → discover → risk → BOM → evidence)
PYTHONPATH="$(ls -d shared/* services/* | tr ':' ':')" \
  .venv/bin/python - <<'PY'
from universal_platform.engine import platform_pipeline
print(platform_pipeline({"network": {"assets": [...]}, "crypto": {...}}))
PY

# CLI
.venv/bin/python -m universal_platform.cli discover request.json --state-out state.json
.venv/bin/python -m universal_platform.cli blast --seed payments.internal --state state.json
.venv/bin/python -m universal_platform.cli whatif --current RSA --target ML-KEM-768 --state state.json
.venv/bin/python -m universal_platform.cli bom --state state.json
.venv/bin/python -m universal_platform.cli drift baseline.json live.json
.venv/bin/python -m universal_platform.cli security request.json

# API (RBAC crypto.read / crypto.manage)
POST /api/v1/platform/discover   GET /api/v1/platform/bom
POST /api/v1/platform/drift      POST /api/v1/platform/risk
POST /api/v1/platform/blast      POST /api/v1/platform/whatif
POST /api/v1/platform/security   GET  /api/v1/platform/evidence
GET  /api/v1/platform/scope
```

## Honest boundaries

- Network/cloud/vendor **live** scanning requires operator credentials or
  authorized scope; the platform consumes their reports. The adapters are
  pure — the whole pipeline is testable with structured input.
- Unknown stays unknown: `UNKNOWN`/`SUSPECT`/`PQC_UNKNOWN` are first-class
  and never auto-labeled secure or insecure.
- Secrets are never stored as scan evidence; key material is metadata-only.
