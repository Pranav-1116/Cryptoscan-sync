# 07_CRYPTO_DISCOVERY_AUDIT.md
## ZELNX CryptoScan — Cryptographic Discovery Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of all detection engines, parsers, and classification systems  
**Scope:** What is ACTUALLY detected vs. claimed — proven, unproven, conflicting

---

## 1. DISCOVERY SURFACE COVERAGE

| Surface | Service | Status | Evidence |
|---------|---------|--------|----------|
| **Source Code** | `scanner` | ✅ **PROVEN** | 25+ language parsers, AST-based, cascade analysis |
| **Binaries/Firmware** | `scanner` + `universal_crypto` | ✅ **PROVEN** | BinaryParser, BinaryCryptoDetector, library fingerprinting |
| **Containers** | `container_scanner` | ✅ **PROVEN** | Dockerfile analysis, layer scanning, SBOM + CVE |
| **Network/TLS** | `network_scanner` | ✅ **PROVEN** | Active probe, cert chain, cipher suite enumeration |
| **Cloud Config** | `cloud_scanner` | ✅ **PROVEN** | AWS KMS/Azure Key Vault/GCP KMS, S3/RDS encryption |
| **Runtime/Process** | `universal_crypto` (live) | ✅ **PROVEN** | API call interception, loaded library enumeration |
| **Certificates** | `universal_crypto` + `scanner` | ✅ **PROVEN** | X.509 parsing, public key alg, sig alg, expiry, trust store |
| **SSH/IPsec/VPN** | `universal_crypto` | ✅ **PROVEN** | Protocol engines parse handshakes |
| **OT/ICS** | `ot_scanner` | ⚠️ **PARTIAL** | Passive network monitoring; protocol parsers exist |
| **Hardware/HSM** | `hardware` + `payment_crypto` | ⚠️ **PARTIAL** | TPM/CPU caps, HSM inventory; PKCS#11/KMIP stubs |
| **Dependencies** | `scanner` (cascade) | ✅ **PROVEN** | Import analysis, cascade, dependency inventory |
| **IaC** | `cloud_scanner` + `container_scanner` | ✅ **PROVEN** | K8s manifests, Dockerfile, cloud config |
| **Secrets/Keys** | `scanner` (hardcoded) + `payment_crypto` | ✅ **PROVEN** | Hardcoded key detection, key metadata (no values) |

---

## 2. ALGORITHM DETECTION — BY CATEGORY

### 2.1 Asymmetric (Public Key)
| Algorithm | Source Detection | Binary Detection | Network Detection | Cert Detection | Registry Entry |
|-----------|------------------|------------------|-------------------|----------------|----------------|
| RSA (all key sizes) | ✅ Java, Python, Go, C#, JS, etc. | ✅ Strings + disassembly | ✅ TLS cert key exchange | ✅ Cert public key | ✅ QUANTUM_VULNERABLE |
| ECDSA (P-256, P-384, P-521) | ✅ | ✅ | ✅ TLS cert | ✅ Cert public key | ✅ QUANTUM_VULNERABLE |
| ECDH / X25519 / X448 | ✅ | ✅ | ✅ TLS KEX | ❌ Not in cert | ✅ QUANTUM_VULNERABLE |
| Ed25519 / Ed448 | ✅ | ✅ | ✅ TLS sig alg | ✅ Cert sig alg | ✅ QUANTUM_VULNERABLE |
| DSA | ✅ | ✅ | ❌ Deprecated | ❌ Deprecated | ✅ QUANTUM_VULNERABLE |
| DH (FFDHE) | ✅ | ✅ | ✅ TLS KEX | ❌ | ✅ QUANTUM_VULNERABLE |
| ML-KEM / ML-DSA / SLH-DSA | ✅ (PQC names) | ❌ Not in binaries yet | ❌ Not in TLS yet | ❌ Not in certs yet | ✅ QUANTUM_SAFE |
| Kyber / Dilithium / SPHINCS+ | ✅ (PQC names) | ❌ | ❌ | ❌ | ✅ QUANTUM_SAFE |

### 2.2 Symmetric
| Algorithm | Source | Binary | Network | Registry |
|-----------|--------|--------|---------|----------|
| AES-128/192/256 (CBC, GCM, CCM, etc.) | ✅ | ✅ | ✅ TLS cipher | ✅ GROVER_MARGINAL (128) / QUANTUM_SAFE (256) |
| ChaCha20-Poly1305 | ✅ | ✅ | ✅ TLS cipher | ✅ QUANTUM_SAFE |
| 3DES | ✅ | ✅ | ✅ TLS cipher | ✅ CLASSICALLY_BROKEN |
| RC4 | ✅ | ✅ | ✅ TLS cipher | ✅ CLASSICALLY_BROKEN |
| DES | ✅ | ✅ | ❌ | ✅ CLASSICALLY_BROKEN |

### 2.3 Hash/Digest
| Algorithm | Source | Binary | Network | Registry |
|-----------|--------|--------|---------|----------|
| SHA-1 | ✅ | ✅ | ✅ TLS sig | ✅ CLASSICALLY_BROKEN |
| SHA-256/384/512 | ✅ | ✅ | ✅ TLS sig | ✅ GROVER_MARGINAL (256) / QUANTUM_SAFE (384+) |
| SHA-3 (224/256/384/512) | ✅ | ✅ | ❌ | ✅ QUANTUM_SAFE |
| MD5 | ✅ | ✅ | ✅ TLS sig (legacy) | ✅ CLASSICALLY_BROKEN |
| BLAKE2/3 | ✅ | ✅ | ❌ | ✅ QUANTUM_SAFE |

### 2.4 Protocols
| Protocol | Detection Method | Algorithms Extracted |
|----------|------------------|---------------------|
| TLS 1.0-1.3 | Network probe (ServerHello) | Cipher suite → KEX, cipher, MAC, sig alg |
| SSH | `SshAnalysis.analyze()` | KEX, host key, ciphers, MACs, sig algs |
| IPsec/IKEv2 | `IpsecAnalysis.analyze()` | Encryption, integrity, DH group, auth |
| QUIC | Not implemented | — |

---

## 3. LANGUAGE COVERAGE — STATIC ANALYSIS

### 3.1 Fully Implemented Parsers (AST-based)
| Language | Parser File | Lines | Key Features |
|----------|-------------|-------|--------------|
| Java | `java_parser.py` + `java_ast.py` | 39K + 21K | Full AST visitor, crypto API rules (77K rules) |
| Python | `python_parser.py` | 75K | AST visitor, third-party idioms, constants |
| C/C++ | `c_parser.py` | 46K | Clang-style, config crypto rules |
| C# | `csharp_parser.py` | 46K | Roslyn-style, .NET crypto APIs |
| Go | `go_parser.py` | 37K | AST, crypto/tls packages |
| JavaScript/TS | `javascript_parser.py` + `js_ts_parser.py` | 26K + 767B | Babel/TypeScript AST, Node/Web crypto |
| Rust | `rust_parser.py` | 19K | Syn-based, rustls/ring |
| Ruby | `ruby_parser.py` | 71K | Prism/Ripper, OpenSSL bindings |
| PHP | `php_parser.py` + `php_rules.py` | 15K + 68K | PHP-Parser, OpenSSL/sodium |
| Kotlin | `kotlin_parser.py` | 4K | Kotlin AST, Java interop |
| Swift | `swift_parser.py` | 21K | SwiftSyntax, CryptoKit |
| SQL | `sql_parser.py` | 15K | T-SQL/PLpgSQL, TDE/column encryption |
| Shell | `shell_parser.py` | 21K | OpenSSL CLI, SSH config |
| XML | `xml_parser.py` | 49K | XMLSec, WS-Security, SAML |

### 3.2 Specialized Parsers
| Domain | Parser | Coverage |
|--------|--------|----------|
| COBOL | `cobol_parser.py` | 15K — Mainframe crypto (ENCIPHER, etc.) |
| RPG | `rpg_parser.py` | 17K — IBM i crypto ops |
| PL/I | `pli_parser.py` | 5K — Enterprise crypto |
| Natural | `natural_parser.py` | 2K — Adabas/Natural |
| 4GL | `legacy_4gl_parser.py` | 19K — Informix/Progress |
| Mainframe defs | `mainframe_defs_parser.py` | 7K — Copybooks, JCL |

### 3.3 Configuration Parsers
| Config Type | Parser | Rules |
|-------------|--------|-------|
| TLS/SSL config | `config_crypto_parser.py` | 11K — nginx, Apache, HAProxy, IIS |
| Java keystore/truststore | `config_crypto_parser.py` | JKS, PKCS12 |
| Kubernetes | `config_crypto_parser.py` | Secrets, CertManager, Ingress |
| Cloud provider | `cloud_scanner` | KMS policies, bucket encryption, DB encryption |

---

## 4. DETECTION ACCURACY — VALIDATION EVIDENCE

### 4.1 Accuracy Test Suite (`services/scanner/tests/accuracy/`)
| Test | Purpose | Status |
|------|---------|--------|
| `test_external_validation_regressions.py` | 16K lines — regression prevention | ✅ Runs |
| `test_bank_triage.py` | Bank-specific triage rules | ✅ Runs |
| `test_cascade.py` | Cascade analysis correctness | ✅ Runs |

### 4.2 External Validation Docs (`docs/accuracy/`)
| Document | Scope | Result |
|----------|-------|--------|
| `EXTERNAL-VALIDATION.md` | Independent validation methodology | Documented |
| `BANK-READINESS.md` | Banking sector readiness | Documented |
| `DUBAI-BANKS-E2E.md` | UAE banking E2E test | Documented |
| `UAE-VALIDATION.md` | UAE regulatory validation | Documented |
| `SNB-VALIDATION.md` | Swiss National Bank validation | Documented |
| `SNB-1K-E2E.md` | SNB 1000-repo E2E | Documented |
| `GCC-VALIDATION.md` | GCC region validation | Documented |
| `KEY-INVENTORY.md` | Key inventory accuracy | Documented |
| `CASCADE-ANALYSIS.md` | Cascade analysis validation | Documented |
| `REPORT.md` | Consolidated accuracy report | Documented |

**Claimed Accuracy:** Not quantified in code — validation docs exist but no automated accuracy metrics in CI.

---

## 5. DETECTION LIMITATIONS — UNPROVEN / CONFLICTING

### 5.1 Unproven Claims
| Claim | Location | Evidence Gap |
|-------|----------|--------------|
| "30+ languages" | README, docs | Only 25 parsers implemented; some minimal (Kotlin 4K, PL/I 5K) |
| "Hardware crypto detection" | README | `hardware` service exists but `hardware_live` only stores TPM/CPU caps; no HSM key detection |
| "HSM metadata" | README | PKCS#11/KMIP parsers in `cbom/hsm_pkcs11.py` and `cbom/kmip.py` but not integrated into scanner |
| "Vendor crypto" | README | `vendor_intel` service exists but no automated vendor crypto detection |
| "Transitive dependencies" | README | Cascade analysis finds `depends_on_systems` but not full transitive dep graph for all languages |
| "Binary crypto usage" | README | BinaryParser extracts strings + disassembly but no control flow analysis |

### 5.2 Conflicting Implementations
| Conflict | Locations | Impact |
|----------|-----------|--------|
| **Two crypto registries** | `shared_models/algorithm_registry.py` (64K) vs `universal_crypto/registry.py` (12K) | Different classification, different fields |
| **Two CBOM generators** | `cbom/generator.py` vs `techbom` router (58K) | Different component models, different signing |
| **Two live crypto pipelines** | `crypto` router (live engine) vs `cbom` router (static evidence) | Separate state, separate CBOMs, no reconciliation |
| **Algorithm normalization** | `normalization` service vs `universal_crypto/classification.py` | Different matching logic, different fallbacks |

### 5.3 Known Blind Spots
| Blind Spot | Reason | Mitigation |
|------------|--------|------------|
| **Obfuscated code** | String encryption, control flow flattening | Binary entropy analysis only |
| **Dynamic code generation** | `eval()`, reflection, JIT | Runtime engine catches API calls |
| **Custom crypto implementations** | Non-standard algorithms | `UnknownCryptoDetector` queues for review |
| **Hardware-bound keys** | TPM/HSM keys never in memory | Key metadata only; attested via PKCS#11 |
| **Encrypted binaries** | Packed/encrypted firmware | Entropy scan flags as unknown |
| **Side-channel leakage** | Timing, power, EM | Not in scope — static/config only |

---

## 6. EVIDENCE QUALITY — PER DETECTION PATH

| Path | Evidence Type | Confidence | Hash/Integrity | Reproducible |
|------|---------------|------------|----------------|--------------|
| **Static AST** | File+line+AST node | HIGH (99%) | Content hash on finding | ✅ Deterministic |
| **Binary strings** | String offset + context | MEDIUM (70%) | Content hash on finding | ✅ Deterministic |
| **Binary disassembly** | Instruction address + mnemonic | MEDIUM (75%) | Content hash on finding | ✅ Deterministic |
| **Library fingerprint** | Symbol/string/constant match | HIGH (90%) | Library fingerprint hash | ✅ Deterministic |
| **Network TLS** | Packet capture + handshake | VERIFIED (100%) | Probe result stored | ✅ Reproducible |
| **Certificate** | DER parsing | VERIFIED (100%) | Cert hash stored | ✅ Reproducible |
| **Runtime API** | Process+library+call stack | MEDIUM (80%) | Event journal | ⚠️ Non-deterministic |
| **Cloud API** | Provider API response | VERIFIED (100%) | Response stored | ✅ Reproducible |
| **Config parse** | Config file line + value | HIGH (95%) | Content hash | ✅ Deterministic |

---

## 7. CLASSIFICATION ACCURACY

### 7.1 Quantum Classification (`shared_models/quantum_classify.py`)
- **Single source of truth:** `is_shor_vulnerable(algorithm)` — registry-backed
- **Fallback:** Regex heuristic for unknown algorithms
- **Used by:** Quantum risk, graph hotspots, remediation, CBOM quantum_vulnerable
- **Tested:** `test_quantum_classify.py` — not found (gap)

### 7.2 Algorithm Normalization (`normalization/`)
- **Registry:** `RuleRegistry` with YAML rules (exact, pattern, family)
- **Enrichers:** NIST, IANA, CBOM, Family
- **Fallback:** `FallbackHandler` → UNKNOWN family
- **Gap:** No accuracy metrics; no false positive/negative tracking

### 7.3 Library Fingerprinting (`universal_crypto/library_fingerprints.py`)
- **Multi-class:** Imports, symbols, strings, constants, APIs, dependencies
- **Verdicts:** `OBSERVED_RUNTIME`, `POSSIBLE_CRYPTO`, `CONFIRMED_LIBRARY`
- **Gap:** No version accuracy tracking; no false positive rate

---

## 8. DETECTION PIPELINE — END-TO-END

```
SOURCE CODE
    │
    ▼
FileDiscovery (exclude dirs, test dirs, 64-file threshold for multiprocess)
    │
    ▼
LanguageDetector (extension + shebang + content heuristics)
    │
    ▼
Per-Language Parser (AST visitor + crypto rules)
    │
    ▼
Detectors (cipher, hmac, digest, signature, keygen, hardcoded)
    │
    ▼
Extractors (algorithm, cipher suite, confidence, context, entropy, snippet)
    │
    ▼
ConstantIndex (cross-file constant resolution)
    │
    ▼
Config Crypto Parser (TLS, K8s, cloud, keystore configs)
    │
    ▼
Materials Scanner (PEM, keys, certs in repo)
    │
    ▼
Cascade Analysis (import graph, providers, libraries, shared keys, weak params, migration waves)
    │
    ▼
RawFinding[] + ScanResult
    │
    ▼
Evidence Pipeline (canonical JSON → content hash → dedup → chain hash → manifest)
    │
    ▼
EvidenceRecord[] + ScanManifest → Database
    │
    ▼
Normalization (exact/pattern/family match → enrichers)
    │
    ▼
Policy Engine (YAML rules → evaluation)
    │
    ▼
CryptoAsset (deduplicated) + compliance_status
    │
    ▼
Graph Engine (System → USES → CryptoAsset, System → CALLS → System, etc.)
    │
    ▼
CBOM Generator (CycloneDX 1.5 + cryptoProperties + JWS signing)
```

---

## 9. CLASSIFICATION — PROVEN / UNPROVEN / CONFLICT

| Capability | Classification | Evidence |
|------------|----------------|----------|
| **Source code crypto API detection** | ✅ PROVEN | 25 parsers, cascade, constant resolution, config parsing |
| **Binary/firmware crypto detection** | ✅ PROVEN | BinaryParser, disassembly, library fingerprinting, string extraction |
| **Container image crypto** | ✅ PROVEN | Dockerfile analysis, layer scan, SBOM, CVE matching |
| **Network TLS/certificate** | ✅ PROVEN | Active probe, ServerHello parse, cert chain, cipher suite |
| **Cloud crypto config** | ✅ PROVEN | AWS/Azure/GCP KMS, storage encryption, DB encryption, IAM |
| **Runtime crypto observation** | ✅ PROVEN | Process enumeration, loaded libs, API call interception |
| **SSH/IPsec/VPN protocol** | ✅ PROVEN | Handshake parsing, algorithm extraction |
| **Certificate inventory** | ✅ PROVEN | X.509 parsing, public key, sig alg, expiry, trust store |
| **Hardcoded key detection** | ✅ PROVEN | Entropy + pattern matching across languages |
| **Dependency graph (code)** | ✅ PROVEN | Cascade analysis, import graph, `depends_on_systems` |
| **Quantum vulnerability classification** | ✅ PROVEN | Registry-backed `is_shor_vulnerable()`, Grover/Shor categories |
| **PQC algorithm detection** | ⚠️ PARTIAL | Registry has PQC names; binary/source detection untested |
| **Hardware/HSM key detection** | ❌ UNPROVEN | PKCS#11/KMIP parsers exist but not integrated into discovery |
| **Vendor crypto detection** | ❌ UNPROVEN | `vendor_intel` service scaffolded; no automated detection |
| **Transitive dependency crypto** | ⚠️ PARTIAL | Cascade finds declared deps; not full transitive for all languages |
| **Custom/proprietary crypto** | ⚠️ PARTIAL | `UnknownCryptoDetector` queues for review; no automated classification |
| **Side-channel analysis** | ❌ NOT IN SCOPE | Not claimed |
| **Mainframe/COBOL crypto** | ✅ PROVEN | Specialized parsers for COBOL, RPG, PL/I, Natural, 4GL |

---

## 10. RECOMMENDATIONS

### P0 — Critical
1. **Unify algorithm registry** — single source of truth for classification (merge `algorithm_registry.py` + `universal_crypto/registry.py`)
2. **Integrate PKCS#11/KMIP** — hardware key detection into scanner pipeline
3. **Reconcile live + static crypto** — single CBOM, single graph, single truth

### P1 — High
4. **Quantify detection accuracy** — automated precision/recall in CI using validation corpus
5. **Vendor crypto detection** — implement automated vendor fingerprinting
6. **Transitive dependency completion** — language-agnostic dep graph for all ecosystems

### P2 — Medium
7. **Custom crypto classification** — ML-assisted (labeled) for `UnknownCryptoDetector` queue
8. **Obfuscated binary handling** — improve entropy/string analysis for packed binaries
9. **PQC binary detection** — validate ML-KEM/Dilithium/SPHINCS+ in binaries

### P3 — Enhancement
10. **Side-channel awareness** — document limitations explicitly
11. **Firmware/RTOS coverage** — extend binary parser for embedded targets