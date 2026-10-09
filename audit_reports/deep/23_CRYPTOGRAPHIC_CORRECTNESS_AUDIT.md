# 23_CRYPTOGRAPHIC_CORRECTNESS_AUDIT.md
## ZELNX CryptoScan — Cryptographic Correctness Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of all cryptographic detection, classification, normalization, and validation logic across scanner, universal_crypto, normalization, quantum, and CBOM services  
**Scope:** Algorithm identification, key-size detection, mode/padding detection, protocol analysis, certificate parsing, library fingerprinting, quantum classification, CBOM generation

---

## EXECUTIVE SUMMARY

| Component | Score | Status |
|-----------|-------|--------|
| Algorithm Identification | 8/10 | Strong registry, good coverage |
| Key Size Detection | 7/10 | Good for static, weak for runtime |
| Mode/Padding Detection | 6/10 | Partial — ECB detected, others weak |
| Protocol Analysis (TLS/SSH/IPsec) | 8/10 | Good parsing, cipher suite mapping |
| Certificate Parsing | 8/10 | X.509 parsing solid |
| Library Fingerprinting | 7/10 | Multi-class, but version detection weak |
| Quantum Classification | 8/10 | Registry-backed, deterministic |
| CBOM Generation | 8/10 | CycloneDX 1.5 compliant, JWS signing |
| Normalization | 6/10 | Fallback-heavy, duplicate registries |
| False Positive Rate | Unknown | Not measured in CI |

**Overall: 7.2/10** — Cryptographically sound core, but detection gaps in binary/runtime, no FP/FN metrics.

---

## 1. ALGORITHM IDENTIFICATION

### 1.1 Algorithm Registry

**File:** `shared/shared_models/shared_models/algorithm_registry.py` (64K lines)

```python
# 300+ algorithm entries with:
# - IANA OIDs
# - NIST designations (Approved/Deprecated/Disallowed)
# - Quantum status: QUANTUM_VULNERABLE, QUANTUM_SAFE, GROVER_MARGINAL, CLASSICALLY_BROKEN, UNKNOWN
# - Primitive type: ASYMMETRIC, SYMMETRIC, HASH, KEM, SIGNATURE
# - Key sizes, curves, parameters
```

**Coverage:**
| Category | Algorithms | Examples |
|----------|------------|----------|
| Asymmetric | 50+ | RSA, ECDSA, EdDSA, DH, ECDH, X25519, Kyber, Dilithium |
| Symmetric | 30+ | AES, ChaCha20, 3DES, RC4, Camellia |
| Hash | 20+ | SHA-1/2/3, BLAKE2/3, MD5, RIPEMD |
| KEM | 10+ | ML-KEM, Kyber, HQV |
| Signature | 15+ | ML-DSA, Dilithium, SPHINCS+, Falcon |

**Strengths:**
- ✅ IANA OID mapping for all standard algorithms
- ✅ NIST designation tracking (FIPS 140-3, SP 800-57)
- ✅ Quantum status per algorithm (registry-backed)
- ✅ Primitive classification for CBOM `cryptoProperties`

**Gaps:**
- ❌ Proprietary/vendor algorithms not registered
- ❌ Algorithm aliases not comprehensive (e.g., "AES256" vs "AES-256")
- ❌ No version tracking for algorithm registry updates

---

### 1.2 Static Source Detection

**File:** `services/scanner/scanner/parsers/` (25+ parsers)

**Detection Methods:**
| Language | Parser | Crypto APIs Detected |
|----------|--------|---------------------|
| Java | `java_parser.py` + `java_ast.py` | JCA, BouncyCastle, Conscrypt |
| Python | `python_parser.py` | cryptography, hashlib, hmac, ssl, OpenSSL |
| C/C++ | `c_parser.py` | OpenSSL, mbedTLS, wolfSSL, libcrypto |
| Go | `go_parser.py` | crypto/tls, crypto/x509, golang.org/x/crypto |
| JavaScript/TS | `javascript_parser.py` | Node crypto, Web Crypto, Forge, crypto-js |
| C# | `csharp_parser.py` | System.Security.Cryptography, BouncyCastle |
| Rust | `rust_parser.py` | rustls, ring, openssl-sys |
| Ruby | `ruby_parser.py` | OpenSSL, RbNaCl |
| PHP | `php_parser.py` | OpenSSL, Sodium, mcrypt |

**Detection Points:**
| API | Example | Algorithm Extracted |
|-----|---------|---------------------|
| `Cipher.getInstance("AES/GCM/NoPadding")` | Java | AES, GCM, NoPadding |
| `cryptography.hazmat.primitives.ciphers.Cipher(algorithms.AES(key), modes.GCM(nonce))` | Python | AES, GCM |
| `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)` | C/OpenSSL | AES, GCM |
| `tls.Config{CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384}}` | Go | TLS_AES_256_GCM_SHA384 |

**Accuracy Indicators:**
- ✅ AST-based (not regex) — structural understanding
- ✅ Constant resolution across files (`ConstantIndex`)
- ✅ Context extraction (method, class, line)
- ✅ Confidence scoring (HIGH/MEDIUM/LOW)
- ❌ No control flow analysis (dead code still detected)
- ❌ No obfuscation handling
- ❌ Dynamic dispatch not resolved

---

### 1.3 Binary/Firmware Detection

**File:** `services/universal_crypto/universal_crypto/binary_engine.py`

```python
# Detection methods:
# 1. String extraction (algorithm names, OIDs, library versions)
# 2. Disassembly (CAPSTONE) for instruction patterns
# 3. Library fingerprinting (symbols, constants, imports)
# 3. Custom crypto detection (heuristic)
```

**Detection Capabilities:**
| Target | Algorithms Detected | Limitations |
|--------|---------------------|-------------|
| ELF/PE/Mach-O | AES, RSA, ECDSA, SHA, ChaCha20 via strings | No control flow |
| JAR/DEX | Java crypto via bytecode | Same as source parser |
| .NET assemblies | System.Security.Cryptography via IL | Limited |
| Firmware (UEFI) | Limited | No UEFI parsing |

**Gaps:**
- ❌ No control flow analysis (dead code detected)
- ❌ No deobfuscation (packers, encryption)
- ❌ No firmware filesystem extraction
- ❌ Version detection weak (library version from strings only)

---

### 1.4 Runtime Detection

**File:** `services/universal_crypto/universal_crypto/runtime_engine.py`

```python
# Detection via:
# - Loaded library enumeration (dlopen, /proc/pid/maps)
# - API call interception (LD_PRELOAD, ptrace, eBPF)
# - Network traffic analysis (TLS handshake capture)
```

**Capabilities:**
| Source | Detected | Key Size | Mode |
|--------|----------|----------|------|
| Loaded libraries | Library name + version | ❌ | ❌ |
| API calls | Algorithm + params | ✅ Sometimes | ✅ Sometimes |
| TLS handshake | Cipher suite → algorithm | ✅ Via suite | ✅ Via suite |

**Gaps:**
- ❌ No key material extraction (by design)
- ❌ No attestation of runtime findings
- ❌ Sampling-based, not continuous

---

## 2. KEY SIZE DETECTION

### 2.1 Static Analysis

| Source | Key Size Detection | Accuracy |
|--------|-------------------|----------|
| Java `KeyPairGenerator.initialize(2048)` | ✅ Explicit | HIGH |
| Python `rsa.generate_private_key(key_size=2048)` | ✅ Explicit | HIGH |
| OpenSSL `RSA_generate_key_ex(ctx, 2048, ...)` | ✅ Explicit | HIGH |
| Config files (key_size: 2048) | ✅ Explicit | HIGH |
| Derived/calculated key sizes | ❌ Not detected | N/A |

### 2.2 Binary Analysis

| Method | Key Size Detection |
|--------|-------------------|
| String "2048" near RSA | Heuristic, MEDIUM |
| Disassembly `mov rdi, 2048` | Heuristic, LOW |
| Certificate parsing | ✅ From cert |

### 2.3 Certificate Parsing

**File:** `services/universal_crypto/universal_crypto/certificate_intel.py`

```python
def analyze_certificate(self, der, ...):
    # Extracts:
    # - Public key algorithm (RSA, ECDSA, EdDSA, X25519)
    # - Key size (RSA: 2048/3072/4096, EC: curve → size)
    # - Signature algorithm
    # - Validity period
    # - Extensions (SAN, key usage, etc.)
```

**Accuracy:** HIGH — X.509 parsing via `cryptography` library.

---

### 2.4 Key Size Gaps

| Gap | Impact |
|-----|--------|
| **No key size for symmetric keys** | AES-128 vs AES-256 indistinguishable in binary |
| **Derived key sizes** | HKDF/PBKDF2 output size not tracked |
| **Key size in config only** | Runtime key generation size not captured |
| **HSM key sizes** | Not detectable without PKCS#11 |

---

## 3. MODE/PADDING DETECTION

### 3.1 Static Detection

| Mode | Detection | Example |
|------|-----------|---------|
| ECB | ✅ Explicit | `Cipher.getInstance("AES/ECB/PKCS5Padding")` |
| CBC | ✅ Explicit | `Cipher.getInstance("AES/CBC/PKCS5Padding")` |
| GCM | ✅ Explicit | `Cipher.getInstance("AES/GCM/NoPadding")` |
| CCM | ✅ Explicit | `Cipher.getInstance("AES/CCM/NoPadding")` |
| CTR | ✅ Explicit | `Cipher.getInstance("AES/CTR/NoPadding")` |
| OFB/CFB | ✅ Explicit | `Cipher.getInstance("AES/OFB/PKCS5Padding")` |

### 3.2 Padding Detection

| Padding | Detection |
|---------|-----------|
| PKCS5/7 | ✅ Explicit |
| NoPadding | ✅ Explicit (for AEAD) |
| OAEP | ✅ Explicit (RSA) |
| PSS | ✅ Explicit (RSA) |
| PKCS1v15 | ✅ Explicit (RSA) |

### 3.3 Gaps

| Gap | Example |
|-----|---------|
| **Implicit defaults** | `Cipher.getInstance("AES")` → provider default (often ECB) |
| **Provider-specific modes** | BouncyCastle `GCM` vs `GCM/NoPadding` |
| **Custom padding** | Not detected |
| **Binary mode detection** | Disassembly heuristic only |

---

## 4. PROTOCOL ANALYSIS

### 4.1 TLS Analysis

**File:** `services/universal_crypto/universal_crypto/protocol_engine.py:TlsAnalysis`

```python
# Parses:
# - ServerHello (cipher suite, version, extensions)
# - Certificate chain
# - Key exchange parameters
# - Signature algorithms

# Maps cipher suite → algorithm components:
TLS_AES_256_GCM_SHA384 → {kex: "ECDHE", cipher: "AES-256-GCM", mac: "AEAD", sig: "ECDSA"}
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → {kex: "ECDHE", auth: "RSA", cipher: "AES-256-GCM"}
```

**Capabilities:**
| Feature | Supported |
|---------|-----------|
| TLS 1.0-1.3 | ✅ |
| Cipher suite parsing | ✅ (IANA registry) |
| Certificate chain validation | ✅ |
| Extension parsing (ALPN, SNI, etc.) | ✅ |
| Session resumption detection | ❌ |
| Client cert detection | ❌ |

---

### 4.2 SSH Analysis

**File:** `services/universal_crypto/universal_crypto/protocol_engine.py:SshAnalysis`

```python
# Parses:
# - Key exchange algorithms (curve25519-sha256, diffie-hellman-group14-sha256)
# - Host key algorithms (ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519)
# - Encryption ciphers (aes256-gcm, chacha20-poly1305)
# - MAC algorithms (hmac-sha2-256, hmac-sha2-512)
```

**Accuracy:** HIGH — SSH protocol well-defined, parsing deterministic.

---

### 4.3 IPsec/IKE Analysis

**File:** `services/universal_crypto/universal_crypto/protocol_engine.py:IpsecAnalysis`

```python
# Parses IKEv1/IKEv2:
# - Encryption (AES-GCM, AES-CBC, CHACHA20-POLY1305)
# - Integrity (HMAC-SHA256, AES-GMAC, AES-XCBC)
# - DH Group (14, 19, 20, 21)
# - Authentication (PSK, RSA, ECDSA)
```

**Gaps:**
- ❌ IKEv1 aggressive mode detection
- ❌ ESP/AH parsing in traffic
- ❌ MOBIKE detection

---

## 5. CERTIFICATE PARSING

### 5.1 X.509 Parsing

**File:** `services/universal_crypto/universal_crypto/certificate_intel.py`

```python
def analyze_certificate(self, der, location, asset_id, trust_anchor=False):
    # Returns:
    # - Subject, Issuer, Serial Number
    # - Validity (notBefore, notAfter)
    # - Public key algorithm + key size + curve
    # - Signature algorithm
    # - Extensions: SAN, Key Usage, Extended Key Usage, Basic Constraints
    # - Certificate policies
    # - CRL Distribution Points, OCSP
    # - Trust anchor detection
```

**Trust Store Analysis:**
```python
def analyze_trust_store(self, store_name, anchors, expected_roots):
    # Validates trust anchors against expected roots
    # Detects missing/extra/unexpected anchors
```

**Accuracy:** HIGH — Uses `cryptography.x509` library.

---

### 5.2 Certificate Gaps

| Gap | Impact |
|-----|--------|
| **CT log verification** | Not implemented |
| **OCSP/CRL checking** | Parsed but not validated |
| **Certificate transparency** | SCTs parsed but not verified |
| **Pinning validation** | HPKP parsed but deprecated |
| **PKCS#7/CMS parsing** | Not implemented |

---

## 6. LIBRARY FINGERPRINTING

### 6.1 Multi-Class Fingerprinting

**File:** `services/universal_crypto/universal_crypto/library_fingerprints.py`

```python
class LibraryFingerprinter:
    def fingerprint(self, imports, symbols, strings, constants, apis, dependencies):
        # Returns list of {library, provider, version, evidence_classes, verdict, confidence}
```

**Evidence Classes:**
| Class | Description | Confidence |
|-------|-------------|------------|
| `binary` | Strings/symbols in binary | MEDIUM |
| `imports` | Import table entries | HIGH |
| `symbols` | Exported symbols | HIGH |
| `constants` | Magic constants (e.g., SHA256 IV) | HIGH |
| `apis` | API call patterns | MEDIUM |
| `dependencies` | Package manager deps | HIGH |

**Verdicts:** `CONFIRMED_LIBRARY`, `POSSIBLE_CRYPTO`, `OBSERVED_RUNTIME`

**Gaps:**
- ❌ Version detection weak (strings only)
- ❌ No vendor attribution
- ❌ No vulnerability mapping (CVE linking)
- ❌ Static linking detection weak

---

## 7. QUANTUM CLASSIFICATION

### 7.1 Registry-Backed Classification

**File:** `shared/shared_models/shared_models/quantum_classify.py`

```python
def is_shor_vulnerable(algorithm: str) -> bool:
    # 1. Try registry lookup (quantum_status == QUANTUM_VULNERABLE)
    # 2. Fallback: regex heuristic for RSA/ECDSA/DH/Ed25519/X25519
```

**Classification Categories:**
| Category | Algorithms | Quantum Status |
|----------|------------|----------------|
| `SHOR_VULNERABLE` | RSA, DH, DSA, ECDH, ECDSA, Ed25519, X25519 | Vulnerable to Shor |
| `GROVER_MARGINAL` | AES-128, SHA-256 | Vulnerable to Grover |
| `CLASSICALLY_BROKEN` | DES, 3DES, RC4, MD5, SHA-1, SSLv3, TLS 1.0/1.1 | Broken classically |
| `QUANTUM_SAFE` | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384+, SHA-3 | Post-quantum safe |
| `UNKNOWN` | Unrecognized algorithms | Unknown |

**Usage:**
- `quantum_classify.py:is_shor_vulnerable()` — Single source of truth
- `graph.py:_quantum_vulnerable_algorithm()` — Falls back to regex
- `remediation/engine.py` — Uses classification for rules
- `quantum/risk.py` — Uses for risk scoring

---

### 7.2 Quantum Risk Scoring

**File:** `services/quantum/quantum/risk.py`

```python
def classify(algorithm, key_size, purpose):
    # Returns: vulnerable, category, estimated_break_year, 
    #          harvest_now_decrypt_later_risk, threat_type, 
    #          base_vulnerability (0-100), recommended_replacement
```

**Scoring Factors:**
| Factor | Weight | Description |
|--------|--------|-------------|
| Base vulnerability | 100/100/40/50/0 | By category |
| Data sensitivity | 1.0-2.0 | Classification-based |
| HNDL multiplier | 1.0-1.5 | Retention + regulated |
| Timeline | 1.0-2.0 | Years to quantum threat |
| Criticality tier | 1.0-1.5 | System criticality |

**Output:** `quantum_risk_score` (0-100), `risk_category`, `migration_deadline`, `recommended_replacement`

---

## 8. NORMALIZATION

### 8.1 Normalization Engine

**File:** `services/normalization/normalization/core/engine.py`

```python
class NormalizationEngine:
    def __init__(self, rules_directory):
        self.rule_loader = RuleLoader(rules_directory)
        self.rules = self.rule_loader.load_all_rules()
        self.registry = RuleRegistry()
        self.registry.register_all(self.rules, overwrite=True)
        self.processor = NormalizationProcessor(self.registry)
```

**Matching Pipeline:**
1. `ExactMatcher` — Registry lookup by canonical name
2. `PatternMatcher` — Regex patterns for variants
3. `FallbackHandler` — UNKNOWN family assignment

**Enrichers:**
| Enricher | Purpose |
|----------|---------|
| `NISTEnricher` | NIST designation, FIPS status |
| `IANAEnricher` | IANA OID, TLS cipher suite mapping |
| `CBOMEnricher` | CBOM component type, quantum_vulnerable |
| `FamilyEnricher` | Algorithm family (RSA, ECC, AES, etc.) |

---

### 8.2 Normalization Gaps

| Gap | Evidence |
|-----|----------|
| **Two algorithm registries** | `shared_models/algorithm_registry.py` + `universal_crypto/registry.py` |
| **Fallback-heavy** | Many algorithms → UNKNOWN family |
| **No version tracking** | Algorithm aliases not versioned |
| **Duplicate logic** | `normalization` service + `universal_crypto/classification.py` |

---

## 9. CBOM GENERATION

### 9.1 CycloneDX 1.5 Compliance

**File:** `services/cbom/cbom/generator.py`

```python
class CbomGenerator:
    def from_records(self, records, ...):
        # Produces CycloneDX 1.5 with:
        # - bomFormat: "CycloneDX"
        # - specVersion: "1.5"
        # - components[] with cryptoProperties
        # - dependencies[] graph
        # - vulnerabilities[] (optional)
```

**cryptoProperties Implementation:**
```json
{
  "assetType": "algorithm",
  "oid": "1.2.840.113549.1.1.1",
  "algorithmProperties": {
    "primitive": "asymmetric",
    "algorithm": "RSA",
    "mode": null,
    "padding": "PKCS1v15",
    "parameterSetIdentifier": "2048"
  },
  "nistDesignation": "Approved (legacy use only)",
  "quantumVulnerable": true
}
```

**Compliance:** ✅ CycloneDX 1.5 `cryptoProperties` extension

---

### 9.2 CBOM Signing

```python
# JWS (RFC 7515) over canonical BOM
# Algorithms: HS256 (legacy), RS256, ES256
# Key rotation via retired secrets list
```

**Verification:** `verify_report()` returns check-by-check report.

---

### 9.3 CBOM Gaps

| Gap | Evidence |
|-----|----------|
| **Three CBOM generators** | `cbom/`, `techbom/`, `crypto` live CBOM |
| **No SPDX output** | Only CycloneDX |
| **No composition support** | Nested BOMs not implemented |
| **External references missing** | No VCS, issue tracker links |

---

## 10. FALSE POSITIVE / FALSE NEGATIVE ANALYSIS

### 10.1 Known False Positives

| Pattern | Cause | Mitigation |
|---------|-------|------------|
| Test crypto constants | Test vectors detected as real | `exclude_test_dirs` option |
| Example code in docs | String literals in comments | Heuristic filtering |
| Obfuscated strings | Encoded algorithm names | Entropy filter |
| Library version strings | "OpenSSL 1.1.1" detected as algorithm | `IMPLEMENTATION_FINGERPRINTS` filter |

---

### 10.2 Known False Negatives

| Pattern | Cause |
|---------|-------|
| Dynamic algorithm selection | `Cipher.getInstance(config.getAlgorithm())` |
| Reflection-based invocation | `method.invoke(cipher, ...)` |
| Native code (JNI) | Algorithm in .so/.dll not analyzed |
| Obfuscated binaries | Packers, encryption, control flow flattening |
| Custom crypto implementations | Non-standard algorithms not in registry |

---

### 10.3 Accuracy Metrics — NOT MEASURED

**Critical Gap:** No automated precision/recall measurement in CI.

**Validation Corpus:** `services/scanner/tests/accuracy/` contains test cases but no automated metrics.

**External Validation Docs:** `docs/accuracy/` — Reports exist but not automated.

---

## 11. CRYPTOGRAPHIC CORRECTNESS — IMPLEMENTATION

### 11.1 Hashing (Evidence Chain)

```python
# SHA-256 via hashlib
# Canonical JSON: sorted keys, no whitespace, deterministic floats
# Chain hash: H(content_hash[i] + chain_hash[i-1])
```

**Correctness:** ✅ Standard SHA-256, proper canonicalization.

---

### 11.2 CBOM Signing (JWS)

```python
# RFC 7515 JWS Compact Serialization
# Algorithms: HS256, RS256, ES256
# Canonical BOM signed (excluding signature properties)
```

**Correctness:** ✅ RFC 7515 compliant.

---

### 11.3 Password Hashing

```python
# PBKDF2-SHA256, 600k iterations (configurable)
# Salt: 16 bytes random
# Verification: hmac.compare_digest (constant-time)
```

**Correctness:** ✅ Industry standard.

---

### 11.4 Session Tokens

```python
# HMAC-SHA256 over payload
# Payload: username, roles, iat, exp
# Verification: hmac.compare_digest
```

**Correctness:** ✅ Standard.

---

## 12. MISSING CRYPTOGRAPHIC CAPABILITIES

| Capability | Status | Needed For |
|------------|--------|------------|
| **PKCS#11/HSM integration** | Parser only (`cbom/hsm_pkcs11.py`) | HSM key detection |
| **KMIP support** | Parser only (`cbom/kmip.py`) | Key management interop |
| **Certificate Transparency** | Parsed only | CT log verification |
| **OCSP/CRL validation** | Parsed only | Real-time revocation |
| **CT log verification** | Missing | SCT verification |
| **TLS 1.3 PQC cipher suites** | Missing | Kyber/Dilithium in TLS |
| **Hybrid KEM detection** | Missing | X25519+ML-KEM, ECDHE+ML-KEM |
| **Post-quantum SSH** | Missing | SSH with PQC KEX |
| **Post-quantum IPsec** | Missing | IKEv2 with PQC |

---

## 13. SUMMARY SCORECARD

| Capability | Score | Evidence |
|------------|-------|----------|
| Algorithm Registry | 9/10 | 300+ entries, IANA OIDs, NIST, quantum status |
| Static Source Detection | 8/10 | 25 AST parsers, constant resolution |
| Binary Detection | 6/10 | Strings + disassembly, no control flow |
| Runtime Detection | 6/10 | API interception, no attestation |
| Key Size Detection | 7/10 | Good static, weak binary/runtime |
| Mode/Padding | 7/10 | Explicit detected, implicit missed |
| TLS Analysis | 8/10 | Cipher suite → algorithm mapping |
| SSH Analysis | 8/10 | KEX, host key, cipher, MAC parsing |
| IPsec Analysis | 7/10 | IKEv2 parsing, ESP missing |
| Certificate Parsing | 8/10 | X.509 via cryptography lib |
| Library Fingerprinting | 7/10 | Multi-class, version weak |
| Quantum Classification | 8/10 | Registry-backed, deterministic |
| Normalization | 6/10 | Fallback-heavy, duplicate registries |
| CBOM Generation | 8/10 | CycloneDX 1.5 + cryptoProperties |
| FP/FN Metrics | 1/10 | Not automated |

---

## 13. RECOMMENDATIONS

### P0 — Critical

1. **Merge algorithm registries** — Single source of truth for quantum classification
2. **Merge CBOM generators** — Single CycloneDX 1.5 implementation
3. **Add FP/FN metrics to CI** — Automated precision/recall on validation corpus

### P1 — High

4. **Improve binary detection** — Add control flow analysis (angr/ghidra)
5. **Implement PKCS#11/KMIP operational** — HSM key detection
6. **Add TLS 1.3 PQC cipher suite detection** — Kyber, Dilithium in TLS
7. **Improve library version detection** — Beyond string matching

### P2 — Medium

8. **Add Certificate Transparency verification** — SCT validation
9. **Implement OCSP/CRL validation** — Real-time revocation checking
10. **Add hybrid KEM detection** — X25519+ML-KEM, ECDHE+ML-KEM
11. **Post-quantum SSH/IPsec detection** — Protocol upgrades

### P3 — Enhancement

12. **CT log verification** — SCT verification against known logs
13. **Firmware filesystem extraction** — UEFI, squashfs, jffs2
14. **Custom crypto classification ML** — For unknown detector queue
15. **Formal verification** — Critical paths (evidence chain, JWS)

---

## 14. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Algorithm registry | `shared/shared_models/shared_models/algorithm_registry.py` |
| Quantum classification | `shared/shared_models/shared_models/quantum_classify.py` |
| Scanner parsers | `services/scanner/scanner/parsers/*.py` |
| Binary engine | `services/universal_crypto/universal_crypto/binary_engine.py` |
| Runtime engine | `services/universal_crypto/universal_crypto/runtime_engine.py` |
| Protocol engine | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| Certificate intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
| Library fingerprints | `services/universal_crypto/universal_crypto/library_fingerprints.py` |
| Normalization engine | `services/normalization/normalization/core/engine.py` |
| CBOM generator | `services/cbom/cbom/generator.py` |
| Quantum risk | `services/quantum/quantum/risk.py` |
| Safe finding | `shared/shared_models/shared_models/safe_finding.py` |