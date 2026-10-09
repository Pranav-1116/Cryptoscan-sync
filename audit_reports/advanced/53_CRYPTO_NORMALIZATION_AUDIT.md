# 53_CRYPTO_NORMALIZATION_AUDIT.md
## ZELNX CryptoScan — Crypto Normalization Audit

**Generated:** 2026-09-20  
**Method:** Deep inspection of algorithm, protocol, key-size, curve, library, vendor, and certificate normalization  
**Scope:** All normalization logic across `services/normalization/`, `shared/shared_models/`, and `services/universal_crypto/`

---

## EXECUTIVE SUMMARY

| Normalization Area | Status | Collisions | Ambiguities | Score |
|--------------------|--------|------------|-------------|-------|
| Algorithm Names | ⚠️ Partial | 12+ known | 5+ ambiguous | 6/10 |
| Protocol Names | ⚠️ Partial | 3+ known | 2+ ambiguous | 6/10 |
| Key Size | ✅ Good | None | None | 9/10 |
| Curve Names | ⚠️ Partial | 2+ known | 3+ ambiguous | 5/10 |
| Library Names | ⚠️ Partial | 5+ known | 3+ ambiguous | 5/10 |
| Vendor Names | ❌ Missing | N/A | N/A | 0/10 |
| Certificate Fields | ✅ Good | None | None | 9/10 |
| Protocol Versions | ⚠️ Partial | 2+ known | 1+ ambiguous | 6/10 |

**Overall: 5.5/10** — Works for common cases, but significant collisions and ambiguities exist

---

## 1. NORMALIZATION ARCHITECTURE

### 1.1 Multiple Normalization Systems

| System | Location | Purpose | Scope |
|--------|----------|---------|-------|
| **NormalizationEngine** | `services/normalization/normalization/core/engine.py` | Primary normalization | Algorithm, protocol, key-size, curve |
| **Universal Crypto Classification** | `universal_crypto/classification.py` | Crypto classification + quantum | Algorithm, protocol, quantum status |
| **Algorithm Registry** | `shared_models/algorithm_registry.py` | Canonical algorithm DB | 300+ algorithms with OIDs, NIST, quantum |
| **CBOM Enricher** | `normalization/enrichers/cbom_enricher.py` | CBOM-specific fields | cryptoProperties mapping |
| **NIST Enricher** | `normalization/enrichers/nist_enricher.py` | NIST designations | FIPS status, approval |
| **IANA Enricher** | `normalization/enrichers/iana_enricher.py` | IANA OIDs, TLS suites | OID mapping, cipher suites |
| **Family Enricher** | `normalization/enrichers/family_enricher.py` | Algorithm families | RSA, ECC, AES, etc. |

**Critical Issue:** **Two separate algorithm registries** with different schemas.

---

## 2. ALGORITHM NORMALIZATION

### 2.1 Algorithm Registry Comparison

| Registry | Location | Entries | Fields |
|----------|----------|---------|--------|
| **Primary** | `shared_models/algorithm_registry.py` | 300+ | algorithm, oid, nist_designation, quantum_status, primitive, key_sizes, curves, aliases |
| **Universal Crypto** | `universal_crypto/registry.py` | ~100 | name, type, quantum_status, strength |

### 2.2 Known Algorithm Collisions

| Input Variant | Registry 1 | Registry 2 | Normalized | Conflict |
|---------------|------------|------------|------------|----------|
| `SHA1` | `SHA-1` | `SHA1` | `SHA-1` | ❌ Different |
| `SHA-1` | `SHA-1` | `SHA-1` | `SHA-1` | ✅ |
| `sha1` | `SHA-1` | `SHA1` | `SHA-1` | ❌ Different |
| `SHA256` | `SHA-256` | `SHA256` | `SHA-256` | ❌ Different |
| `SHA-256` | `SHA-256` | `SHA-256` | `SHA-256` | ✅ |
| `SHA_256` | `SHA-256` | `SHA256` | `SHA-256` | ❌ Different |
| `RSA2048` | `RSA` (2048) | `RSA2048` | `RSA` (2048) | ❌ Different |
| `RSA-2048` | `RSA` (2048) | `RSA-2048` | `RSA` (2048) | ❌ Different |
| `RSA_2048` | `RSA` (2048) | `RSA2048` | `RSA` (2048) | ❌ Different |
| `ECDSA_P256` | `ECDSA` (P-256) | `ECDSA-P256` | `ECDSA` (P-256) | ❌ Different |
| `ECDSA-P256` | `ECDSA` (P-256) | `ECDSA-P256` | `ECDSA` (P-256) | ❌ Different |
| `P-256` | `ECDSA` (P-256) | `P-256` | `ECDSA` (P-256) | ❌ Different |
| `secp256r1` | `ECDSA` (P-256) | `secp256r1` | `ECDSA` (P-256) | ❌ Different |
| `AES256` | `AES` (256) | `AES256` | `AES` (256) | ❌ Different |
| `AES-256` | `AES` (256) | `AES-256` | `AES` (256) | ❌ Different |
| `AES_256` | `AES` (256) | `AES256` | `AES` (256) | ❌ Different |
| `AES256GCM` | `AES-GCM` (256) | `AES256GCM` | `AES-GCM` (256) | ❌ Different |
| `AES-GCM-256` | `AES-GCM` (256) | `AES-GCM-256` | `AES-GCM` (256) | ❌ Different |
| `ChaCha20Poly1305` | `CHACHA20-POLY1305` | `CHACHA20-POLY1305` | `CHAACHA20-POLY1305` | ✅ |
| `ChaCha20-Poly1305` | `CHACHA20-POLY1305` | `CHACHA20-POLY1305` | `CHACHA20-POLY1305` | ✅ |
| `X25519` | `X25519` | `X25519` | `X25519` | ✅ |
| `Ed25519` | `ED25519` | `ED25519` | `ED25519` | ✅ |
| `ML-KEM-768` | `ML-KEM-768` | `ML-KEM-768` | `ML-KEM-768` | ✅ (new) |
| `ML-DSA-65` | `ML-DSA-65` | `ML-DSA-65` | `ML-DSA-65` | ✅ (new) |

---

### 2.3 Ambiguous Normalizations

| Input | Normalized To | Also Could Be | Ambiguity |
|-------|---------------|---------------|-----------|
| `RSA` | `RSA` (key_size unknown) | `RSA-2048`, `RSA-4096` | Key size unknown |
| `ECDSA` | `ECDSA` (curve unknown) | `P-256`, `P-384`, `P-521` | Curve unknown |
| `AES` | `AES` (key_size unknown) | `AES-128`, `AES-192`, `AES-256` | Key size unknown |
| `DH` | `DH` (group unknown) | `DH-2048`, `DH-3072` | Group unknown |
| `ECDH` | `ECDH` (curve unknown) | `P-256`, `P-384`, `X25519` | Curve unknown |
| `AES-GCM` | `AES-GCM` (key_size unknown) | `AES-128-GCM`, `AES-256-GCM` | Key size unknown |
| `TLS` | `TLS` (version unknown) | `TLS 1.2`, `TLS 1.3` | Version unknown |
| `SHA` | `SHA-1` (legacy) | `SHA-256`, `SHA-384` | Algorithm family |

---

## 3. PROTOCOL NORMALIZATION

### 3.1 Protocol Name Collisions

| Input Variant | Normalized | Also Could Be | Conflict |
|---------------|------------|---------------|----------|
| `TLS1.2` | `TLS 1.2` | `TLSv1.2` | ❌ Different input |
| `TLSv1.2` | `TLS 1.2` | `TLS 1.2` | ✅ |
| `TLSv1.3` | `TLS 1.3` | `TLS 1.3` | ✅ |
| `SSLv3` | `SSL 3.0` | `SSL 3.0` | ✅ |
| `SSLv2` | `SSL 2.0` | `SSL 2.0` | ✅ |
| `TLS1.0` | `TLS 1.0` | `TLS 1.0` | ✅ |
| `TLS1.1` | `TLS 1.1` | `TLS 1.1` | ✅ |
| `SSL` | `SSL` (ambiguous) | `SSL 3.0`, `TLS` | Ambiguous |
| `TLS` | `TLS` (ambiguous) | `TLS 1.0`...`1.3` | Ambiguous |
| `SSLv2` | `SSL 2.0` | `SSL 2.0` | ✅ |
| `SSL3` | `SSL 3.0` | `SSL 3.0` | ✅ |

### 3.2 Cipher Suite Normalization

**File:** `services/universal_crypto/universal_crypto/protocol_engine.py:TlsAnalysis`

```python
# Cipher suite → Algorithm mapping:
TLS_AES_256_GCM_SHA384 → {kex: "ECDHE", cipher: "AES-256-GCM", mac: "AEAD", sig: "ECDSA"}
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 → {kex: "ECDHE", auth: "RSA", cipher: "AES-256-GCM"}
```

**Gap:** Cipher suite strings not normalized to canonical algorithm names in all paths.

---

## 4. KEY SIZE NORMALIZATION

### 4.1 Key Size — GOOD

| Input | Normalized | Consistent |
|-------|------------|------------|
| `2048` | `2048` (int) | ✅ |
| `2048` (string) | `2048` (int) | ✅ |
| `RSA2048` | `2048` (extracted) | ✅ |
| `RSA-2048` | `2048` (extracted) | ✅ |
| `RSA_2048` | `2048` (extracted) | ✅ |
| `4096` | `4096` (int) | ✅ |
| `P-256` | `256` (curve→size) | ✅ |
| `P-384` | `384` (curve→size) | ✅ |
| `P-521` | `521` (curve→size) | ✅ |
| `X25519` | `255` (curve→size) | ✅ |
| `X448` | `448` (curve→size) | ✅ |
| `Ed25519` | `255` (curve→size) | ✅ |
| `Ed448` | `448` (curve→size) | ✅ |

**Good:** Key size extraction is consistent and correct.

---

## 5. CURVE NORMALIZATION

### 5.1 Curve Name Collisions

| Input Variant | Normalized | Also Could Be | Conflict |
|---------------|------------|---------------|----------|
| `P-256` | `P-256` | `secp256r1`, `prime256v1` | ❌ Different |
| `secp256r1` | `P-256` | `P-256` | ✅ |
| `prime256v1` | `P-256` | `P-256` | ✅ |
| `P-384` | `P-384` | `secp384r1` | ❌ Different |
| `secp384r1` | `P-384` | `P-384` | ✅ |
| `P-521` | `P-521` | `secp521r1` | ❌ Different |
| `secp521r1` | `P-521` | `P-521` | ✅ |
| `X25519` | `X25519` | `Curve25519` | ❌ Different |
| `Curve25519` | `X25519` | `X25519` | ✅ |
| `X448` | `X448` | `Curve448` | ❌ Different |
| `Curve448` | `X448` | `X448` | ✅ |
| `Ed25519` | `Ed25519` | `Ed25519` | ✅ |
| `Ed448` | `Ed448` | `Ed448` | ✅ |
| `brainpoolP256r1` | `brainpoolP256r1` | `brainpoolP256r1` | ✅ |
| `brainpoolP384r1` | `brainpoolP384r1` | `brainpoolP384r1` | ✅ |
| `brainpoolP512r1` | `brainpoolP512r1` | `brainpoolP512r1` | ✅ |

**Gap:** Registry has aliases but normalization doesn't consistently apply them.

---

## 6. LIBRARY NORMALIZATION

### 6.1 Library Name Collisions

| Library | Variants Seen | Normalized | Collision |
|---------|---------------|------------|-----------|
| OpenSSL | `OpenSSL`, `openssl`, `libssl`, `libcrypto` | `OpenSSL` | ❌ Multiple |
| BoringSSL | `BoringSSL`, `boringssl` | `BoringSSL` | ❌ |
| LibreSSL | `LibreSSL`, `libressl` | `LibreSSL` | ❌ |
| BouncyCastle | `BouncyCastle`, `BC`, `bcprov`, `bcpkix` | `BouncyCastle` | ❌ Multiple |
| Java Crypto | `JCE`, `SunJCE`, `SunPKCS11` | `JCE` | ❌ |
| Microsoft Crypto | `CNG`, `CAPI`, `NCrypt` | `CNG` | ❌ |
| OpenJDK | `OpenJDK`, `OpenJDK 11`, `OpenJDK 17` | `OpenJDK` | ❌ Version in name |
| .NET Crypto | `System.Security.Cryptography`, `System.Core` | `System.Security.Cryptography` | ❌ |
| Node.js Crypto | `crypto`, `node:crypto` | `crypto` | ❌ |
| Python cryptography | `cryptography`, `cryptography.hazmat` | `cryptography` | ❌ |
| Go stdlib | `crypto`, `crypto/tls`, `crypto/x509` | `crypto` | ❌ Package path |
| Rust crates | `ring`, `rustls`, `openssl-sys`, `p256` | Various | ❌ Crate name |

**Gap:** No canonical library name registry with version separation.

---

## 7. VENDOR NORMALIZATION — MISSING

### 7.1 Current State

| Aspect | Status |
|--------|--------|
| Vendor name canonicalization | ❌ Not implemented |
| Vendor product mapping | ❌ Not implemented |
| Vendor alias tracking | ❌ Not implemented |
| Vendor → Product mapping | ❌ Not implemented |
| Vendor crypto capabilities | ❌ Not implemented |

**Gap:** Complete absence of vendor normalization.

---

## 8. CERTIFICATE FIELD NORMALIZATION — GOOD

### 8.1 Certificate Fields

| Field | Normalization | Consistent |
|-------|---------------|------------|
| Subject DN | RFC 4514 string | ✅ RFC 4514 |
| Issuer DN | RFC 4514 string | ✅ RFC 4514 |
| Serial Number | Hex string (uppercase) | ✅ |
| Validity | ISO 8601 UTC | ✅ ISO 8601 |
| Public Key Algorithm | Canonical algorithm name | ✅ |
| Key Size | Integer bits | ✅ |
| Curve | Canonical curve name | ⚠️ Partial |
| Signature Algorithm | Canonical algorithm name | ✅ |
| Extensions | Parsed structures | ✅ |
| SAN | List of DNS/IP/URI/Email | ✅ |
| Key Usage | Bit flags → names | ✅ |
| Extended Key Usage | OID → name mapping | ✅ |

**Good:** Certificate normalization uses `cryptography.x509` library — standards-compliant.

---

## 9. PROTOCOL VERSION NORMALIZATION

### 9.1 TLS Version Collisions

| Input | Normalized | Also Could Be |
|-------|------------|---------------|
| `TLS1.0` | `TLS 1.0` | `TLSv1.0` |
| `TLSv1.0` | `TLS 1.0` | `TLS 1.0` |
| `TLS 1.0` | `TLS 1.0` | `TLS 1.0` |
| `SSLv3` | `SSL 3.0` | `SSL 3.0` |
| `SSLv2` | `SSL 2.0` | `SSL 2.0` |
| `TLS 1.2` | `TLS 1.2` | `TLSv1.2` |
| `TLSv1.2` | `TLS 1.2` | `TLS 1.2` |
| `TLS 1.3` | `TLS 1.3` | `TLSv1.3` |
| `TLSv1.3` | `TLS 1.3` | `TLS 1.3` |

**Good for standard forms.** Gap: `TLS` alone is ambiguous.

---

## 10. NORMALIZATION PIPELINE — TWO PARALLEL SYSTEMS

### 10.1 System 1: NormalizationEngine

**File:** `services/normalization/normalization/core/engine.py`

```python
class NormalizationEngine:
    def __init__(self, rules_directory):
        self.rule_loader = RuleLoader(rules_directory)
        self.rules = self.rule_loader.load_all_rules()
        registry = RuleRegistry()
        registry.register_all(self.rules, overwrite=True)
        self.registry = registry
        self.processor = NormalizationProcessor(registry)
        # Enrichers added AFTER matching
        self.nist_enricher = NISTEnricher()
        self.iana_enricher = IANAEnricher()
        self.cbom_enricher = CBOMEnricher()
        self.family_enricher = FamilyEnricher()
```

**Pipeline:** Match → Enrich (NIST, IANA, CBOM, Family)

### 10.2 System 2: Universal Crypto Classification

**File:** `services/universal_crypto/universal_crypto/classification.py`

```python
class CryptoClassifier:
    def classify_observation(self, observation):
        # Uses algorithm_registry from shared_models
        # Quantum classification via quantum_classify.is_shor_vulnerable()
```

**Gap:** Two systems, different registries, different outputs.

---

## 11. NORMALIZATION RULES — YAML-BASED

### 11.1 Rule Structure

**File:** `services/normalization/normalization/rules/` (YAML files)

```yaml
# Example rule:
- rule_id: "normalize-rsa"
  match_type: "pattern"
  pattern: "^RSA[-_]?\\d+$"
  normalized: "RSA"
  extract_key_size: true
  priority: 100
  
- rule_id: "normalize-aes-gcm"
  match_type: "pattern"
  pattern: "^AES[-_]?(\\d+)[-_]?GCM$"
  normalized: "AES-GCM"
  extract_key_size: true
  priority: 90
```

### 11.2 Rule Matching Order

1. **Exact Match** — Registry lookup (highest priority)
2. **Pattern Match** — Regex patterns (priority ordered)
3. **Family Match** — Prefix matching (e.g., `RSA*` → `RSA`)
4. **Fallback** → `UNKNOWN` family

---

## 11. COLLISIONS & AMBIGUITIES SUMMARY

### 11.1 Critical Collisions (Cause Different Normalization)

| Input | System 1 | System 2 | Impact |
|-------|----------|----------|--------|
| `SHA1` vs `SHA-1` | `SHA-1` | `SHA1` | Different CBOM component IDs |
| `RSA2048` vs `RSA-2048` | `RSA` (2048) | `RSA-2048` | Different CBOM IDs |
| `ECDSA_P256` vs `ECDSA-P256` | `ECDSA` (P-256) | `ECDSA-P256` | Different graph nodes |
| `P-256` vs `secp256r1` | `P-256` | `secp256r1` | Different graph nodes |
| `AES256` vs `AES-256` | `AES` (256) | `AES-256` | Different CBOM components |

### 11.2 Ambiguities (Cause Information Loss)

| Input | Normalized | Information Lost |
|-------|------------|------------------|
| `RSA` | `RSA` | Key size unknown |
| `ECDSA` | `ECDSA` | Curve unknown |
| `AES` | `AES` | Key size unknown |
| `DH` | `DH` | Group unknown |
| `TLS` | `TLS` | Version unknown |
| `AES-GCM` | `AES-GCM` | Key size unknown |

---

## 12. RECOMMENDATIONS

### P0 — Critical

1. **Merge Algorithm Registries** — Single source of truth (`shared_models/algorithm_registry.py`)
2. **Unify Normalization Pipeline** — Single `NormalizationEngine` for all paths
3. **Fix Critical Collisions** — Standardize `SHA1`/`SHA-1`, `RSA2048`/`RSA-2048`, etc.
4. **Add Vendor Normalization** — New `VendorNormalizer` component

### P1 — High

5. **Resolve Curve Aliases** — `P-256` = `secp256r1` = `prime256v1` consistently
6. **Standardize Library Names** — Canonical library registry with versions
7. **Add Vendor Normalization** — Canonical vendor names + product mapping
8. **Resolve Ambiguous Normalizations** — Require key size for `RSA`, `AES`, `DH`, `ECDSA`

### P2 — Medium

9. **Protocol Version Disambiguation** — `TLS` alone → error/warning
10. **Library Version Separation** — `OpenJDK 11` ≠ `OpenJDK 17`
11. **Cipher Suite Canonicalization** — All TLS suites → canonical algorithm
12. **Add Normalization Test Suite** — Automated collision/ambiguity detection

### P3 — Enhancement

13. **Normalization Versioning** — Schema version for normalization rules
14. **Normalization Metrics** — Collision rate, ambiguity rate per release
15. **Fuzzy Matching** — Levenshtein for near-matches with low confidence

---

## 12. VERDICT

**Normalization works for standard cases but has significant collisions and ambiguities.** Two parallel normalization systems with different registries cause inconsistent canonical identities across the platform.

| Area | Status |
|------|--------|
| Algorithm names | ⚠️ 12+ collisions |
| Protocol names | ⚠️ 3+ collisions |
| Key size | ✅ Good |
| Curve names | ⚠️ 2+ collisions |
| Library names | ⚠️ 5+ collisions |
| Vendor names | ❌ Missing |
| Certificate fields | ✅ Good |
| Protocol versions | ⚠️ 2+ collisions |

**To fix:** 4-6 weeks for registry unification, collision resolution, vendor normalization.

---

## 13. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| NormalizationEngine | `services/normalization/normalization/core/engine.py` |
| RuleLoader | `services/normalization/normalization/rules/rule_loader.py` |
| RuleRegistry | `services/normalization/normalization/rules/rule_registry.py` |
| ExactMatcher | `services/normalization/normalization/matchers/exact_matcher.py` |
| PatternMatcher | `services/normalization/normalization/matchers/pattern_matcher.py` |
| FallbackHandler | `services/normalization/normalization/matchers/fallback_handler.py` |
| NISTEnricher | `services/normalization/normalization/enrichers/nist_enricher.py` |
| IANAEnricher | `services/normalization/normalization/enrichers/iana_enricher.py` |
| CBOMEnricher | `services/normalization/normalization/enrichers/cbom_enricher.py` |
| FamilyEnricher | `services/normalization/normalization/enrichers/family_enricher.py` |
| Algorithm Registry (primary) | `shared/shared_models/shared_models/algorithm_registry.py` |
| Algorithm Registry (secondary) | `services/universal_crypto/universal_crypto/registry.py` |
| CryptoClassifier | `services/universal_crypto/universal_crypto/classification.py` |
| CryptoClassifier | `services/universal_crypto/universal_crypto/classification.py` |
| Protocol Engine | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| Library Fingerprinter | `services/universal_crypto/universal_crypto/library_fingerprints.py` |
| Quantum Classify | `shared/shared_models/shared_models/quantum_classify.py` |
| Normalization Rules | `services/normalization/normalization/rules/` (YAML files) |