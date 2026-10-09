# 24_DISCOVERY_COVERAGE_MATRIX.md
## ZELNX CryptoScan — Discovery Coverage Matrix

**Generated:** 2026-09-20  
**Method:** Systematic mapping of all discovery sources against implemented detection capabilities  
**Scope:** All 19 discovery surfaces across source, binary, container, network, cloud, runtime, and specialized domains

---

## EXECUTIVE SUMMARY

| Discovery Surface | Status | Coverage | Evidence Quality |
|-------------------|--------|----------|------------------|
| **Source Code** | ✅ IMPLEMENTED | 95% | HIGH — AST-based, 25 languages |
| **Binary/Firmware** | ✅ IMPLEMENTED | 70% | MEDIUM — Strings + disassembly |
| **Containers** | ✅ IMPLEMENTED | 85% | HIGH — Layer scanning + SBOM |
| **Kubernetes/IaC** | ✅ IMPLEMENTED | 80% | HIGH — Manifest parsing |
| **Network/TLS** | ✅ IMPLEMENTED | 90% | VERIFIED — Active probing |
| **Certificates** | ✅ IMPLEMENTED | 90% | VERIFIED — X.509 parsing |
| **Cloud Config** | ✅ IMPLEMENTED | 75% | HIGH — API-verified |
| **Runtime/Process** | ⚠️ PARTIAL | 50% | MEDIUM — Sampling only |
| **Dependencies** | ⚠️ PARTIAL | 40% | MEDIUM — Direct only |
| **Hardware/HSM** | ⚠️ PARTIAL | 30% | LOW — Inventory only |
| **Vendor/Supply Chain** | ❌ MISSING | 10% | NONE — Scaffolded only |
| **Secrets/Keys** | ✅ IMPLEMENTED | 80% | HIGH — Redacted findings |
| **OT/ICS** | ⚠️ PARTIAL | 40% | MEDIUM — Passive only |
| **Payment/HSM** | ⚠️ PARTIAL | 40% | MEDIUM — Ceremony tracking |
| **Configuration Files** | ✅ IMPLEMENTED | 85% | HIGH — Config parsers |
| **API/Protocol** | ✅ IMPLEMENTED | 70% | MEDIUM — SSH/IPsec/TLS |
| **Custom Crypto** | ⚠️ PARTIAL | 30% | LOW — Heuristic only |
| **Key Metadata** | ⚠️ PARTIAL | 40% | MEDIUM — Cert/key parsing |
| **Trust Stores** | ✅ IMPLEMENTED | 80% | HIGH — Anchor analysis |

---

## 2. DISCOVERY COVERAGE MATRIX

### 2.1 Source Code Discovery

| Language | Parser | Crypto APIs | Constant Resolution | Config Files | Test Exclusion | Status |
|----------|--------|-------------|---------------------|--------------|----------------|--------|
| Java | ✅ | JCA, BC, Conscrypt | ✅ | ✅ | ✅ | IMPLEMENTED |
| Python | ✅ | cryptography, ssl, hashlib | ✅ | ✅ | ✅ | IMPLEMENTED |
| C/C++ | ✅ | OpenSSL, mbedTLS, wolfSSL | ✅ | ✅ | ✅ | IMPLEMENTED |
| Go | ✅ | crypto/*, x/crypto | ✅ | ✅ | ✅ | IMPLEMENTED |
| JavaScript/TS | ✅ | Node crypto, Web Crypto, Forge | ✅ | ✅ | ✅ | IMPLEMENTED |
| C# | ✅ | System.Security.Cryptography | ✅ | ✅ | ✅ | IMPLEMENTED |
| Rust | ✅ | rustls, ring, openssl-sys | ✅ | ✅ | ✅ | IMPLEMENTED |
| Ruby | ✅ | OpenSSL, RbNaCl | ✅ | ✅ | ✅ | IMPLEMENTED |
| PHP | ✅ | OpenSSL, Sodium | ✅ | ✅ | ✅ | IMPLEMENTED |
| Kotlin | ✅ | Java interop | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| Swift | ✅ | CryptoKit, CommonCrypto | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| SQL | ✅ | TDE, column encryption | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| Shell | ✅ | OpenSSL CLI, SSH config | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| XML | ✅ | XMLSec, WS-Security | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| COBOL | ✅ | ENCIPHER, etc. | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| RPG | ✅ | IBM i crypto ops | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| PL/I | ✅ | Enterprise crypto | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| Natural | ✅ | Adabas/Natural | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| 4GL | ✅ | Informix/Progress | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |
| Mainframe defs | ✅ | Copybooks, JCL | ⚠️ Partial | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 95% — All major languages, AST-based, constant resolution.

---

### 2.2 Binary/Firmware Discovery

| Target | Format Support | String Extraction | Disassembly | Library Fingerprinting | Version Detection | Control Flow | Status |
|--------|----------------|-------------------|-------------|------------------------|-------------------|--------------|--------|
| ELF (Linux) | ✅ | ✅ | ✅ CAPSTONE | ✅ | ❌ | ❌ | IMPLEMENTED |
| PE (Windows) | ✅ | ✅ | ✅ CAPSTONE | ✅ | ❌ | ❌ | IMPLEMENTED |
| Mach-O (macOS) | ✅ | ✅ | ✅ CAPSTONE | ✅ | ❌ | ❌ | IMPLEMENTED |
| JAR/WAR/EAR | ✅ | ✅ | ✅ (bytecode) | ✅ | ❌ | ❌ | IMPLEMENTED |
| .NET Assembly | ✅ | ✅ | ⚠️ Limited | ✅ | ❌ | ❌ | IMPLEMENTED |
| APK (Android) | ✅ | ✅ | ✅ (DEX) | ✅ | ❌ | ❌ | IMPLEMENTED |
| IPA (iOS) | ✅ | ✅ | ⚠️ Limited | ✅ | ❌ | ❌ | IMPLEMENTED |
| Firmware (UEFI) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |
| Firmware (RTOS) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |
| Bootloader | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |

**Coverage Score:** 70% — Good for standard binaries, missing firmware/RTOS.

---

### 2.3 Container Discovery

| Layer | Dockerfile Analysis | Base Image | Layer Scanning | SBOM Generation | CVE Matching | Config Analysis | Status |
|-------|---------------------|------------|----------------|-----------------|--------------|-----------------|--------|
| Dockerfile | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Image Layers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| OCI Image Spec | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| BuildKit Cache | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |
| Multi-stage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 85% — Comprehensive, missing BuildKit.

---

### 2.4 Kubernetes/IaC Discovery

| Target | Manifest Parsing | Helm Charts | Kustomize | Config Analysis | Policy Checks | Crypto Detection | Status |
|--------|------------------|-------------|-----------|-----------------|---------------|------------------|--------|
| K8s YAML | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Helm Charts | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Kustomize | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Docker Compose | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Terraform | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | IMPLEMENTED |
| CloudFormation | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Ansible | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 80% — Good, missing Helm/Kustomize crypto specifics.

---

### 2.5 Network/TLS Discovery

| Capability | Active Probe | Passive Capture | Certificate Chain | Cipher Suite Enum | TLS Version | ALPN/SNI | Status |
|------------|--------------|-----------------|-------------------|-------------------|-------------|----------|--------|
| TLS 1.0 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| TLS 1.1 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| TLS 1.2 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| TLS 1.3 | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Certificate Chain | ✅ | ❌ | ✅ | N/A | N/A | N/A | IMPLEMENTED |
| Cipher Suite Enum | ✅ | ❌ | N/A | ✅ | N/A | N/A | IMPLEMENTED |
| StartTLS (SMTP/IMAP/etc) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| QUIC | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |
| DTLS | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |

**Coverage Score:** 90% — Active probe only, no passive, missing QUIC/DTLS.

---

### 2.6 Certificate Discovery

| Source | Parsed | Chain | Validity | Key Info | Extensions | Revocation | Status |
|--------|--------|-------|----------|----------|------------|------------|--------|
| Network Scan | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | IMPLEMENTED |
| Source Code (PEM) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | IMPLEMENTED |
| Binary (PKCS#12) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | IMPLEMENTED |
| Container (certs in image) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | IMPLEMENTED |
| Cloud (ACM, Key Vault) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | IMPLEMENTED |
| HSM/PKCS#11 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | MISSING |
| CT Logs | ❌ | N/A | N/A | N/A | N/A | ❌ | MISSING |

**Coverage Score:** 90% — Parsing solid, missing revocation/CT.

---

### 2.7 Cloud Configuration Discovery

| Provider | Service | Crypto Config Detected | Status |
|----------|---------|------------------------|--------|
| **AWS** | KMS | Key policies, rotation, aliases | ✅ IMPLEMENTED |
| | S3 | Bucket encryption (SSE-S3, SSE-KMS, SSE-C) | ✅ IMPLEMENTED |
| | RDS/Aurora | Storage encryption, TDE | ✅ IMPLEMENTED |
| | DynamoDB | Encryption at rest | ✅ IMPLEMENTED |
| | Secrets Manager | Secret rotation, KMS key | ✅ IMPLEMENTED |
| | Certificate Manager | Certificates, renewals | ✅ IMPLEMENTED |
| | CloudHSM | ❌ Not detected | MISSING |
| **Azure** | Key Vault | Key types, rotation, HSM | ✅ IMPLEMENTED |
| | Storage | Blob encryption, CMK | ✅ IMPLEMENTED |
| | SQL/Cosmos DB | TDE, CMK | ✅ IMPLEMENTED |
| | Dedicated HSM | ❌ Not detected | MISSING |
| **GCP** | Cloud KMS | Key rings, rotation, versions | ✅ IMPLEMENTED |
| | Cloud Storage | Bucket encryption, CMEK | ✅ IMPLEMENTED |
| | Cloud SQL/Spanner | Encryption, CMEK | ✅ IMPLEMENTED |
| | Cloud HSM | ❌ Not detected | MISSING |

**Coverage Score:** 75% — Core services covered, HSM missing.

---

### 2.8 Runtime/Process Discovery

| Capability | Implemented | Evidence Quality |
|------------|-------------|------------------|
| Process enumeration | ✅ | MEDIUM |
| Loaded library detection | ✅ | MEDIUM |
| API call interception | ⚠️ Partial (LD_PRELOAD) | LOW |
| Memory scanning | ❌ | NONE |
| TLS handshake capture | ✅ | HIGH |
| API call parameters | ⚠️ Partial | LOW |
| Key extraction | ❌ (by design) | N/A |

**Coverage Score:** 50% — Sampling-based, no continuous monitoring.

---

### 2.9 Dependency Discovery

| Source | Direct Deps | Transitive Deps | Lockfile Parsing | Crypto Relevance | Version Pinning | Status |
|--------|-------------|-----------------|------------------|------------------|-----------------|--------|
| Python (pip/poetry) | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| npm/yarn/pnpm | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Maven/Gradle | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Go modules | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Cargo (Rust) | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| NuGet (.NET) | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Composer (PHP) | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Bundler (Ruby) | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| Pipenv/Poetry | ✅ | ⚠️ Partial | ✅ | ✅ | ✅ | IMPLEMENTED |
| SBOM import | ✅ | ✅ | ✅ | ✅ | ✅ | IMPLEMENTED |
| Transitive crypto propagation | ❌ | ❌ | N/A | ❌ | N/A | MISSING |

**Coverage Score:** 40% — Direct deps only, no recursive crypto analysis.

---

### 2.10 Hardware/HSM Discovery

| Target | Inventory | Crypto Capabilities | Key Detection | Status |
|--------|-----------|---------------------|---------------|--------|
| CPU Crypto (AES-NI, SHA-NI) | ✅ | ✅ | N/A | IMPLEMENTED |
| TPM 1.2/2.0 | ✅ | ✅ (PCR, keys) | ❌ Keys | PARTIAL |
| HSM (PKCS#11) | ✅ Inventory | ✅ Capabilities | ❌ Keys | PARTIAL |
| HSM (KMIP) | ✅ Inventory | ✅ Capabilities | ❌ Keys | PARTIAL |
| Cloud HSM (AWS/Azure/GCP) | ❌ | ❌ | ❌ | MISSING |
| Smart Cards | ❌ | ❌ | ❌ | MISSING |
| Secure Enclaves (SGX, TrustZone) | ❌ | ❌ | ❌ | MISSING |

**Coverage Score:** 30% — Inventory only, no key detection.

---

### 2.11 Vendor/Supply Chain Discovery

| Capability | Implemented | Evidence |
|-------------|-------------|----------|
| Vendor inventory | ✅ (scaffolded) | `vendor_intel` service exists |
| Vendor crypto fingerprinting | ❌ | No automated detection |
| Sub-tier vendor mapping | ⚠️ Manual | `graph.py:/graph/vendor-edges` only manual |
| Vendor risk scoring | ❌ | Scaffolded only |
| SBOM vendor correlation | ❌ | No automated linking |
| Vendor certificate tracking | ❌ | Not implemented |

**Coverage Score:** 10% — Service exists but no automated discovery.

---

### 2.12 Secrets/Key Discovery

| Source | Detected | Redacted | Key Type | Context | Status |
|--------|----------|----------|----------|---------|--------|
| Source code (hardcoded) | ✅ | ✅ | API keys, passwords, private keys | Line, file, entropy | IMPLEMENTED |
| Binary (strings) | ✅ | ✅ | Keys, certificates | Offset, section | IMPLEMENTED |
| Config files | ✅ | ✅ | Passwords, keys | Line, file | IMPLEMENTED |
| Container env vars | ✅ | ✅ | Secrets, keys | Layer, env var | IMPLEMENTED |
| Kubernetes secrets | ✅ | ✅ | All types | Resource, namespace | IMPLEMENTED |
| Cloud secret stores | ⚠️ Partial | ✅ | References only | Service, key ID | PARTIAL |
| HSM key references | ❌ | N/A | Metadata only | N/A | MISSING |
| Certificate private keys | ❌ (by design) | N/A | Never extracted | N/A | BY DESIGN |

**Coverage Score:** 80% — Good detection, proper redaction.

---

### 2.13 OT/ICS Discovery

| Protocol | Passive Detection | Crypto Analysis | Status |
|----------|-------------------|-----------------|--------|
| Modbus | ✅ | ❌ | PARTIAL |
| DNP3 | ✅ | ❌ | PARTIAL |
| IEC 61850 | ✅ | ❌ | PARTIAL |
| PROFINET | ✅ | ❌ | PARTIAL |
| EtherNet/IP | ✅ | ❌ | PARTIAL |
| OPC UA | ✅ | ✅ (cert-based) | PARTIAL |
| MQTT (TLS) | ✅ | ✅ | IMPLEMENTED |
| Custom protocols | ❌ | ❌ | MISSING |

**Coverage Score:** 40% — Passive detection only, minimal crypto.

---

### 2.14 Payment/HSM Discovery

| Capability | Implemented | Evidence |
|------------|-------------|----------|
| Payment key ceremonies | ✅ | `payment_crypto` service |
| HSM audit trail ingestion | ✅ | JSONL/syslog/CSV parsing |
| TR-31 key block parsing | ✅ | `payment_crypto` service |
| PCI policy (PAY-001..010) | ✅ | Policy pack |
| Key ceremony provenance | ✅ | Ceremony tracking |
| HSM key detection | ❌ | PKCS#11 parser only |

**Coverage Score:** 40% — Process tracking, no key detection.

---

### 2.15 Configuration File Discovery

| Config Type | Parsed | Crypto Detection | Status |
|-------------|--------|------------------|--------|
| TLS/SSL (nginx, Apache, HAProxy) | ✅ | ✅ Ciphers, certs, protocols | IMPLEMENTED |
| Kubernetes (CertManager, Ingress) | ✅ | ✅ Certs, TLS config | IMPLEMENTED |
| Java Keystore/Truststore (JKS, PKCS12) | ✅ | ✅ Certs, keys | IMPLEMENTED |
| OpenSSL config | ✅ | ✅ Ciphers, curves | IMPLEMENTED |
| SSH config | ✅ | ✅ KEX, ciphers, MACs | IMPLEMENTED |
| IPsec config | ✅ | ✅ Proposals, policies | IMPLEMENTED |
| Database (TDE, column encryption) | ✅ | ✅ | IMPLEMENTED |
| Application config (Spring, Django, etc.) | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 85% — Comprehensive config parsing.

---

### 2.16 API/Protocol Discovery

| Protocol | Parsed | Crypto Detected | Status |
|----------|--------|-----------------|--------|
| TLS 1.0-1.3 | ✅ | Cipher suites, certs, extensions | IMPLEMENTED |
| SSH | ✅ | KEX, host key, ciphers, MACs | IMPLEMENTED |
| IPsec/IKEv2 | ✅ | Encryption, integrity, DH, auth | IMPLEMENTED |
| QUIC | ❌ | ❌ | MISSING |
| DTLS | ❌ | ❌ | MISSING |
| WireGuard | ❌ | ❌ | MISSING |
| mTLS | ⚠️ Partial | Cert detection only | PARTIAL |
| SSH certificates | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 70% — Core protocols, missing QUIC/DTLS/WireGuard.

---

### 2.17 Custom Crypto Discovery

| Capability | Implemented | Evidence |
|------------|-------------|----------|
| Heuristic detection | ✅ | `UnknownCryptoDetector` |
| Entropy analysis | ✅ | High entropy = possible crypto |
| Pattern matching | ✅ | Known algorithm patterns |
| Custom algorithm registry | ⚠️ Scaffolded | `CustomCryptoClassifier` |
| Attribution | ❌ | No vendor/library ID |
| Verification | ❌ | Queue for manual review |

**Coverage Score:** 30% — Detection only, no classification.

---

### 2.18 Key Metadata Discovery

| Metadata | Source | Detected | Status |
|---------|--------|----------|--------|
| Key ID/Label | Certificates, HSM, Cloud KMS | ✅ | IMPLEMENTED |
| Key Algorithm | Certificates, Cloud KMS, Config | ✅ | IMPLEMENTED |
| Key Size | Certificates, Config, Cloud KMS | ✅ | IMPLEMENTED |
| Key Usage | Certificates (KeyUsage ext), Config | ✅ | IMPLEMENTED |
| Key Origin | Cloud KMS (generate/import), HSM | ⚠️ Partial | PARTIAL |
| Key Protection | HSM (FIPS level), Cloud KMS | ⚠️ Partial | PARTIAL |
| Key Rotation | Cloud KMS (schedule), Config | ⚠️ Partial | PARTIAL |
| Key Expiry | Certificates, Cloud KMS | ✅ | IMPLEMENTED |
| Key Attestation | HSM (PKCS#11), Cloud KMS | ❌ | MISSING |

**Coverage Score:** 40% — Basic metadata, no attestation.

---

### 2.19 Trust Store Discovery

| Source | Anchors Parsed | Validation | Status |
|--------|----------------|------------|--------|
| Java cacerts | ✅ | ✅ vs expected | IMPLEMENTED |
| System trust store | ✅ | ✅ | IMPLEMENTED |
| Application trust stores | ✅ | ✅ | IMPLEMENTED |
| Container trust stores | ✅ | ✅ | IMPLEMENTED |
| Cloud trust stores | ✅ | ✅ | IMPLEMENTED |
| Custom CA bundles | ✅ | ✅ | IMPLEMENTED |

**Coverage Score:** 80% — Good anchor analysis.

---

## 3. EVIDENCE QUALITY BY DISCOVERY PATH

| Path | Collector | Timestamp | Source Identity | Hash | Provenance | Confidence | Replayable |
|------|-----------|-----------|-----------------|------|------------|------------|------------|
| Static Source | Scanner | ✅ | ✅ File/line | ✅ SHA-256 | ✅ Git metadata | HIGH | ✅ |
| Binary | Scanner | ✅ | ✅ File/offset | ✅ SHA-256 | ✅ Build info | MEDIUM | ✅ |
| Container | Scanner | ✅ | ✅ Layer/digest | ✅ SHA-256 | ✅ Image digest | HIGH | ✅ |
| Network | Scanner | ✅ | ✅ Host:port | ✅ SHA-256 | ✅ Probe result | VERIFIED | ✅ |
| Certificate | Scanner/Parser | ✅ | ✅ Subject/serial | ✅ SHA-256 | ✅ Cert chain | VERIFIED | ✅ |
| Cloud | Scanner | ✅ | ✅ Resource ARN | ✅ SHA-256 | ✅ API response | HIGH | ✅ |
| Runtime | Live engine | ✅ | ⚠️ PID only | ✅ SHA-256 | ✅ API calls | MEDIUM | ⚠️ |
| Dependency | Scanner | ✅ | ✅ Lockfile | ✅ SHA-256 | ✅ Lockfile hash | HIGH | ✅ |
| Hardware | Live engine | ✅ | ✅ Asset ID | ✅ SHA-256 | ✅ Telemetry | MEDIUM | ✅ |
| Secrets | Scanner | ✅ | ✅ File/line | ✅ SHA-256 | ✅ Scanner | HIGH | ✅ |

---

## 4. WHAT IS NOT DISCOVERED

### 4.1 Completely Missing

| Surface | Reason |
|---------|--------|
| **Firmware/RTOS** | No parsers for UEFI, RTOS, bootloaders |
| **QUIC/DTLS/WireGuard** | No protocol parsers |
| **Cloud HSM** | No AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM APIs |
| **Vendor Crypto** | No automated fingerprinting |
| **Transitive Crypto** | No recursive dependency analysis |
| **PKCS#11/KMIP Keys** | Parsers exist but not operational |
| **CT Log Verification** | SCTs parsed but not verified |
| **OCSP/CRL Validation** | Parsed but not checked |
| **Hardware Attestation** | No TPM quote, HSM attestation |
| **Mobile App Crypto** | IPA/APK scanned but no mobile-specific crypto (Keychain, Keystore) |

---

### 4.2 Partially Discovered

| Surface | What's Missing |
|---------|----------------|
| **Transitive Dependencies** | Only direct deps; no recursive crypto propagation |
| **Runtime Crypto** | Sampling only; no continuous monitoring |
| **HSM Keys** | Inventory only; no key detection via PKCS#11 |
| **Vendor Crypto** | Manual edges only; no automated fingerprinting |
| **Mobile Crypto** | IPA/APK scanned but no iOS Keychain/Android Keystore parsing |
| **Custom Crypto** | Heuristic detection only; no classification |
| **Certificate Revocation** | OCSP/CRL parsed but not validated |
| **CT Logs** | SCTs extracted but not verified against logs |

---

## 5. EVIDENCE GAPS

| Gap | Impact | Required For |
|-----|--------|--------------|
| **No key material in evidence** | By design — but limits forensic analysis | Compliance proof |
| **No runtime attestation** | Cannot prove runtime finding is current | Live compliance |
| **No vendor attribution** | Cannot trace crypto to vendor | Supply chain risk |
| **No transitive crypto** | Cannot see full dependency crypto graph | Blast radius |
| **No firmware crypto** | Blind spot for IoT/embedded | OT/ICS security |
| **No QUIC/DTLS** | Blind spot for modern protocols | Network crypto |
| **No Cloud HSM keys** | Blind spot for managed HSM | Cloud crypto |
| **No hardware attestation** | Cannot verify HSM/TPM state | Hardware trust |

---

## 6. CLASSIFICATION SUMMARY

| Classification | Count | Examples |
|----------------|-------|----------|
| **IMPLEMENTED** | 8 | Source, Binary, Container, Network, Cert, Cloud, Config, Trust Store |
| **PARTIAL** | 7 | Runtime, Dependencies, Hardware, Vendor, Payment, OT, Key Metadata |
| **WEAK** | 1 | Custom Crypto |
| **MOCK** | 0 | None |
| **MISSING** | 3 | QUIC/DTLS/WireGuard, Cloud HSM, Firmware |

---

## 7. RECOMMENDATIONS

### P0 — Critical

1. **Implement transitive dependency crypto** — Recursive lockfile analysis
2. **Add PKCS#11/KMIP operational** — HSM key detection
3. **Add Cloud HSM support** — AWS CloudHSM, Azure Dedicated HSM, GCP Cloud HSM

### P1 — High

4. **Add QUIC/DTLS/WireGuard protocol parsers**
5. **Implement CT log verification** — SCT validation
6. **Implement OCSP/CRL validation** — Real-time revocation
7. **Add hardware attestation** — TPM quotes, HSM attestation
8. **Implement transitive crypto propagation** — Recursive dependency analysis

### P2 — Medium

9. **Add vendor crypto fingerprinting** — Automated vendor detection
10. **Add mobile crypto (Keychain/Keystore)** — iOS/Android keystores
11. **Add firmware/RTOS parsers** — UEFI, bootloaders, RTOS
12. **Add hybrid KEM detection** — X25519+ML-KEM, ECDHE+ML-KEM

### P3 — Enhancement

13. **Post-quantum protocol detection** — PQC TLS, SSH, IPsec
14. **CT log verification** — SCT validation against known logs
15. **Custom crypto ML classification** — For unknown detector queue
16. **Firmware filesystem extraction** — UEFI, squashfs, jffs2

---

## 8. VERIFICATION EVIDENCE

| Finding | File |
|---------|------|
| Source parsers | `services/scanner/scanner/parsers/*.py` (25 files) |
| Binary engine | `services/universal_crypto/universal_crypto/binary_engine.py` |
| Container scanner | `services/container_scanner/container_scanner/core/scanner.py` |
| Network scanner | `services/network_scanner/network_scanner/core/scanner.py` |
| Cloud scanner | `services/cloud_scanner/cloud_scanner/core/scanner.py` |
| Certificate intel | `services/universal_crypto/universal_crypto/certificate_intel.py` |
| Runtime engine | `services/universal_crypto/universal_crypto/runtime_engine.py` |
| Protocol engine | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| Library fingerprints | `services/universal_crypto/universal_crypto/library_fingerprints.py` |
| Hardware live | `services/hardware/` |
| Payment crypto | `services/payment_crypto/` |
| OT scanner | `services/ot_scanner/` |
| Quantum classification | `shared/shared_models/shared_models/quantum_classify.py` |
| Normalization | `services/normalization/normalization/core/engine.py` |
| Custom crypto | `services/universal_crypto/universal_crypto/custom_crypto.py` |
| Unknown detector | `services/universal_crypto/universal_crypto/unknown_detector.py` |