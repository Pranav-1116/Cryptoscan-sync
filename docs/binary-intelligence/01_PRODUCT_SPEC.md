# CryptoScan Binary Intelligence Engine — Product Specification

Binary cryptographic discovery from compiled artifacts: ELF, PE, Mach-O, JVM, firmware and beyond.

> Source: product specification received 2026-10-16. This document is the
> requirements source for the Binary Intelligence Engine. Requirements
> marked "not in the first release" are register-only until their phase.

A bank's cryptographic implementation is not always visible in its source code. It may exist inside compiled executables, shared libraries, static libraries, firmware, mobile applications, vendor appliances and proprietary software.

For example, a bank might have an application whose source code is unavailable, but the bank has an authorized copy of its executable. CryptoScan should be able to inspect that executable and identify cryptographic algorithms, libraries, protocols, key-handling indicators and potential PQC migration concerns.

The objective should be:

> Discover cryptographic capabilities from compiled artifacts, establish evidence for every finding, map the findings to the bank's technology estate, and identify what can and cannot be proven from static binary analysis.

One important distinction: binary scanning is not simply running `strings` against an executable and searching for `AES`, `RSA` or `SHA256`. That would produce many misleading results. We need a structured binary analysis pipeline with format identification, static analysis, cryptographic detection, dependency resolution, evidence validation and confidence scoring.

## 1. First, understand what we are building

There is an important distinction between the current binary input capability and the full binary intelligence engine we want.

Your existing CryptoScan design already has a binary scan path: the SBOM scan interface supports `kind=source|container|binary`, with separate artifact handling and bounded binary evidence. That means we should extend the existing path, not create a completely separate binary-scanner product. The earlier architecture also separates binary inspection from the queued cryptographic AST/source parsing pipeline.

The next objective is to make binary scanning a first-class capability with deeper analysis and evidence.

### What is a binary artifact?

A binary is a file containing executable code, compiled libraries, machine instructions, data or firmware. It may not be human-readable source code.

**Linux ELF** — Executables, shared libraries (`.so`), object files and system components. Example: `payments-service`, `libcrypto.so`

**Windows PE** — `.exe`, `.dll`, `.sys`, `.efi` and other Windows executable formats. Example: a bank's Windows transaction-processing DLL

**Mach-O** — macOS and iOS executable files and libraries. Example: a native application component

**Java and JVM artifacts** — `.class`, `.jar`, `.war`, `.ear` and related bytecode. Example: a compiled Java banking application using Bouncy Castle

**Firmware and embedded binaries** — Firmware images, extracted root filesystems, bootloaders and device executables. Example: a network appliance or HSM-management appliance firmware image

Other formats worth supporting include Android APK, .NET assemblies, WebAssembly, static archives (`.a`), object files (`.o`), and universal/fat binaries.

Important: a file extension is only a hint. CryptoScan must identify the actual file format from its contents, because files can be renamed or have misleading extensions.

## 2. What exactly should CryptoScan discover?

We should design the scanner around eight discovery dimensions.

| Dimension                     | What we want to discover                                                                  |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| Binary identity               | Format, architecture, platform, compiler indicators and file hashes                       |
| Software composition          | Embedded libraries, versions, packages and dependencies                                   |
| Cryptographic libraries       | OpenSSL, BoringSSL, mbedTLS, wolfSSL, libsodium, etc.                                     |
| Cryptographic algorithms      | AES, RSA, ECC, SHA, HMAC, ML-KEM, ML-DSA, etc.                                            |
| Cryptographic operations      | Encryption, signing, verification, hashing, key exchange and random generation indicators |
| Certificates and key material | Embedded public certificates, public keys, fingerprints and metadata                      |
| Protocols and configuration   | TLS, SSH, IPsec, cipher suites and cryptographic configuration indicators                 |
| PQC exposure                  | Quantum-vulnerable dependencies, available PQC implementations and migration barriers     |

This gives us more than a list of algorithm names. It gives the bank an evidence-backed picture of cryptography inside compiled software.

### Cryptographic libraries we should recognize

We need a versioned fingerprint catalogue, not a few hardcoded string searches.

| Ecosystem               | Libraries / interfaces to recognize         |
| ----------------------- | ------------------------------------------- |
| OpenSSL ecosystem       | OpenSSL, BoringSSL, LibreSSL                |
| Embedded / IoT          | mbedTLS, wolfSSL                            |
| General cryptography    | Botan, NSS, GnuTLS                          |
| Modern native libraries | libsodium                                   |
| Windows                 | CNG, BCrypt, CryptoAPI, NCrypt              |
| Apple                   | CommonCrypto, CryptoKit, Security framework |
| Java                    | JCA/JCE providers, Bouncy Castle            |
| Go                      | `crypto/*`, vendored crypto packages        |
| Rust                    | RustCrypto crates, ring                     |
| Hardware integration    | PKCS#11, vendor HSM SDKs                    |

Some implementations are statically linked, stripped or renamed. We therefore need multiple detection techniques rather than relying on exported library names.

## 3. The complete binary scanning pipeline

This is the architecture I recommend for CryptoScan.

**Binary Intelligence Pipeline**

1. Artifact intake — Upload · Repository artifact · CI/CD build · Authorized bank collector
2. Integrity and safety — SHA-256 · Size limits · Type identification · Quarantine · No execution
3. Binary format analysis — ELF · PE · Mach-O · JVM · APK · WASM · Firmware
4. Static intelligence extraction — Headers · Sections · Symbols · Imports · Strings · Dependencies · Signatures
5. Cryptographic detection — Library fingerprints · Algorithm indicators · Function analysis · Certificates · PQC
6. Evidence and confidence engine — Finding provenance · Evidence hashes · Detection method · Confidence · Limitations
7. Shared CryptoScan intelligence — SBOM · CBOM · Digital Twin · Dependencies · Policy · Drift · PQC simulation
8. Verifiable outputs — Evidence-backed CBOM · SBOM · Risk findings · Reports · API · Audit history

Each stage should be a separate, testable service or module, but all stages must share the same job, evidence and asset identity models.

## 4. Deep analysis of each pipeline stage

### Stage 1 — Artifact intake

CryptoScan needs to accept binary artifacts from several authorized sources:

- Direct upload through the CryptoScan dashboard.
- Local filesystem scanning.
- Git repositories and release artifacts.
- CI/CD build outputs.
- Container image layers.
- Authorized bank infrastructure collectors.
- Firmware packages provided by the bank or device vendor.

For the first version, support direct upload, local filesystem scanning and CI/CD artifacts. Expand to remote collectors after the local pipeline is reliable.

Every submitted artifact should have:

```
artifact_id
tenant_id
original_filename
detected_format
file_size
sha256
source_type
source_location
uploaded_by
received_at
scan_profile
scan_status
```

Critical security controls:

- Validate actual file content, not extension.
- Enforce file-size, processing-time and nesting-depth limits.
- Prevent path traversal and archive extraction attacks.
- Protect against ZIP bombs and recursive archive nesting.
- Store the original artifact separately from extracted metadata.
- Never overwrite an existing artifact with a different digest.
- Record who submitted the artifact and under which authorization.

For a bank deployment, the artifact must stay inside the bank-controlled environment.

### Stage 2 — Binary identification and structural parsing

Before looking for cryptography, CryptoScan must understand the file.

For example, for ELF:

- ELF32 or ELF64.
- Little-endian or big-endian.
- CPU architecture.
- Executable, shared object or relocatable object.
- Entry point.
- Program headers.
- Section headers.
- Dynamic symbols.
- Static symbols, when present.
- Relocation tables.
- Dynamic dependencies.
- Build identifiers and available compiler metadata.

For PE:

- PE32 or PE32+.
- Machine architecture.
- DOS and PE headers.
- Section table.
- Import and export tables.
- Resources.
- Debug information.
- Authenticode signature information.
- DLL dependencies.

For Mach-O:

- 32-bit or 64-bit.
- CPU architecture.
- Load commands.
- Dynamic libraries.
- Symbol tables.
- Code-signing metadata.
- Universal binary slices.

For Java:

- Class metadata.
- Package names.
- Constant pools.
- Method references.
- JAR manifests.
- Dependency metadata.
- Embedded libraries.

Why is this important?

Because the same function name or byte sequence can mean different things in different architectures or formats. We need to understand the executable structure before drawing cryptographic conclusions.

### Stage 3 — Static extraction

This stage extracts information without executing the binary.

I recommend six independent extraction methods.

| Method                 | What it discovers                                             | Main limitation                                  |
| ---------------------- | ------------------------------------------------------------- | ------------------------------------------------ |
| Header analysis        | Platform, architecture and executable format                  | Does not reveal all application behavior         |
| Import/export analysis | External functions and libraries                              | Static linking may hide them                     |
| Symbol analysis        | Function names and symbol relationships                       | Stripped binaries may have no useful symbols     |
| String extraction      | Algorithm names, version strings and configuration indicators | Strings can be unused, misleading or decoys      |
| Dependency analysis    | Shared libraries and embedded components                      | Runtime-loaded components may be missing         |
| Code analysis          | Function patterns and cryptographic implementations           | Optimization and obfuscation complicate matching |

Important design decision: don't treat a string such as `AES-256-GCM` as proof that the executable uses AES-256-GCM.

It could be:

- A debug string.
- An unused configuration option.
- A help message.
- A library capability.
- An actual implementation or operation.

We need to distinguish those possibilities in the findings.

### Stage 4 — Cryptographic function discovery

This is the most important part of the binary scanner.

For native binaries, build a version-controlled function signature database.

Example:

| Library     | Function indicator      | Potential finding                    |
| ----------- | ----------------------- | ------------------------------------ |
| OpenSSL     | `EVP_aes_256_gcm`       | AES-256-GCM capability/use indicator |
| OpenSSL     | `RSA_generate_key_ex`   | RSA key-generation indicator         |
| OpenSSL     | `EVP_sha256`            | SHA-256 capability/use indicator     |
| libsodium   | `crypto_sign_ed25519`   | Ed25519 signature indicator          |
| Windows CNG | `BCryptGenerateKeyPair` | Key-pair generation interface        |
| PKCS#11     | `C_SignInit`            | HSM signing interface                |
| PKCS#11     | `C_DecryptInit`         | HSM decryption interface             |

A function reference alone is not sufficient to conclude that the algorithm is actively used. We should examine:

1. Whether the symbol exists.
2. Whether a call/reference to it exists.
3. Whether the call is reachable from an entry point, where feasible.
4. Whether parameters or constants reveal the algorithm variant.
5. Whether the operation is conditional on runtime configuration.
6. Whether the result is corroborated by configuration, runtime evidence or other sources.

For stripped or statically linked binaries, we need additional techniques:

- Function signature matching.
- Known library fingerprint matching.
- Instruction sequence analysis.
- Cryptographic constant recognition.
- Cross-reference analysis.
- Function similarity analysis.
- Compiler-aware pattern recognition.

The detection engine should support multiple levels of analysis rather than treating every binary as a full reverse-engineering project.

### Stage 5 — Algorithm identification

The engine should recognize algorithm families and variants separately.

| Category                 | Detection targets                                      |
| ------------------------ | ------------------------------------------------------ |
| Symmetric encryption     | AES-128/192/256, DES, 3DES, ChaCha20                   |
| Authenticated encryption | AES-GCM, AES-CCM, ChaCha20-Poly1305                    |
| Asymmetric encryption    | RSA, EC-based encryption, relevant KEM implementations |
| Digital signatures       | RSA-PSS, ECDSA, Ed25519, DSA, ML-DSA                   |
| Key exchange             | DH, ECDH, X25519, ML-KEM                               |
| Hashing                  | MD5, SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3               |
| MAC                      | HMAC, CMAC, Poly1305                                   |
| Key derivation           | PBKDF2, HKDF, scrypt, Argon2                           |
| Random generation        | OS CSPRNG interfaces and library RNG APIs              |
| Protocol cryptography    | TLS, SSH, IPsec and their cryptographic capabilities   |

Do not just store `RSA`. Store the strongest evidence-supported detail:

```
algorithm_family: RSA
algorithm_variant: RSA-2048
operation: digital_signature
mode_or_padding: PSS
key_size_bits: 2048
```

If the binary only proves that an RSA function is present but not the key size, then `key_size_bits` must remain unknown.

Do not invent missing information.

### Stage 6 — Certificate and key-material inspection

Binaries sometimes contain embedded certificates, public keys or other cryptographic material.

CryptoScan should identify:

- PEM certificates.
- DER certificates.
- X.509 metadata.
- Public keys.
- Certificate fingerprints.
- Issuer and subject.
- Validity dates.
- Public-key algorithm and size.
- Certificate signature algorithm.
- Embedded certificate chains where parsable.

Private-key handling needs a strict boundary.

Never export, display or store private-key contents as ordinary findings. Do not log secrets or key material into CryptoLog. If a private key is detected, record a protected detection event, artifact location and classification, and apply an approved secure-handling policy. Ideally, inspection should establish the presence and metadata without persisting the secret.

The scanner must not interpret an arbitrary high-entropy byte sequence as a cryptographic key without adequate structural evidence.

### Stage 7 — Firmware and embedded binary analysis

This is particularly interesting for banks because they operate network devices, appliances, HSMs, security gateways and other infrastructure.

A firmware image may contain:

- Bootloader.
- Kernel.
- Root filesystem.
- Shared libraries.
- Application executables.
- Configuration files.
- Certificates.
- Cryptographic implementations.
- Vendor-specific components.

A suitable pipeline is:

```
Firmware image
    |
    v
Identify container / image format
    |
    v
Extract supported partitions safely
    |
    v
Identify filesystem
    |
    v
Inventory executable and library files
    |
    v
Run binary intelligence on each executable
    |
    v
Identify certificates and crypto configurations
    |
    v
Build firmware component and crypto relationships
    |
    v
Generate evidence-backed findings
```

Potential technologies include Binwalk for firmware identification and extraction, format-specific filesystem parsers, and the same binary analysis engine for extracted executables.

Do not treat a vendor firmware version as proof of every component or algorithm inside it. Firmware extraction can be incomplete, encrypted, compressed or protected.

## 5. The most important distinction: capability versus actual usage

This is where CryptoScan can become significantly more useful than a simple binary inventory tool.

Imagine the following hypothetical bank executable:

```
payments-engine
    |
    +-- libcrypto.so
    |
    +-- OpenSSL functions
    |      |
    |      +-- EVP_aes_256_gcm
    |      +-- RSA_generate_key_ex
    |      +-- EVP_sha256
    |
    +-- TLS configuration
           |
           +-- TLS 1.2
           +-- TLS 1.3
```

There are several different claims we could make.

| Evidence                                          | What CryptoScan can conclude                                              |
| ------------------------------------------------- | ------------------------------------------------------------------------- |
| `libcrypto.so` is dynamically linked              | The executable depends on that library                                    |
| AES function is imported                          | AES functionality is referenced                                           |
| AES function is called from a reachable code path | Stronger evidence of potential AES operation                              |
| AES-256-GCM parameters are confirmed              | Evidence for that specific variant                                        |
| Runtime telemetry records the operation           | Evidence that the operation occurred in the observed environment and time |
| TLS configuration permits TLS 1.2                 | Configuration capability, not proof of a particular live connection       |

This distinction must be built into the product.

### CBOM relationship model

We should use the CycloneDX CBOM model, especially its distinction between `provides` and `uses`.

- A cryptographic library can provide an algorithm.
- An application can use that algorithm.
- A protocol can depend on several cryptographic algorithms.
- An HSM can provide key operations to an application through PKCS#11.

This distinction is central to avoiding false claims.

For example:

```
payments-engine
      |
      | dependsOn
      v
libcrypto.so
      |
      | provides
      v
AES-256-GCM
      |
      | used by (only when supported by evidence)
      v
payments-engine
```

We must not create the final `uses` relationship simply because the application and library appear in the same binary or deployment.

## 6. Static analysis versus dynamic analysis

We need both, but they have different purposes.

**Static binary analysis — build first:**

- Inspects executable files without running them.
- Identifies binary formats, libraries, functions, algorithm indicators and dependencies.
- Can be performed on offline bank artifacts.
- Useful for third-party software where source code is unavailable.

**Dynamic cryptographic analysis — advanced phase:**

- Observes cryptographic behavior while software runs in an approved test environment.
- Can reveal actual operations, runtime-selected algorithms and library behavior.
- Can identify configuration-dependent cryptography.
- Requires execution controls, instrumentation and a suitable test environment.

Static analysis cannot always prove which algorithms are used at runtime. Dynamic analysis cannot prove behavior that was not exercised during the observation period.

My recommendation is:

1. Build the static engine first.
2. Make its evidence and confidence model reliable.
3. Add controlled dynamic analysis as a separate, optional capability.
4. Correlate static findings with runtime observations and network evidence.

Do not execute an unknown customer binary on the CryptoScan API server. Dynamic analysis should use an isolated, bank-approved execution environment with strict network, filesystem, privilege and resource controls.

For supported environments, instrument or collect approved telemetry for OpenSSL EVP operations, Java JCA/JCE operations, Windows CNG operations, PKCS#11 calls, TLS handshakes and negotiated parameters, certificate validation, and key-generation and signing operations.

For each observation, record the process identity, binary digest, library identity, operation, timestamp, environment and evidence source. Do not capture secret key material or plaintext.

## 7. Evidence and confidence: the feature that makes this bank-grade

A binary scanner without evidence discipline will produce a list of guesses. CryptoScan needs a finding model that explains exactly why it believes something.

Every finding should carry:

```
{
  "finding_id": "unique-id",
  "artifact_id": "artifact-id",
  "artifact_sha256": "sha256-value",
  "subject": "payments-engine",
  "finding_type": "cryptographic_algorithm",
  "algorithm": "AES",
  "variant": "AES-256-GCM",
  "operation": "encryption",
  "detection_method": "function_and_call_analysis",
  "evidence": [
    {
      "type": "function_reference",
      "location": "ELF symbol/function offset",
      "description": "Recognized cryptographic function reference"
    }
  ],
  "confidence": "high",
  "usage_status": "statically_supported",
  "runtime_confirmed": false,
  "limitations": [],
  "scanner_version": "version",
  "signature_database_version": "version",
  "observed_at": "timestamp"
}
```

This is an illustrative data contract, not a claim that your existing API already returns these exact fields.

### Suggested evidence classifications

| Classification       | Meaning                                                         |
| -------------------- | --------------------------------------------------------------- |
| `observed`           | Directly observed in an analyzed artifact or authorized runtime |
| `strongly_supported` | Multiple independent static indicators support the finding      |
| `indicated`          | One reliable but incomplete indicator exists                    |
| `inferred`           | Derived from a dependency or contextual relationship            |
| `unknown`            | Insufficient evidence                                           |
| `not_detected`       | No finding was detected within the declared analysis scope      |

These are proposed CryptoScan classifications. They should be distinct from a numerical confidence score.

### Confidence must not be confused with coverage

For example:

- A binary can have 98% analysis coverage and still contain an unknown algorithm.
- A finding can have high confidence while the overall binary remains only partially analyzed.
- A scanner can detect no cryptography because symbols are stripped, not because the binary is cryptography-free.

We need two separate measurements:

**Finding confidence:** How strongly does the evidence support this particular finding?

**Analysis coverage:** How much of the artifact did CryptoScan successfully inspect?

A useful analysis coverage report should include:

- Total artifact size.
- Bytes and sections inspected.
- Number of executable sections.
- Number of recognized functions.
- Number of unresolved dependencies.
- Unsupported architectures.
- Packed or encrypted regions.
- Analysis timeouts.
- Extraction failures.
- Whether symbols were stripped.
- Whether deep analysis was completed.

Never report `No cryptography found` as `Cryptography absent` unless there is a defensible basis for that conclusion.

## 8. How binary scanning connects to all six BOMs

We should not create a seventh disconnected BOM. Binary analysis should feed the existing six-BOM ecosystem.

| BOM     | Contribution from binary scanning                                                                          |
| ------- | ---------------------------------------------------------------------------------------------------------- |
| SBOM    | Binary components, embedded libraries, versions, hashes and dependencies                                   |
| CBOM    | Algorithms, cryptographic operations, protocols, certificates and evidence                                 |
| HBOM    | Firmware executables, device software, embedded components and hardware associations                       |
| NBOM    | Network-related cryptographic capabilities, correlated with independently observed endpoints and protocols |
| VBOM    | Vendor software, proprietary binaries, firmware and supplier dependencies                                  |
| TechBOM | Complete relationship between application, binary, library, device, service and cryptographic assets       |

Notice that we do not automatically assume that the Payments Application uses an HSM just because the binary contains a PKCS#11 library. We need a supported relationship, such as a confirmed call path, configuration mapping or authorized runtime evidence.

The Digital Twin should preserve relationship provenance and distinguish:

- Directly observed relationship.
- Static dependency.
- Configuration-derived relationship.
- Runtime-confirmed relationship.
- Inferred relationship.
- Unresolved relationship.

This is consistent with your existing principle: a business system is not a scan target, and relationships must come from evidence rather than names or co-occurrence.

## 9. PQC intelligence from compiled binaries

This is where binary analysis becomes commercially valuable for ZELNX.

A bank might not have source code for a third-party transaction application. Yet it needs to understand whether that application is dependent on cryptographic implementations that will require migration.

CryptoScan should look for three things.

### A. Quantum-vulnerable cryptography

Examples of algorithm families requiring PQC migration assessment include RSA, finite-field Diffie–Hellman, ECDH, ECDSA, EdDSA.

The scanner should not classify all uses of these algorithms as immediate vulnerabilities. It should assess the context, role, security requirements and migration dependency.

### B. PQC implementations already present

Identify indicators for ML-KEM, ML-DSA, SLH-DSA, hybrid key exchange, hybrid certificates or protocol support where applicable.

The presence of a PQC implementation does not prove that the bank's application actually uses it. It could be unused library functionality.

### C. Migration blockers

Binary intelligence should identify:

- Old cryptographic libraries.
- Hardcoded algorithm selections.
- Unsupported library versions.
- Vendor-specific cryptographic interfaces.
- Static-linked cryptographic dependencies.
- Proprietary binary components without source availability.
- Incompatible protocol dependencies.
- Unavailable replacement libraries.
- Firmware update dependencies.

Example assessment shape:

```
PQC Migration Assessment

Quantum-vulnerable algorithm indicators: Detected
PQC implementation indicators: Not detected
Cryptographic library: Identified
Static linking: Suspected / evidence-dependent
Source availability: Unavailable
Vendor replacement dependency: Requires confirmation
Migration readiness: Not established
```

This is more useful than simply saying "RSA found."

## 10. Recommended tools and engineering components

Do not write every parser, disassembler and archive extractor from scratch. Build ZELNX's own orchestration, cryptographic intelligence, evidence, policy and relationship engines around proven specialist tools.

| Component                     | Suggested technology                          | Purpose                                         |
| ----------------------------- | --------------------------------------------- | ----------------------------------------------- |
| ELF parsing                   | LIEF, pyelftools                              | ELF headers, sections, symbols and dependencies |
| PE parsing                    | LIEF, pefile                                  | Windows executable structure                    |
| Mach-O parsing                | LIEF                                          | Apple executable formats                        |
| General binary identification | libmagic, LIEF                                | Actual file-format identification               |
| Java analysis                 | JVM class/JAR parsers                         | Bytecode and package analysis                   |
| Binary reverse engineering    | Ghidra headless                               | Deep function and instruction analysis          |
| Firmware extraction           | Binwalk                                       | Firmware identification and extraction          |
| SBOM discovery                | Syft                                          | Component inventory                             |
| Crypto asset detection        | ZELNX signature and rule engine               | Algorithm/library discovery                     |
| Certificate parsing           | OpenSSL libraries / X.509 parser              | Certificate and public-key metadata             |
| Reporting                     | Existing CryptoScan pipeline                  | SBOM, CBOM and evidence export                  |

Ghidra is useful for deep analysis, but should not be required for every artifact. Binwalk is useful for firmware. Syft can supplement component inventory, but it is not a replacement for cryptographic function analysis.

### What ZELNX must own

The differentiating IP should be:

1. Binary cryptographic fingerprint database.
2. Algorithm and implementation detection logic.
3. Static evidence interpretation.
4. Capability-versus-usage classification.
5. Confidence and coverage calculations.
6. CBOM generation and dependency mapping.
7. Digital Twin relationship correlation.
8. PQC migration impact assessment.
9. Historical binary comparison and drift intelligence.
10. Bank-grade evidence integrity and audit.

The third-party tools should be replaceable adapters. Their raw output should never become the authoritative CryptoScan result without validation and normalization.

## 11. Proposed CryptoScan module architecture

A dedicated binary intelligence package under the existing SBOM and scanning architecture. Before implementation, map it to the actual repository so we extend existing services rather than duplicate them.

Target layout (map to the actual repository before implementation):

```
services/binary_intelligence/
├── api/            routes, schemas
├── intake/         artifact validator, storage, hasher
├── formats/        elf, pe, macho, java, wasm, firmware parsers
├── extractors/     header, section, symbol, import, string,
│                   dependency, certificate extractors
├── crypto_detection/ library fingerprints, function signatures,
│                   algorithm/operation detectors, crypto constants,
│                   pqc detector
├── deep_analysis/  ghidra adapter, firmware adapter, scheduler
├── evidence/       evidence builder, provenance, confidence, coverage
├── normalization/  component, algorithm, dependency normalizers
├── integrations/   sbom, cbom, digital twin, cryptolog, pqc adapters
└── tests/          fixtures and per-module tests
```

### Database additions

The database should preserve the original artifact, the analysis run, individual findings and evidence separately.

| Entity                        | Purpose                                                 |
| ----------------------------- | ------------------------------------------------------- |
| `binary_artifacts`            | Artifact identity, digest, source and storage reference |
| `binary_scan_runs`            | Scan configuration, scanner version and status          |
| `binary_sections`             | Sections, offsets, sizes and attributes                 |
| `binary_components`           | Identified software components and libraries            |
| `binary_symbols`              | Relevant imported/exported symbols                      |
| `binary_crypto_findings`      | Normalized cryptographic findings                       |
| `binary_evidence`             | Evidence references and provenance                      |
| `binary_dependencies`         | Component and library dependency relationships          |
| `binary_analysis_coverage`    | Unsupported areas and analysis completeness             |
| `binary_fingerprint_versions` | Version history for signatures and rules                |

Use the existing tenant, audit, evidence and artifact models wherever possible. Avoid introducing duplicate artifact identity or evidence storage systems.

The original artifact's SHA-256 should be linked to every scan run. If the artifact changes, it must become a new immutable artifact version.

## 12. API design

| Method | Endpoint                                              | Purpose                              |
| ------ | ----------------------------------------------------- | ------------------------------------ |
| POST   | `/api/v1/binary/scan`                                 | Submit an authorized binary artifact |
| POST   | `/api/v1/binary/scan/path`                            | Scan an approved local path          |
| GET    | `/api/v1/binary/scans/{scan_id}`                      | Scan status and metadata             |
| GET    | `/api/v1/binary/artifacts/{artifact_id}`              | Artifact details                     |
| GET    | `/api/v1/binary/artifacts/{artifact_id}/findings`     | Cryptographic findings               |
| GET    | `/api/v1/binary/artifacts/{artifact_id}/dependencies` | Binary dependency graph              |
| GET    | `/api/v1/binary/artifacts/{artifact_id}/coverage`     | Coverage and analysis limitations    |
| GET    | `/api/v1/binary/artifacts/{artifact_id}/evidence`     | Evidence references                  |
| POST   | `/api/v1/binary/artifacts/{artifact_id}/rescan`       | Rescan with a new profile            |
| GET    | `/api/v1/binary/artifacts/{artifact_id}/comparison`   | Compare artifact versions            |

Example scan request:

```
{
  "artifact_source": "upload",
  "analysis_profile": "standard",
  "requested_analyses": [
    "format_identification",
    "component_discovery",
    "crypto_detection",
    "certificate_analysis",
    "pqc_assessment"
  ],
  "deep_analysis": false,
  "generate_sbom": true,
  "generate_cbom": true
}
```

The API should support asynchronous jobs because large binaries and firmware images may take longer than a normal HTTP request.

### Three scan profiles

| Profile  | Operations                                                                                  | Intended use                      |
| -------- | ------------------------------------------------------------------------------------------- | --------------------------------- |
| Quick    | Format, hash, metadata, strings, imports, basic signatures                                  | Fast artifact triage              |
| Standard | Quick + symbols, dependencies, library fingerprints, crypto analysis and evidence           | Normal bank scanning              |
| Deep     | Standard + advanced function analysis, firmware extraction and optional reverse engineering | High-value or difficult artifacts |

A deep scan should never be the default for every file.

## 13. Performance and resource management

Design for a local development machine (8 GB RAM) before scaling to a bank's infrastructure: one scan orchestrator, one or two binary worker processes, local filesystem or object storage for artifacts, Ghidra headless as an optional isolated deep-analysis worker. Avoid running Ghidra against every binary.

Measure independently: file intake time, hash calculation time, format identification time, symbol extraction time, dependency analysis time, cryptographic detection time, deep-analysis time, peak RAM per worker, CPU time, storage consumption, scan failure rate, findings per artifact, evidence completeness.

Do not advertise fixed scanning speeds until you have measured representative artifacts across multiple architectures and sizes.

## 14. Security: especially important for banking

Binary files are untrusted input. A parser vulnerability could become a serious problem for CryptoScan itself.

| Threat                   | Required protection                                        |
| ------------------------ | ---------------------------------------------------------- |
| Malformed binary         | Safe parsers, bounded reads and error isolation            |
| ZIP bomb                 | Decompression limits and recursion limits                  |
| Parser exploit           | Sandboxed worker processes                                 |
| Resource exhaustion      | CPU, RAM, disk and execution time limits                   |
| Path traversal           | Safe extraction and canonical path validation              |
| Symlink attacks          | No-follow file handling and isolated extraction roots      |
| Malicious executable     | Never execute during static analysis                       |
| Cross-tenant access      | Tenant-scoped authorization and storage                    |
| Artifact replacement     | Immutable digest-based identity                            |
| Sensitive binary leakage | On-prem storage, encryption and access audit               |
| Parser/tool compromise   | Pinned tool versions, signed updates and dependency review |

Also:

- No arbitrary shell execution from uploaded files.
- No automatic external network access from analysis workers.
- No automatic submission to public malware or scanning services.
- No private-key content in findings, logs or reports.
- No hidden upload of bank artifacts to ZELNX.
- All deep execution must be explicitly authorized and isolated.

These controls should apply to the entire scanning environment, not only the binary parser.

## 15. How to test the binary engine properly

Build a controlled binary test corpus before calling the feature production-qualified.

| Test group           | Samples                                      | Expected result                                      |
| -------------------- | -------------------------------------------- | ---------------------------------------------------- |
| ELF                  | Linux x86-64 and ARM64 executables           | Correct format, architecture and metadata            |
| ELF shared libraries | OpenSSL-linked and statically linked samples | Library and function detection                       |
| PE                   | Windows EXE and DLL                          | Import, export and architecture discovery            |
| Mach-O               | macOS executable and universal binary        | Correct slices and dependencies                      |
| Java                 | JAR and compiled classes                     | Crypto provider and bytecode indicators              |
| Firmware             | Supported embedded filesystem images         | Safe extraction and component inventory              |
| Stripped binaries    | No useful symbols                            | Reduced-confidence detection without false certainty |
| Obfuscated binaries  | Packed or protected examples                 | Correctly report analysis limitations                |
| PQC samples          | Test implementations of ML-KEM and ML-DSA    | Identify implementation indicators                   |
| Negative samples     | Ordinary non-cryptographic binaries          | Control false-positive rate                          |
| Malformed samples    | Invalid headers and archives                 | Safe failure without worker compromise               |
| Large samples        | Large executables and firmware               | Resource limits and job recovery                     |

### The ground-truth test corpus

For every sample, maintain:

```
sample_id
artifact_sha256
file_format
architecture
known_components
known_crypto_algorithms
known_operations
expected_dependencies
known_certificates
expected_findings
expected_non_findings
test_provenance
```

Use binaries that you build yourself for the initial test suite. This gives you known ground truth.

### Metrics we need

1. True positives.
2. False positives.
3. False negatives.
4. Precision.
5. Recall.
6. Format identification accuracy.
7. Library identification accuracy.
8. Algorithm-variant identification accuracy.
9. Evidence completeness.
10. Coverage by architecture and format.

Don't combine all of these into one overall accuracy percentage.

## 16. What the dashboard should look like

The binary intelligence interface should look like a cryptographic threat intelligence console, not an AI chatbot or generic AI dashboard.

A dedicated page: **Binary Intelligence**, with sections:

1. Artifact Inventory — all scanned binaries.
2. Binary Analysis — format, architecture, sections, symbols and dependencies.
3. Crypto Findings — algorithms, libraries, operations and evidence.
4. PQC Exposure — quantum-vulnerable indicators and migration dependencies.
5. Evidence Viewer — finding provenance and supporting evidence.
6. Version Comparison — changes between binary releases.
7. Coverage — unsupported formats, stripped symbols and unresolved regions.
8. Digital Twin — links to related systems, assets and infrastructure.

Add an evidence panel beside each finding. The user should be able to see the binary offset or function reference, detection rule, scanner version, supporting evidence and analysis limitation.

All illustrative values must be labelled illustrative — not measurements from a real scan.

## 17. Implementation roadmap

Six phases rather than every format and reverse-engineering capability at once.

**Phase 1 — Binary foundation (first priority)**

- Audit the current `kind=binary` path.
- Identify existing parsers, storage, APIs and evidence handling.
- Add robust format detection and hash-based artifact identity.
- Build ELF64 and PE64 metadata extraction.
- Add a test corpus and scan coverage reporting.

**Phase 2 — Cryptographic discovery**

- Implement function and library signature catalogues.
- Extract imports, symbols, strings and dependencies.
- Detect common cryptographic APIs.
- Normalize algorithms and operations.
- Introduce confidence and evidence classification.

**Phase 3 — SBOM and CBOM integration**

- Link binary findings to SBOM components.
- Generate CBOM cryptographic assets.
- Implement `provides` and `uses` relationships.
- Add evidence-backed dependency mapping.
- Integrate with the existing Digital Twin.

**Phase 4 — Expanded formats**

- Mach-O and universal binaries.
- Java JAR and class analysis.
- APK and .NET.
- Static libraries and WebAssembly.
- Firmware extraction and recursive component scanning.

**Phase 5 — Deep binary analysis**

- Ghidra integration.
- Stripped and statically linked binary analysis.
- Function matching and code similarity.
- Advanced algorithm identification.
- Controlled dynamic analysis as an optional separate capability.

**Phase 6 — Enterprise intelligence**

- Binary version drift.
- Vendor and firmware dependency intelligence.
- PQC migration impact analysis.
- Historical evidence comparison.
- CryptoLog and Performance Engine integration, when those modules are qualified.
- Enterprise reporting and production qualification.

## 18. What I would prioritize first

Do not start with firmware, dynamic execution, malware detection and deep reverse engineering all at once.

**Recommended MVP scope — Binary Intelligence v1:**

- ELF32/ELF64.
- PE32/PE32+.
- Static libraries and shared libraries.
- Java JAR/class files.
- Binary format identification.
- SHA-256 artifact identity.
- Imports, exports, symbols and strings.
- Cryptographic library fingerprints.
- Common algorithm and operation detection.
- Certificate metadata extraction.
- Evidence and confidence.
- SBOM/CBOM integration.
- Binary version comparison.

**Not in the first release:**

- Automatic execution of customer binaries.
- Full decompilation of every binary.
- Universal firmware support.
- Guaranteed detection of every statically linked algorithm.
- Claims of complete runtime cryptographic visibility.
