# ZELNX CryptoScan: Kernel & Operating System-Level Cryptographic Intelligence

This should become another major capability of ZELNX CryptoScan.

Binary analysis tells us what cryptographic functionality is present inside compiled applications and libraries. Kernel and OS-level analysis tells us how cryptographic capabilities are exposed, configured, managed and observed by the operating system.

This is especially important for banks because cryptography does not operate only inside application code. It is also present in:
- Operating-system cryptographic providers.
- Kernel cryptographic subsystems.
- TLS and network stacks.
- IPsec and VPN services.
- SSH and certificate services.
- TPMs, HSMs and hardware security interfaces.
- Secure boot and firmware verification.
- Disk and filesystem encryption.
- OS key stores and credential-management facilities.
- Kernel modules and device drivers.

The objective is to build an evidence-backed understanding of the cryptographic posture of the entire operating system, not merely detect whether an algorithm name exists.

I recommend naming this capability:
Proposed ZELNX module
**OS & Kernel Intelligence Engine**
Operating System Cryptographic Intelligence

Discover, assess, monitor and correlate cryptographic implementations, kernel interfaces, OS security configurations, hardware-backed trust mechanisms and runtime cryptographic activity.

One important boundary: the standard bank deployment should use authorized, read-only collection. Kernel instrumentation, runtime tracing and configuration changes must be separately approved. CryptoScan should not install a permanent kernel module, modify kernel state or intercept sensitive application data merely to perform an inventory.

## 1. What exactly are we scanning?

Think of a bank's operating system as several connected layers.

OS cryptographic architecture
- Layer 1 — Applications: Banking applications · Payment services · Java · .NET · Native executables
- Layer 2 — OS cryptographic providers: OpenSSL · GnuTLS · Windows CNG · Java JCA · Apple Security
- Layer 3 — System services and security facilities: Certificate stores · Key stores · SSH · TLS services · Disk encryption · Secure boot
- Layer 4 — Kernel: Crypto API · IPsec · Kernel TLS · Filesystem encryption · Random subsystem · Module interfaces
- Layer 5 — Hardware trust and acceleration: TPM · HSM · CPU crypto instructions · Secure element · Hardware RNG

ZELNX CryptoScan Intelligence: Evidence · Six BOMs · Digital Twin · CryptoLog · PQC · Threat intelligence

These layers are logical, not a claim that every operating system uses exactly this architecture. For example, Windows CNG and Linux AF_ALG expose different interfaces, and hardware cryptographic operations may be performed outside the host kernel.

### The 12 analysis domains

| Domain | What CryptoScan should inspect |
|---|---|
| 1. OS identity | OS family, version, kernel build and architecture |
| 2. Kernel configuration | Crypto options, modules, compiled capabilities |
| 3. Kernel crypto subsystem | Algorithms, providers, interfaces and priorities |
| 4. Cryptographic modules | Loaded modules, drivers and dependencies |
| 5. TLS and network security | TLS, SSH, IPsec, VPN and protocol configuration |
| 6. OS cryptographic libraries | OpenSSL, GnuTLS, NSS, Windows CNG and others |
| 7. Key and certificate stores | Certificates, public-key metadata, key-store interfaces |
| 8. Disk and filesystem encryption | LUKS, dm-crypt, BitLocker, FileVault, fscrypt |
| 9. Hardware trust | TPM, Secure Boot, HSM and CPU acceleration |
| 10. Randomness | CSPRNG configuration, entropy interfaces and health indicators |
| 11. Runtime cryptographic activity | Approved observations of cryptographic operations |
| 12. OS lifecycle and drift | Patches, configuration changes, provider changes and deprecations |

The key design principle: every finding should have an observation source, collection time, scope, evidence reference and confidence classification.

## 2. Linux kernel-level intelligence

Linux should be the first operating-system implementation because it is practical to develop and test on your Parrot OS environment, and it gives us a strong foundation for enterprise Linux deployments.

### 2.1 Linux kernel identity and configuration

CryptoScan should discover:

| Attribute | Example |
|---|---|
| Distribution | Ubuntu, RHEL, Debian, SUSE, Parrot |
| Distribution version | Exact release and build |
| Kernel version | Running kernel release |
| Kernel architecture | x86_64, ARM64 |
| Kernel build | Build ID and available build metadata |
| Kernel configuration | Enabled crypto and security options |
| Kernel command line | Boot configuration |
| Kernel taint state | Whether kernel has recorded taint indicators |
| Module signature enforcement | Configuration and runtime state |
| Secure Boot | Firmware and OS-reported state |
| FIPS configuration | Mode and relevant provider configuration |

Possible read-only collection sources: `uname -a`, `uname -r`, `uname -m`, `cat /etc/os-release`, `cat /proc/cmdline`, `cat /proc/sys/kernel/tainted`. Kernel configuration may be available through `cat /proc/config.gz` or `cat /boot/config-$(uname -r)`.

Not every distribution exposes these sources. CryptoScan must record unavailable information rather than treating it as disabled.

Why this matters: two servers can run the same application and cryptographic library but have different kernel capabilities, security configurations, hardware acceleration and patch levels.

### 2.2 Linux Kernel Crypto API

This should be one of the central parts of the Linux collector.

The Linux Kernel Crypto API provides cryptographic transformations to kernel consumers. Its documented categories include symmetric encryption, AEAD, hashing, keyed hashing, random generation, asymmetric cryptography, signatures and key-agreement primitives.

A key inspection source is `cat /proc/crypto`. This can expose registered kernel crypto implementations. For example, a system may expose entries corresponding to:

```
name         : aes
driver       : aesni_intel
priority     : ...
type         : ...
```

Or:

```
name         : sha256
driver       : sha256_generic
```

These are illustrative examples, not guaranteed output from every kernel.

CryptoScan should extract:
- Algorithm name.
- Driver name.
- Algorithm type.
- Implementation priority.
- Block size.
- Digest size.
- Key-size range.
- Self-test state, where exposed.
- Module or built-in implementation association.
- Hardware-accelerated or generic implementation indicators.
- Collection timestamp.
- Kernel version and configuration context.

The distinction between the generic algorithm name and implementation driver is particularly important.

```
aes
 ├── aes_generic
 ├── aesni_intel
 └── another architecture-specific implementation
```

This is not necessarily three different algorithms. They may be different implementations of the same algorithm selected according to kernel capabilities and priorities.

**Important limitation: /proc/crypto is an inventory of registered implementations, not proof that every listed algorithm is actively being used. A separate observation source is required to establish runtime use.**

### 2.3 Kernel crypto configuration and module analysis

CryptoScan should examine kernel configuration flags, including categories such as CONFIG_CRYPTO, CONFIG_CRYPTO_AES, CONFIG_CRYPTO_SHA256, CONFIG_CRYPTO_GCM, CONFIG_CRYPTO_CHACHA20, CONFIG_CRYPTO_POLY1305, CONFIG_CRYPTO_USER_API, CONFIG_CRYPTO_DEV_*. This is an illustrative subset; the actual configuration names and available algorithms vary with kernel version.

Inspect loaded modules: `lsmod`, `cat /proc/modules`. Inspect module information: `modinfo <module_name>`.

The collector should identify:
- Loaded cryptographic modules.
- Built-in versus dynamically loaded implementations, where determinable.
- Module version.
- Module signer.
- Dependencies.
- Module load state.
- Signature enforcement state.
- Known vulnerability associations.
- Changes since the previous collection.

Potential modules include architecture-specific AES implementations, cryptographic hash implementations and hardware crypto drivers.

**Do not assume that a missing entry in lsmod means a cryptographic feature is unavailable. It may be built into the kernel.**

### 2.4 Kernel crypto interfaces

CryptoScan should inventory how applications and kernel consumers can access cryptographic functionality. One example is the Linux AF_ALG interface.

However, there is an important current security consideration: Linux kernel documentation now describes AF_ALG as deprecated and insecure, with restrictions introduced in Linux 7.3. The documentation recommends assessing whether it is needed and restricting or disabling it when it is not required.

Therefore, CryptoScan should:
1. Detect whether the interface is configured.
2. Read its restriction setting where supported.
3. Identify authorized applications that depend on it, where evidence is available.
4. Evaluate exposure and compatibility.
5. Produce a recommendation based on the actual kernel version and use case.

It should not blindly recommend disabling it on every bank server.

### 2.5 Kernel TLS and network cryptography

The Linux networking stack can participate in cryptographic operations through facilities like Kernel TLS and IPsec.

We should inspect: Kernel TLS support and configuration; TLS offload capabilities, where available; IPsec XFRM state and policies; VPN implementation and configuration; Crypto modules associated with networking; Negotiated protocol and cipher information from approved telemetry; Kernel and userspace ownership of cryptographic operations.

Useful read-only collection commands include `ip xfrm state`, `ip xfrm policy`, `ss -tulpen`. These provide different pieces of evidence. They do not independently establish the complete cryptographic configuration of a TLS connection. For example, `ss` can show sockets and process associations, but not automatically reveal the negotiated TLS cipher. CryptoScan must correlate network observations with TLS-specific telemetry or authorized application instrumentation.

### 2.6 Linux disk and filesystem encryption

This is especially important for banking infrastructure. Inspect: LUKS volumes; dm-crypt mappings; Filesystem encryption; Encrypted swap; Encryption configuration; Key-management method; Hardware-backed unlocking where supported.

Possible collection sources: `lsblk -f`, `findmnt`, `dmsetup ls --tree`, `cryptsetup status <mapping_name>`.

For LUKS, collect metadata such as: LUKS version; Cipher and mode; Hash and KDF metadata; Keyslot count and state; Sector size; Device relationship; Header backup status, if available through approved metadata.

**Do not extract passphrases, volume keys or keyslot secret material.**

A volume being mounted and accessible does not mean its encryption configuration has been independently verified. CryptoScan should distinguish configured, observed and validated states.

### 2.7 Linux random-number generation

Randomness is foundational to cryptography. Inspect: Kernel random subsystem configuration; Available RNG interfaces; getrandom() usage indicators where observed; Hardware RNG devices; virtio_rng in virtualized environments; Approved entropy services; RNG-related kernel modules; Relevant system health and error indicators.

Possible sources include `cat /proc/sys/kernel/random/uuid`, `ls -l /dev/random /dev/urandom`, `lsmod | grep -Ei 'rng|random'`. These are inventory examples, not a sufficient RNG quality test.

**Do not declare a system's randomness secure or insecure from one entropy counter.** We need kernel version, configuration, source information, health evidence and the actual cryptographic module context.

### 2.8 Linux TPM and hardware crypto interfaces

Inspect: TPM 2.0 presence; TPM driver and device interface; TPM firmware version; TPM properties and capabilities; Secure Boot measurements, where available; HSM device drivers; PKCS#11 interfaces; Hardware crypto accelerator drivers; CPU crypto instruction capabilities.

Possible read-only sources: `ls -l /dev/tpm*`, `lscpu`. Where supported and authorized: `tpm2_getcap properties-fixed`, `tpm2_getcap algorithms`.

For a bank HSM, CryptoScan should normally collect metadata through approved vendor interfaces and the bank's authorized integration — not attempt to access or extract protected key material.

## 3. Linux runtime kernel observation

Static kernel inspection tells us what is available. Runtime observation helps determine what happens while the system operates. This should be an optional, tightly controlled collection mode.

### Three levels of runtime monitoring

| Level | Method | Risk and purpose |
|---|---|---|
| Level 1 | Existing OS logs, counters and interfaces | Lowest operational impact |
| Level 2 | Approved tracepoints and eBPF telemetry | Targeted runtime visibility |
| Level 3 | Kprobes, kretprobes or deeper instrumentation | Advanced, higher operational risk |

Linux provides tracing frameworks including tracepoints, ftrace, kprobes and related mechanisms. For ZELNX, I would prioritize supported tracepoints and carefully scoped eBPF programs.

However, do not assume that every tracepoint or kernel internal interface is stable across versions. Linux documentation explicitly warns that tracepoints can change, and some BPF tracing programs that depend on internal structures require adaptation across kernel versions.

### What should runtime observation collect?

Example:

```
event_id
host_id
boot_id
process_id
process_start_time
executable_digest
operation_category
algorithm_identifier
provider_identifier
kernel_or_userspace
interface
timestamp
evidence_source
collection_profile
```

Potential event categories: Cryptographic API allocation; Algorithm selection; Key-generation request; Encryption/decryption operation category; Hash operation category; Signature generation/verification; Kernel TLS state transition; IPsec policy change; Crypto module load/unload; TPM or HSM provider activity. The precise operations observable depend on the instrumentation point and OS implementation.

### What must never be collected?

- Plaintext.
- Private keys.
- Encryption keys.
- Passwords.
- Tokens.
- Decrypted application data.
- TLS session secrets.
- HSM key material.
- Full cryptographic input/output buffers.

The runtime engine should produce metadata events, not capture cryptographic payloads.

### Recommended implementation

```
ZELNX Linux Runtime Collector
  Approved kernel tracepoints / eBPF programs
    ↓
  Bounded event filter
    (Process identity · Event category · Allowlisted fields)
    ↓
  Local event normalizer
    (Schema validation · Deduplication · Timestamping)
    ↓
  Evidence store + CryptoLog
    (Hash-linked event metadata and collection provenance)
```

I would not build a custom Linux kernel module for the first version. Prefer existing read-only interfaces and a narrowly scoped eBPF collector where the required events are actually available.

## 4. Windows kernel and OS intelligence

After Linux, Windows should be the second major OS implementation. Many financial institutions have Windows Server systems, Active Directory infrastructure, certificate services, application servers and hardware-backed security facilities.

Windows has a different cryptographic architecture. We should not attempt to force Linux-specific collection logic onto it.

### 4.1 Windows cryptographic architecture

Important Windows interfaces include: CNG (modern cryptographic API architecture); BCrypt (cryptographic primitive interfaces); NCrypt (key storage and key-management interfaces); Schannel (Windows TLS/SSL security provider); CryptoAPI (legacy cryptographic interfaces); CSP (legacy cryptographic service providers); KSP (key storage providers); CNG kernel-mode interfaces; Windows certificate stores.

Microsoft recommends CNG for new development, while CryptoAPI remains for backward compatibility. CryptoScan should detect both modern and legacy interfaces. Legacy presence is not automatically a vulnerability, but it can identify migration and compatibility concerns.

### 4.2 Windows kernel and driver analysis

Collect: Windows version and build; Kernel version and architecture; Loaded kernel drivers; Driver signer and signature status; Driver version; Driver file hash; Code Integrity status; Secure Boot status; VBS and HVCI configuration, where available; Relevant cryptographic provider drivers; TPM state; Hardware-backed key provider availability.

Windows kernel Code Integrity helps ensure that loaded kernel drivers meet signing requirements. This makes driver signature and integrity state important parts of OS-level intelligence.

Example PowerShell collection commands: Get-ComputerInfo (WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture); Get-CimInstance Win32_OperatingSystem; Get-CimInstance Win32_SystemDriver (Name, State, StartMode, PathName); Confirm-SecureBootUEFI; Get-Tpm.

Some commands require elevated permissions or specific hardware and firmware support. **A failed command must be reported as unavailable or permission-denied, not as proof that a feature is absent.**

### 4.3 Windows cryptographic provider inventory

CryptoScan should enumerate: CNG algorithm providers; Key storage providers; Legacy CSP providers; Cryptographic algorithms available through the providers; Provider version and registration; Certificate store metadata; Hardware-backed provider indicators; Relevant policy settings.

We should correlate the provider inventory with actual application dependencies and runtime observations. **A provider being installed does not prove that any banking application is using it.**

### 4.4 Windows certificate and key-store analysis

Inspect: Local machine certificate stores; Current user certificate stores, where authorized; Root and intermediate CA certificates; Certificate expiration; Signature algorithms; Public-key algorithms and sizes; Certificate EKUs and key usage; Provider associations; Hardware-backed key indicators, where exposed. (Get-ChildItem Cert:\LocalMachine\My / Root / CA.)

For the production collector, normalize certificate metadata and fingerprints. **Avoid exporting private keys or secret key containers.**

### 4.5 Windows TLS and protocol intelligence

Inspect: Schannel configuration; TLS protocol configuration; Cipher suite policies; Certificate bindings; IIS TLS configuration, where installed; RDP security configuration; IPsec policies; VPN configuration; Relevant Windows cryptographic policy settings.

We should distinguish: Protocol supported by the OS; Protocol enabled by configuration; Protocol actually negotiated in an observed connection. **Those are three different findings.**

### 4.6 Windows runtime event intelligence

Use ETW where suitable. ETW supports providers, sessions, controllers and consumers, including providers implemented in user mode, kernel mode or the Windows kernel.

CryptoScan should: 1. Identify available providers. 2. Determine which events they actually expose. 3. Enable only an approved set. 4. Record event loss and collection gaps. 5. Normalize metadata. 6. Correlate events to process and binary identity. 7. Avoid collecting secrets or sensitive payloads.

ETW should not be represented as a universal feed of every cryptographic operation. The event coverage depends on the particular providers and instrumentation.

## 5. macOS kernel and OS intelligence

macOS is a third platform to support, especially for developer workstations, enterprise endpoints and build infrastructure.

### 5.1 macOS cryptographic facilities

Components: CommonCrypto; CryptoKit; Security framework; Keychain; Secure Enclave; FileVault; Apple Platform Security; Kernel/system extensions.

The collector should identify the OS version, CPU architecture, available cryptographic facilities, key-store configuration, disk encryption status and security boot state where supported. Example commands: `sw_vers`, `uname -a`, `uname -m`, `fdesetup status`, `system_profiler SPHardwareDataType`.

Certificate and trust-store inspection should use the supported Security framework and Keychain interfaces rather than scraping protected storage files.

### 5.2 Kernel and runtime visibility

macOS kernel and endpoint instrumentation differs from Linux. CryptoScan should prefer supported system APIs, approved endpoint security telemetry and OS configuration sources. It should not depend on unsupported kernel extensions or assume Linux-style eBPF visibility.

For the initial macOS release, prioritize inventory and configuration analysis. Add deeper runtime cryptographic observation only after validating the permitted APIs and available event coverage for supported macOS versions.

## 6. The OS-level intelligence matrix

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| OS and kernel inventory | Priority 1 | Priority 2 | Priority 3 |
| Kernel crypto inventory | Kernel Crypto API | CNG/kernel interfaces | OS API inventory |
| Crypto modules/providers | Kernel modules | CNG, CSP, KSP and drivers | Frameworks and providers |
| TLS and network | OpenSSL, GnuTLS, kTLS, IPsec | Schannel, IPsec | Security framework, system services |
| Disk encryption | LUKS, dm-crypt, fscrypt | BitLocker | FileVault |
| Hardware trust | TPM, HSM | TPM, HSM | Secure Enclave, hardware-backed keys |
| Runtime telemetry | eBPF, tracepoints | ETW and approved instrumentation | Supported endpoint telemetry |
| Secure boot | UEFI/Secure Boot | UEFI/Secure Boot, Code Integrity | Platform security and boot integrity |
| PQC intelligence | Kernel/library/config inventory | CNG/provider inventory | Framework/library inventory |

These are implementation targets. They do not mean every listed feature is available on every OS release or device.

## 7. How the OS collector should work

One shared OS intelligence architecture with separate operating-system adapters:

```
Cross-platform OS Intelligence Engine
  OS Collection Orchestrator
    (Authorization · Host identity · Collection profile · Scheduling)
       |            |             |
    Linux        Windows        macOS
  procfs/       CNG/PowerShell/ Security/Keychain/
  sysfs/kernel  ETW/CIM        system APIs
  APIs/eBPF
       \            |             /
  Shared Normalization Engine
    (Common host model · Algorithm model · Provider model · Evidence model)
       ↓
  Evidence and Relationship Engine
    (Provenance · Confidence · Coverage · Change history)
       ↓
  CryptoScan Platform
    (BOMs · Digital Twin · CryptoLog · PQC · Threat intelligence)
```

Two operating modes:

**Mode A — Snapshot inventory**: Collect configuration and installed capabilities; Read kernel and OS metadata; Enumerate providers and modules; Inspect certificate metadata; Report disk encryption and hardware trust state; Produce a signed or hash-verifiable collection package.

**Mode B — Continuous monitoring**: Watch selected configuration changes; Detect module/provider changes; Record OS crypto-related events where supported; Detect certificate and policy drift; Monitor collection health; Send metadata to the local bank deployment. Mode B should have explicit event filters, retention settings, sampling and backpressure controls.

## 8. How this connects to the six BOMs

Kernel and OS analysis should enrich your existing six BOMs rather than introduce another disconnected inventory.

| BOM | OS and kernel contribution |
|---|---|
| SBOM | OS packages, installed libraries, kernel packages, drivers and components |
| CBOM | Kernel algorithms, OS crypto providers, cryptographic capabilities, certificates and operation evidence |
| HBOM | CPU crypto acceleration, TPM, HSM, firmware, drivers and hardware associations |
| NBOM | TLS, SSH, IPsec, VPN and OS networking cryptography |
| VBOM | OS vendor, kernel supplier, crypto provider vendor, driver and firmware suppliers |
| TechBOM | Host, operating system, kernel, applications, hardware, providers and dependency relationships |

Example: one Linux bank server:

```
BANK-PAYMENTS-SERVER-01
    |
    +-- Ubuntu Server
    |
    +-- Linux Kernel
    |      |
    |      +-- Kernel Crypto API
    |      +-- AES implementation
    |      +-- SHA-256 implementation
    |      +-- IPsec support
    |
    +-- OpenSSL
    |
    +-- payments-engine
    |
    +-- LUKS encrypted storage
    |
    +-- TPM 2.0
    |
    +-- Network TLS configuration
```

CryptoScan should be able to answer:
1. Which cryptographic implementations are available in the kernel?
2. Which cryptographic libraries are installed?
3. Which applications depend on those libraries?
4. Is disk encryption configured?
5. What algorithms and providers are exposed?
6. Is hardware-backed security available?
7. Which protocols and cryptographic configurations are enabled?
8. What changes have occurred since the previous scan?
9. Which findings are actually supported by runtime evidence?
10. Which systems may need PQC migration?

**But the platform must not infer that payments-engine uses the kernel AES implementation just because both exist on the same host. It needs an actual relationship supported by evidence.**

## 9. Advanced risk and threat intelligence rules

This is where the OS engine becomes more than an inventory collector. A dedicated rule catalogue:

| Rule ID | Detection | Potential impact |
|---|---|---|
| OS-CRYPTO-001 | Weak cryptographic implementation exposed | Legacy cryptographic risk |
| OS-CRYPTO-002 | Deprecated cryptographic interface enabled | Increased attack surface |
| OS-CRYPTO-003 | Unexpected crypto module loaded | Possible configuration drift |
| OS-CRYPTO-004 | Untrusted or unexpected driver signature | Kernel integrity concern |
| OS-CRYPTO-005 | Legacy provider detected | Migration assessment |
| OS-CRYPTO-006 | TLS configuration allows weak protocols | Network cryptographic exposure |
| OS-CRYPTO-007 | Disk encryption not established | Data-at-rest protection gap |
| OS-CRYPTO-008 | Certificate near expiration | Service availability risk |
| OS-CRYPTO-009 | TPM unavailable or misconfigured | Hardware trust concern |
| OS-CRYPTO-010 | Secure Boot disabled | Boot integrity concern |
| OS-CRYPTO-011 | Crypto provider version vulnerable | Potential software risk |
| OS-CRYPTO-012 | Cryptographic configuration changed | Drift investigation |
| OS-CRYPTO-013 | Unexpected kernel module signer | Integrity investigation |
| OS-CRYPTO-014 | Randomness configuration concern | Cryptographic assurance concern |
| OS-CRYPTO-015 | PQC migration dependency identified | Migration planning requirement |
| OS-CRYPTO-016 | Kernel crypto capability unavailable | Compatibility or dependency concern |
| OS-CRYPTO-017 | Runtime collector losing events | Observability gap |
| OS-CRYPTO-018 | HSM or TPM provider state changed | Hardware trust investigation |

These are proposed detection rules, not automatic vulnerability verdicts.

Example: weak TLS configuration. Suppose a Linux server has a configuration that permits TLS 1.0. CryptoScan should not merely show "TLS 1.0 detected / CRITICAL". Instead, it should establish:

```
Finding: Legacy TLS protocol permitted

Host: BANK-PAYMENTS-SERVER-01

Evidence source:
    OS configuration

Configured protocol:
    TLS 1.0

Observed runtime negotiation:
    Not established

Affected service:
    Requires correlation

Business system:
    Requires registered mapping

Risk:
    Legacy protocol exposure

Recommendation:
    Review application compatibility,
    approved protocol policy and client dependencies.
```

This is a much more defensible result for a bank auditor.

### Risk calculation

Use a multi-factor model: R = f(S,E,X,B,C) where S: security significance; E: evidence confidence; X: actual exposure; B: business impact; C: compensating controls.

**Do not simply multiply arbitrary numbers and present the result as a scientifically validated risk score.** Version the risk model and preserve the underlying factors so a bank can review the decision.

## 10. Database and evidence architecture

The OS Intelligence Engine needs a shared host model and normalized evidence. Introduce or extend:

| Entity | Purpose |
|---|---|
| os_assets | Host identity and operating-system metadata |
| os_scan_runs | Snapshot and monitoring collection runs |
| os_kernel_inventory | Kernel version, architecture and configuration |
| os_crypto_capabilities | Available algorithms and implementations |
| os_crypto_providers | Libraries, providers and kernel interfaces |
| os_kernel_modules | Kernel modules and driver metadata |
| os_certificates | Certificate metadata and fingerprints |
| os_storage_encryption | Disk and filesystem encryption state |
| os_hardware_trust | TPM, HSM and hardware trust metadata |
| os_network_crypto | TLS, SSH, IPsec and VPN metadata |
| os_runtime_events | Approved runtime metadata events |
| os_findings | Normalized risk and configuration findings |
| os_evidence | Evidence references, hashes and provenance |
| os_coverage | Collection completeness and unavailable data |

Reuse existing tenant_id, asset_id, evidence_id, audit and scan-job structures wherever possible.

Example evidence record:

```json
{
  "finding_type": "kernel_crypto_capability",
  "host_id": "host-001",
  "kernel_version": "observed-version",
  "algorithm": "AES",
  "implementation": "observed-driver",
  "evidence_source": "/proc/crypto",
  "observation_type": "registered_capability",
  "runtime_usage_confirmed": false,
  "confidence": "high",
  "collection_timestamp": "timestamp",
  "collector_version": "version",
  "evidence_digest": "sha256-value"
}
```

The important field is `runtime_usage_confirmed: false`. The finding says that the kernel exposes the implementation. It does not claim that a bank application used it.

### Evidence integrity

For every collection: 1. Capture the original metadata. 2. Normalize it into a canonical schema. 3. Record the collector and version. 4. Hash the evidence artifact. 5. Link the artifact to the host and scan run. 6. Record collection permissions and limitations. 7. Sign or checkpoint the collection manifest using the bank-approved signing architecture. 8. Preserve subsequent corrections as separate records.

This integrates naturally with your existing evidence integrity and CryptoLog design.

## 11. On-premises security architecture

For banks, I would not install a privileged always-running agent by default. Use a two-tier design:

**Tier 1 — Read-only inventory collector (default mode)**: Runs with the minimum privileges required; Reads supported OS interfaces; Collects configuration and metadata; Does not modify kernel settings; Does not install kernel modules; Does not execute uploaded artifacts; Sends evidence to the bank's local CryptoScan server.

**Tier 2 — Approved runtime collector (optional advanced mode)**: Uses narrowly scoped, approved instrumentation; Requires explicit authorization; Has bounded event collection; Has CPU, memory and event-loss monitoring; Supports immediate disablement; Does not collect cryptographic secrets or plaintext; Records all collector changes and configuration.

Additional controls: Signed collector packages; Version-pinned dependencies; Bank-controlled installation; No external telemetry; Local retention and encryption; Role-based access control; Immutable audit history; Customer-controlled removal; Signed update verification; No permanent remote support backdoor.

**A bank must be able to disable runtime collection without losing its static inventory capability.**

## 12. Testing and qualification

Linux qualification matrix: Kernel identification (multiple LTS and supported kernel versions); Crypto API (generic and hardware-specific implementations); Module inventory (built-in, loaded, unloaded and unavailable modules); Disk encryption (LUKS1, LUKS2, unencrypted volumes); Networking (TLS, IPsec and VPN configurations); Randomness (supported CSPRNG and RNG configurations); TPM (available, unavailable and permission denied); Secure Boot (enabled, disabled and unsupported); Runtime collection (events, loss, restarts and disabled mode); Permissions (root, restricted user and missing capabilities); Resilience (kernel upgrades, reboot and collector crash).

Windows qualification matrix: Supported Windows Server versions; CNG and legacy CryptoAPI providers; Certificate stores; Schannel configurations; BitLocker; TPM; Driver signing; Code Integrity; ETW collection and event loss; Privilege restrictions.

macOS qualification matrix: Supported macOS releases; FileVault; Keychain metadata access; Security framework; Secure Enclave availability; Hardware and architecture identification; System extension and endpoint telemetry restrictions.

Quality measurements: Measure separately: Inventory completeness; Configuration detection accuracy; Finding precision and recall; Runtime event loss; Collector overhead; Unsupported configuration rate; False-positive rate; Evidence integrity verification; Recovery after reboot; Cross-version compatibility.

**A successful collection on your Parrot laptop is not sufficient qualification for an enterprise Linux fleet.**

## 13. Recommended engineering roadmap

1. **Phase 1 — Linux OS inventory** (build first): OS and kernel identity; Kernel configuration; /proc/crypto parser; Kernel modules and driver inventory; OS cryptographic libraries; Certificate metadata; Disk encryption metadata; TPM and Secure Boot state; Evidence and coverage reporting. Deliverable: Linux OS Cryptographic Inventory.
2. **Phase 2 — Linux security intelligence**: Crypto API capability normalization; IPsec and TLS configuration; Randomness inventory; Legacy interface detection; Configuration policy engine; Historical drift; Risk and evidence reports. Deliverable: Linux Cryptographic Posture Assessment.
3. **Phase 3 — Linux runtime intelligence**: Approved tracepoint discovery; eBPF compatibility layer; Process and binary identity correlation; Bounded metadata events; CryptoLog integration; Event-loss and performance monitoring. Deliverable: Linux Runtime Crypto Intelligence.
4. **Phase 4 — Windows OS intelligence**: CNG, CSP and KSP inventory; Schannel; Certificate stores; BitLocker and TPM; Driver integrity; Secure Boot and Code Integrity; ETW integration. Deliverable: Windows Cryptographic Posture Assessment.
5. **Phase 5 — macOS intelligence**: Security framework and Keychain metadata; FileVault; Secure Enclave indicators; OS and architecture inventory; Supported endpoint telemetry. Deliverable: macOS Cryptographic Posture Assessment.
6. **Phase 6 — Enterprise intelligence correlation**: Six-BOM integration; Digital Twin relationships; Binary-to-OS-to-hardware mapping; PQC migration impact; Cross-host drift; Fleet-level reporting; Production qualification. Deliverable: Cross-Platform OS & Kernel Intelligence.

## 14. How this changes the overall CryptoScan product

```
ZELNX CryptoScan — Intelligence architecture

  Source intelligence     (Source code and dependencies)
  Binary intelligence     (Executables and firmware)
  OS & kernel intelligence (Providers, kernel, runtime)
  Network intelligence    (TLS, SSH, VPN, IPsec)
  Hardware intelligence   (HSM, TPM, firmware)
  Vendor intelligence     (Products and suppliers)
           ↓
  Shared Evidence and Relationship Engine
    (Provenance · Integrity · Confidence · Dependencies · History)
           ↓
  Enterprise Cryptographic Intelligence
    (Six BOMs · Digital Twin · CryptoLog · PQC · Performance · Governance)
```

Product distinction: Binary intelligence examines compiled implementations. OS intelligence examines operating-system capabilities and configurations. Kernel intelligence examines kernel cryptographic facilities and approved runtime behavior. Network intelligence examines protocol and connection evidence. Hardware intelligence examines hardware-backed cryptographic capabilities. Together, they provide a much stronger view than any one scanner can provide.

## 15. My recommendation: what to build next in your repository

Do not immediately start creating all the proposed modules. Your current repository already has scanning, BOM, evidence and Digital Twin architecture. We should first establish the exact overlap and gaps.

Implementation sequence:
1. Audit existing OS discovery, hardware discovery, network discovery and binary scanning.
2. Identify any existing kernel or OS crypto collectors.
3. Map current findings to the shared evidence model.
4. Define one canonical OSAsset and KernelCryptoCapability model.
5. Implement Linux read-only collection first.
6. Integrate with existing SBOM, CBOM, HBOM and TechBOM.
7. Test against actual local Linux configuration.
8. Only then add runtime eBPF instrumentation.
9. Add Windows and macOS adapters after the shared model is validated.

## Primary technical references

- Linux Kernel Crypto API documentation
- Linux Kernel Crypto API architecture
- Linux AF_ALG interface and deprecation
- Linux kernel tracing technologies
- Linux BPF design and compatibility
- Microsoft Windows Cryptography architecture
- Microsoft ETW architecture

The product goal: CryptoScan should eventually be able to tell a bank not just which cryptographic algorithms exist in its applications, but which are available in the operating system, which providers and hardware support them, which are configured, which are observed in operation, what evidence establishes those facts, and what could be affected by a cryptographic migration. That is the level of intelligence I would target for ZELNX.
