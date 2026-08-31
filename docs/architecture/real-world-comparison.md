# CryptoScan vs. the real world — honest competitive comparison

*Scope of this document:* a factual, honest comparison of CryptoScan against
real products and open-source tools in each area it touches. It follows the
platform's own rule — [platform boundaries](platform-boundaries.md): claim
only what ships, and name gaps honestly.

> **Related:** [bank-vs-zelnx.md](bank-vs-zelnx.md) compares the product
> against what a *real bank actually runs* (its vendor estate, processes and
> regulatory asks) rather than against competitor products.

Sources are linked inline; key claims reflect publicly available vendor
material as of 2026-08.

---

## 1. The landscape — who does what

CryptoScan sits in a category that is **emerging, not mature**: "cryptographic
inventory / crypto posture management". The closest real-world products are
**SandboxAQ Cryptosense** (acquired 2022), **Keyfactor** (PQC discovery via
InfoSec Global), and the **CycloneDX CBOM** standard itself (v1.6, Apr 2024;
v1.7, Oct 2025; ratified as ECMA-424, Dec 2025). Most adjacent tools are
*single-domain*: TLS scanners, CSPM tools, container scanners, OT platforms,
CLM platforms.

| Product | Category | Crypto inventory in source | Cert/key lifecycle | Network TLS | Cloud | Containers | OT | HSM | PQC | CBOM out |
|---|---|---|---|---|---|---|---|---|---|---|
| **CryptoScan (this repo)** | Crypto inventory + posture platform | ✅ 10+ languages, deterministic | ⚠️ inventory + expiry only | ✅ passive | ✅ read-only tenants | ✅ layers/jars/libs | ✅ passive, zero packets | ✅ TR-31, PAY rules | ✅ evidence-supported | ✅ CycloneDX 1.7 |
| **Venafi (CyberArk)** [1][4] | Machine identity / CLM | ❌ no | ✅ deep (200+ sources, automation) | ⚠️ certificate-centric | ⚠️ module-based | ⚠️ partial | ❌ | ⚠️ key-protection focus | 🔶 in development | 🔶 import |
| **Keyfactor** [2][5] | CLM + PKI (EJBCA) | ❌ no | ✅ deep (CA-agnostic, ACME/SCEP/EST/CMP) | ⚠️ certificate-centric | ✅ cloud inventory | 🔶 | ❌ | 🔶 | ✅ (InfoSec Global) | 🔶 |
| **SandboxAQ Cryptosense** [3][6] | Crypto inventory + PQC | ✅ app traces (Java/OpenSSL/PKCS#11) | 🔶 | ✅ network analyzer | 🔶 | ✅ filesystem scans | ❌ | ✅ key-store/HSM visibility | ✅ flagship | 🔶 |
| **SCANOSS Crypto Finder** [7] | Source-level crypto visibility (OSS) | ✅ emits CycloneDX CBOM | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 🔶 (via CBOM) | ✅ |
| **Prowler** [8][9] | CSPM (OSS) | ❌ | ❌ | 🔶 | ✅ 600+ checks, 44 frameworks | 🔶 | ❌ | ❌ | ❌ | ❌ |
| **Trivy** [9] | Container/cloud vuln + SBOM | ❌ | ❌ | ❌ | 🔶 | ✅ SBOM + CVEs | ❌ | ❌ | ❌ | SBOM yes |
| **testssl.sh / SSLyze / CryptoLyzer** [10][11] | TLS posture scanners | ❌ | ❌ | ✅ deepest single-host | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Nozomi Networks / Claroty** [12] | OT security platforms | ❌ | ❌ | 🔶 | ❌ | ❌ | ✅ full OT (DPI, anomaly, threat) | ❌ | ❌ | ❌ |
| **Semgrep / SonarQube / Checkmarx** | General SAST | ⚠️ crypto rules are a small subset | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

Legend: ✅ = real capability · ⚠️ = partial / adjacent · 🔶 = limited / roadmap · ❌ = not provided

---

## 2. Head-to-head with the closest analogs

### 2.1 vs. SandboxAQ Cryptosense (the most direct real-world comparison)

Cryptosense (Paris, founded 2013, acquired by SandboxAQ in 2022 [6]) is the
product banks have actually bought for "crypto cartography": it traces crypto
library calls in applications (Java JCE/JCA/BouncyCastle, OpenSSL, PKCS#11,
.NET in development), scores against NIST/ENISA profiles with 45+ configurable
rules, and now pairs with the SandboxAQ Network Analyzer for the "first
complete crypto inventory of filesystems, applications and networks" [3][5].

| Dimension | SandboxAQ Cryptosense | CryptoScan |
|---|---|---|
| Source inventory | Agentless file scans + **runtime application traces** (dynamic) | Agentless static scan across 10+ languages (no runtime tracing) |
| Depth per finding | Tracer-level call graphs, false-positive rate <1/1000 claimed [5] | Deterministic static detection with confidence stamps |
| Network | Network Analyzer (full stack) | Passive TLS + cert posture |
| Evidence chain | Reports/maps | **Hash-chained evidence, tamper-evident packs/transfers (unique)** |
| Policy | 45+ configurable rules, NIST/ENISA profiles [5] | Versioned YAML, deterministic, no AI |
| HSM | Key-store/HSM visibility (PQC defense) [6] | TR-31 parsing, ceremony provenance, PAY policy — **metadata only** |
| Pricing | SaaS/on-prem, ~$595–$1,495/mo per app (2021 public data) [5] | Self-hosted OSS |
| Key material | Scans/traces key stores (visibility) | **Never touches key material — enforced by tests** |

**Honest verdict:** Cryptosense has deeper per-application analysis (runtime
traces) and years of bank-proven detection. CryptoScan is broader
(containers, cloud tenants, OT, HSM, vendor/supply-chain in one repo), fully
self-hosted, and has an evidence chain + metadata-only guarantee that no
commercial tool advertises — a compliance story, not a detection story.

### 2.2 vs. SCANOSS Crypto Finder (the open-source analog)

Crypto Finder is the closest OSS to CryptoScan's source-tree piece: it emits
structured findings (file, line range, algorithm, mode, padding, key size)
and **exports CycloneDX CBOM as a first-class outcome** for CI/CD [7].

- **Both:** source-level crypto visibility, CycloneDX CBOM output, policy-friendly.
- **Crypto Finder:** single-purpose source scanner; language/rule breadth is
  its own; no estate layer.
- **CryptoScan:** full pipeline beyond detection — evidence chain, policy,
  drift/gates, graph, agility/PQC scoring, remediation, reporting, live
  monitoring; multi-domain collectors (network/cloud/container/OT/HSM/vendor).

### 2.3 vs. Venafi / Keyfactor (cert lifecycle & machine identity)

These are **not** crypto-inventory products — they manage *certificates and
keys* at scale: discovery across 200+ sources (Venafi), CA-agnostic lifecycle
automation (ACME/SCEP/EST/CMP), PKI (Keyfactor's EJBCA), code signing, SSH [1][2][4].

- **They win on:** production scale (Venafi: 1M+ certificates, FedRAMP,
  200+ integrations [4]), real lifecycle automation (issue/renew/revoke), PKI
  ownership, enterprise support/SLA.
- **CryptoScan wins on:** algorithm-level inventory *inside applications and
  containers* (they don't do this), evidence chain, deterministic policy,
  PQC migration planning with evidence, and the metadata-only stance — Venafi
  *protects private keys* (stores/rotates them); CryptoScan deliberately
  **never sees key material at all**, which is a different compliance posture.

### 2.4 vs. TLS scanners (testssl.sh, SSLyze, CryptoLyzer, SSL Labs)

testssl.sh is the deepest free single-host TLS checker (A–F grade, broad
vulnerability checklist, OpenSSL-dependent); CryptoLyzer adds SSH/IKE/HTTP
headers/DNS and JA3/JA4 fingerprinting [10][11].

- CryptoScan's network piece is a **subset**: passive TLS + certificate
  posture + expiry + DNSSEC/IPsec targets, as *one layer of an estate-wide
  inventory* — not a TLS lab. A TLS team keeps testssl.sh; CryptoScan
  aggregates the results into CBOM/policy/drift alongside everything else.

### 2.5 vs. Prowler / Trivy (cloud & container posture)

Prowler: agentless CSPM, 600+ checks, 44 compliance frameworks across
AWS/Azure/GCP/K8s [8][9]. Trivy: container + cloud SBOM/CVE scanning [9].

- CryptoScan's cloud/container work is **crypto-only** (algorithms, key
  material posture, crypto config in IaC) — it deliberately does not compete
  with their breadth (IAM misconfig, network exposure, CVEs at scale).
- CryptoScan adds what they lack: crypto-normalized CBOM, PQC risk scoring,
  evidence-chained findings, policy/drift over crypto state.

### 2.6 vs. Nozomi Networks / Claroty (OT)

Nozomi (passive DPI via SPAN/TAP sensors + optional protocol-aware "Smart
Polling", AI-enhanced asset intelligence, threat/anomaly detection) and
Claroty are **full OT security platforms** [12].

- CryptoScan's OT module is **passive crypto/asset inventory only, zero
  packets sent** — a deliberate subset. It does not do anomaly detection,
  threat detection, or endpoint sensors. Its value is feeding crypto state
  (protocols, TLS, device crypto) into the same evidence/policy/PQC pipeline
  as the rest of the estate.

---

## 3. What real tools have that CryptoScan does not (honest gaps)

1. **Production-scale discovery & lifecycle automation.** Venafi's 200+
   collectors, CA-agnostic issuance/renewal/revocation, 1M+ certificate
   estates [1][4]. CryptoScan inventories; it does not issue, renew, or
   rotate anything.
2. **Runtime/dynamic analysis.** Cryptosense's application tracing sees
   runtime crypto behavior; CryptoScan is static + passive only.
3. **Enterprise readiness.** FedRAMP/ISO certifications, SLAs, sales support,
   managed PKI (Keyfactor), cloud SaaS hosting — none of this exists here.
4. **Full OT security.** DPI sensors, anomaly/threat detection, endpoint
   sensors (Nozomi Arc), smart polling [12].
5. **General CSPM/container vuln breadth.** Prowler's 600+ checks and 44
   frameworks, Trivy's CVE feed at scale [8][9].
6. **Deep single-host TLS lab** (testssl.sh-class exhaustive checks, JA3/JA4) [10][11].
7. **AI/ML-assisted analysis** — deliberately absent by design (deterministic
   policy is an invariant), but vendors like Nozomi and SandboxAQ use it.

## 4. What CryptoScan has that the real world mostly does not

1. **Evidence-chained findings.** Every finding has content/chain hashes;
   packs and cross-instance transfers are digest-verified and tamper-evident.
   No commercial tool in this space advertises this.
2. **"Key metadata only, never key material" — enforced.** A tested invariant
   (fake secrets planted in source records provably never leak into evidence
   packs). This is the compliance-friendly property banks need and is the
   platform's strongest differentiator.
3. **Deterministic, versioned, no-AI policy** across 25+ rule sets
   (NIST/FIPS/NSA/PCI-DSS/HIPAA/ISO/PAY), evaluated with zero ML.
4. **One pipeline, many domains.** Source + network + containers + cloud
   tenants + OT + HSM + vendor/supply-chain normalize into one CBOM graph
   with drift, PQC scoring, remediation and live monitoring — no
   multi-vendor stitching.
5. **CycloneDX CBOM 1.7 native output** aligned to the ECMA-424 standard and
   the regulatory push (NSA/CISA guidance, NIST SP 800-131A, PCI DSS 4.0,
   EU CRA) [13][14].
6. **Self-hosted OSS with 2,294 tests / 25 services** — auditable end to end.

---

## 5. Bottom line

- **As a product competing for bank production budgets**, CryptoScan is years
  behind Venafi/Keyfactor/SandboxAQ on scale, integrations, lifecycle
  automation, certification and support — that is not close.
- **As a crypto-inventory-and-posture platform**, it is feature-comparable to
  the emerging category (Cryptosense, Crypto Finder) and **unique** on
  evidence chaining, the metadata-only guarantee, deterministic policy, and
  the breadth of domains under one pipeline.
- **Realistic positioning:** the honest, self-hosted, evidence-chained
  *inventory & readiness* layer that feeds (rather than replaces) the
  commercial CLM/OT/CSPM tools — "know your crypto estate, prove it, and
  plan the migration" — with the compliance story (never touches key
  material) as the wedge.

---

## Sources

[1] Venafi (CyberArk) capabilities — devopsschool.com, venafi.com
[2] Keyfactor vs CyberArk/Venafi — keyfactor.com/comparison
[3] SandboxAQ Security Suite / Cryptosense module — sandboxaq.com/press
[4] Enterprise PKI vendor matrix 2026 — axelspire.com
[5] Cryptosense Analyzer pricing & features — getapp.co.uk
[6] SandboxAQ buys Cryptosense — bankinfosecurity.com (2022)
[7] SCANOSS Crypto Finder — scanoss.com/post/crypto-finder
[8] Prowler CSPM — microsoft marketplace / prowler.com
[9] Open-source AWS security CLIs 2026 — haitmg.pl
[10] CryptoLyzer vs SSLyze vs testssl.sh — pfeifferszilard.hu (2026)
[11] Best SSL/TLS testing tools — immuniweb.com (2026)
[12] Nozomi Networks passive vs active OT monitoring — nozominetworks.com
[13] CycloneDX CBOM — encryptionconsulting.com; cyclonedx.org (ECMA-424, Dec 2025)
[14] CBOM deep-dive & regulatory drivers — postquantum.com; safeguard.sh
