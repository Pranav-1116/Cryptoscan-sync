# ZELNX / CryptoScan vs. a real bank — estate-level comparison

*Scope:* not product-vs-product (see [real-world-comparison.md](real-world-comparison.md)
for that), but **product vs. what a real bank actually runs**. We compare the
ZELNX Universal Vendor Scanner + 24/7 Live Vendor Engine + the CryptoScan
platform against the crypto-relevant estate of a realistic mid-to-large
retail/corporate bank, and against what regulators now require banks to do.

The reference bank below is a **composite profile** (typical of Tier-1/2
banks in 2026), not one named institution. Every claim about "the real bank"
is grounded in public sources linked inline; claims about the product are
restricted to what ships in this repository and is covered by tests.

---

## 1. The reference bank (composite profile)

A bank with ~10–20 million retail customers, corporate + payments lines,
operating in 3 regions (UAE, EU, USA). It runs:

- **Card payments** (EMV issuance, PIN processing, tokenization) on
  **Thales payShield HSMs** — the payment HSM family used by most of the
  world's payment processors, PCI HSM / FIPS 140-2/3 certified, with
  MEPS/CB/SAFIRE scheme certifications [1][4][5].
- **Online/API banking** fronted by **F5 BIG-IP** ADCs (TLS termination,
  SSL VPN, ZTNA) behind **Palo Alto / Fortinet / Cisco** NGFWs [5][6].
- **Databases** (Oracle, SQL Server) monitored by **IBM InfoSphere Guardium**
  for database security and compliance reporting [2].
- **SOC** on **Splunk Enterprise Security** and **IBM QRadar** (the SIEMs
  most deployed in banking/finance), with **Exabeam** UEBA, **Cortex XSOAR /
  Splunk SOAR**, and **CrowdStrike / SentinelOne / Microsoft Defender** EDR [1][3].
- **Certificate lifecycle** managed by a **Venafi- or Keyfactor-class CLM**
  (200+ discovery sources, CA-agnostic issue/renew/revoke) [real-world-comparison §2.3].
- **Cloud** (AWS + Azure) with KMS/Key Vault/Managed HSM, plus
  **Akeyless-class secrets management** for just-in-time credentials and
  rotation (SOX / PCI DSS req. 10 audit trails) [3].
- **Mainframe / core banking** (z/OS or AS/400) with its own crypto
  services and long-lived keys.

**What the bank's crypto estate looks like in one sentence:** dozens of
vendors, thousands of devices, hundreds of thousands of certificates/keys,
multiple regulators, and a crypto change process that touches payment HSMs,
ADCs, firewalls, PKI and cloud KMS — with no single inventory that spans all
of it.

---

## 2. What the bank actually runs today (and what each tool covers)

| Domain | Real tool at the bank | What it does well | Blind spot |
|---|---|---|---|
| Payments crypto | Thales payShield + payShield Manager/Monitor/TMD | PIN/EMV/key ops, scheme audits, FIPS/PCI HSM certs [1][4][5] | HSM health & firmware only — no algorithm-level view of *what consumes* the HSM |
| Cert lifecycle | Venafi / Keyfactor | Issue/renew/revoke at scale, 200+ collectors, PKI ownership | **No algorithm-level inventory inside apps/containers**; no evidence chain |
| Network | F5 BIG-IP + Palo Alto/Fortinet/Cisco | TLS offload, L4–L7 security, VPN/ZTNA [5][6] | Each vendor's own console; no unified crypto view across firewall + LB + router |
| Database | IBM InfoSphere Guardium | DB activity monitoring, SQLi defense, compliance reporting [2] | Crypto *configuration* of the DB (TLS versions, certs, TDE key mgmt) not its focus |
| SOC | Splunk ES / QRadar + UEBA + SOAR + EDR | Log correlation, incident timelines, detection [1][3] | Sees *events*, not *crypto state*; needs log onboarding per source, high false-positive variance |
| Cloud | AWS/Azure KMS + Akeyless-class vault | Key rotation, JIT credentials, audit logs [3] | No cross-cloud crypto inventory; no PQC readiness of KMS keys |
| Compliance reporting | Manual + GRC tooling | Audit packs per request | "Asset total without criticality creates false comfort" — the exact gap regulators flag [7] |

The defining characteristic of the bank's stack: **each domain is a separate
silo with its own console, its own inventory, its own alerting.** Correlating
"root CA changed" across 500 certs → 1,200 apps → 40 business services
currently means a human stitching together Venafi exports, Splunk queries and
F5/cloud tickets.

---

## 3. What the product maps onto the bank's estate

ZELNX/CryptoScan's universal vendor scanner was built for exactly this estate
(16 vendor categories, 68 first-party plugins):

| Bank domain | Product module | What it does on the bank's estate |
|---|---|---|
| Payments HSMs | `plugins/hsm.py` (Thales Luna, Entrust nShield, Utimaco, AWS CloudHSM) + `live/vendor_monitors.HsmLiveMonitor` | Metadata-only HSM watch: firmware, algorithms, key *metadata*, partitions — **never keys/PINs** (assertion-guarded); HSM_CONFIGURATION_CHANGED / FIRMWARE_CHANGED / KEY_METADATA_CHANGED events |
| Network + firewall | `plugins/network.py`, `plugins/firewall.py`, `live/vendor_monitors` (Cisco, PAN-OS, FortiOS, Check Point, Sophos, SonicWall, F5, NGINX, HAProxy) | Unified crypto view across router + firewall + LB: IKE/IPsec/SSH/TLS/cert/trust-store events normalized into one event model |
| Cert lifecycle | `live/cert_watcher.py` | Universal certificate watcher: new/renewed/expired/revoked/algorithm/key-size/chain changes from every vendor surface |
| PKI | `plugins/pki.py` + `PkiLiveMonitor` | Root/intermediate/issuing CA watch, CERTIFICATE_CREATED…CA_CHANGED, trust chain, signature algorithms |
| Databases | `plugins/database.py` (Oracle, SQL Server, PostgreSQL, MySQL, MariaDB, MongoDB, Redis, Cassandra) | TLS/certs/encryption/key-management refs — the crypto-config layer Guardium doesn't cover |
| Cloud | `plugins/cloud.py` (AWS/Azure/GCP KMS/Key Vault/Cloud KMS, ACM/PCA) + live CBOM | Key *metadata* (algorithm, size, state, rotation) and cert inventory across tenants; vendor→cloud correlation (Cisco→IPsec→VPC→EKS→app) |
| SOC | `plugins/security.py` (Splunk, QRadar as *intelligence sources*) | Passively turns SIEM TLS/cert/VPN/policy events into CryptoObservations → evidence → live CBOM — without duplicating SIEM analytics |
| Mainframe | (not implemented — see gaps §5) | — |

---

## 4. Head-to-head on the regulator's asks

Regulators and industry bodies now demand specific things from banks.
The 2025–2026 guidance is unusually concrete:

- **UK NCSC roadmap:** cryptographic inventory + initial migration plan by
  **2028**, highest-priority services migrated by **2031**, complete by
  **2035** [7].
- **G7 Cyber Expert Group (Jan 2026):** phased, risk-based transition,
  mid-2030s horizon, vendor-transparency treated as a bottleneck [8].
- **US NSM-10 / OMB M-23-02:** PQC leads, full cryptographic inventory,
  migration by 2035; NIST PQC standards (FIPS 203/204/205/206) available
  now [1][9].
- **BIS Project Leap:** central-bank coordination; inventories and planning
  flagged as *manual* in current practice — "average migration time of 24
  months for critical systems" [1].
- **PCI DSS 4.0 / SOX / DORA:** auditable evidence, change control, and
  operational-resilience records for crypto-relevant changes.

| What the guidance asks a bank to show | How the bank does it today | How the product does it |
|---|---|---|
| Complete cryptographic inventory | Spread across Venafi (certs), HSM consoles, cloud consoles, spreadsheets | One normalized CBOM: source + network + containers + cloud + HSM + vendor/supply-chain → CycloneDX 1.5/1.7 output, 68 plugin families |
| Evidence for every finding | Screenshots + manual exports | **SHA-256 evidence chain**, tamper-evident packs/transfers, chain verification built in |
| "Which certs/keys are quantum-vulnerable?" | Vendor-by-vendor manual review | Versioned, evidence-backed PQC DB (§22) — `PQC_SUPPORTED/HYBRID/PARTIALLY/ROADMAP/NOT_SUPPORTED/UNKNOWN`, never inferred from product names |
| "When must we migrate and what's priority?" | Analyst judgment | Lifecycle DB + `migration_priority()`: legacy + PQC-required + EOS → HIGH; live PQC monitor with migration impact scoring |
| "What breaks if this CA/key changes?" | Multi-tool manual tracing | **Blast radius** over the universal dependency graph: root CA change → 500 certs → 1,200 apps → 40 business services, correlated as **one incident** |
| Continuous monitoring without load | Scheduled scans per console | 7 live modes; fingerprint gating (deep scan only when crypto-relevant config changes); lightweight polling |
| Audit-ready change history | SIEM logs (require onboarding + correlation) | Event gateway → append-only event log → state transitions → versioned CBOM materializations |
| PQC vendor readiness for procurement | Manual vendor questionnaires | Vendor capability registry + evidence-backed verdicts per vendor/product/version — feeds procurement decisions (BIS: "vendor readiness is the critical path" [7][10]) |

---

## 5. Honest gaps — what the real bank has that the product does not

Per the platform's own [platform boundaries](platform-boundaries.md), these
are stated as facts, not sales copy:

1. **Production-scale lifecycle automation.** The bank's Venafi/Keyfactor
   installs *issue, renew and revoke* certificates at scale (1M+ estates).
   ZELNX inventories and monitors crypto — it never writes to a CA or rotates
   a key. That is a deliberate boundary (read-only by contract), and it means
   the product complements, not replaces, CLM.
2. **Runtime/dynamic analysis.** The bank's app teams use
   Cryptosense-class tracing or agent-based telemetry to see *runtime* crypto
   behavior. ZELNX is static + passive + API-metadata only.
3. **Certifications & enterprise support.** PCI HSM, FIPS 140-3, FedRAMP,
   SOC 2, 24×7 vendor support, SLAs — the bank's vendors hold these; the
   product holds none and cannot yet be the compliance *owner* of an HSM or
   payment rail.
4. **Threat detection.** Splunk/QRadar/EDR detect *attacks*. ZELNX detects
   *crypto change and drift* — different job, and it deliberately does not
   duplicate SOC analytics (SIEM is an intelligence *source*, §11).
5. **Mainframe core banking (z/OS, AS/400).** No plugin exists; bank
   mainframe crypto (RACF/ICSF, long-lived keys) is out of current scope.
6. **True scale engineering.** The bank operates tens of thousands of
   devices and hundreds of thousands of certs; the product is verified on a
   local estate (2,483 tests, 26 service dirs) — production ingestion at
   bank scale (rate limits, event lag, multi-region fan-in) is untested.
7. **Deep single-host TLS lab** (testssl.sh-class), general CSPM breadth
   (Prowler's 600+ checks), full OT DPI — all deliberately out of scope.

---

## 6. Honest differentiators — what the product has that the bank's stack does not

1. **One estate, one model.** The bank's #1 problem is that crypto
   information lives in 6+ silos. The product normalizes Cisco, Palo Alto,
   F5, Thales, AWS, Azure, Splunk events into **one canonical event model →
   one dependency graph → one live CBOM**. No bank tool does this today;
   banks stitch it manually [7][8].
2. **Evidence-chained everything.** Every observation → content hash → chain
   hash → verifiable evidence pack. The bank's auditors get screenshots;
   the product gives them a tamper-evident, verifiable chain.
3. **Metadata-only, enforced.** The product *never touches key material* —
   unlike Venafi (which protects/rotates keys) and unlike HSM consoles. For a
   bank's compliance posture, "we never saw the key" is a feature: it keeps
   the tool out of PCI HSM scope entirely.
4. **Evidence-backed PQC verdicts with honest UNKNOWN.** The bank's
   procurement team asks "is vendor X quantum-ready?" and gets marketing.
   The product answers with a versioned DB, evidence source, last-verified
   date, confidence — or **UNKNOWN**, never a guess.
5. **Live drift + blast radius across vendors.** A bank's F5 TLS profile
   change or root-CA rotation currently produces tickets in separate
   consoles. The product classifies drift (NO_CHANGE…CRITICAL_CRYPTO_DRIFT),
   walks the cross-vendor graph, and emits **one correlated incident** with
   counts.
6. **Offline-first + regional.** Isolated bank networks (air-gapped
   processing centers) get a local queue + evidence store + secure sync; UAE/
   EU/USA edges keep monitoring when the central plane is down — matching how
   banks actually run regional ops.
7. **Deterministic, no-AI, auditable OSS.** 2,483 tests, self-hosted, no
   black box. Regulators ask for evidence; the codebase is the evidence.

---

## 7. Bottom line

- **As a replacement for the bank's existing tooling:** no. The bank's
  Venafi/Keyfactor, Thales HSMs, F5, Splunk and Guardium run at a scale,
  with certifications and automation, that the product does not match — and
  is not trying to.
- **As the layer the bank is missing:** yes. Regulators (NCSC 2028/2031/
  2035, G7, BIS, NSM-10) now require a *complete, evidence-backed crypto
  inventory with vendor readiness and migration priority* — and the bank's
  current stack cannot produce it from one place. The product is purpose-built
  for that gap: universal vendor normalization → evidence chain → live CBOM →
  PQC/lifecycle verdicts → blast radius.
- **Realistic positioning:** "know your crypto estate, prove it, and plan the
  migration" — the honest inventory-and-readiness layer that **feeds** the
  bank's CLM (cert renewal tickets), SIEM (events), HSMs (firmware/algos)
  and cloud consoles, instead of replacing any of them. The compliance wedge
  is the evidence chain + metadata-only guarantee: it gives a bank what an
  auditor asks for ("show me every crypto change and its evidence") without
  adding anything to the PCI/HSM scope.

---

## Sources

[1] Post-Quantum Financial Infrastructure Framework (PQFIF) — sec.gov (2025):
     NSM-10 2035 deadline, BIS Project Leap, HSM/payment-processor criticality
[2] F5 + IBM InfoSphere Guardium joint DB security — F5/IBM white paper
[3] Akeyless — financial-institution secrets management, PCI DSS req. 10,
     SOX ITGC (2026)
[4] Thales payShield 10K — PCI HSM, FIPS 140-2 L3, Common Criteria EAL4+,
     EMV/PIN/tokenization (Thales + payment-industry sources)
[5] Thales payShield / payShield Cloud HSM technical briefs — cpl.thalesgroup.com
[6] F5 BIG-IP in banking: ADC, TLS offload, SSL VPN, ZTNA — F5 + industry
     architecture write-ups (2025–2026)
[7] Post-Quantum Cryptography for Banks: A Migration Playbook —
     globalbankingandfinance.com (2026-08): NCSC 2028/2031/2035, vendor
     readiness as critical path, "asset total without criticality creates
     false comfort"
[8] G7 Cyber Expert Group PQC roadmap — thequantuminsider.com (2026-01):
     mid-2030s horizon, vendor transparency bottleneck
[9] Quantum Threat Readiness for Financial Institutions — netbankaudit.com:
     OMB M-23-02 blueprint, examiner artifacts (inventory, FIPS 140-3, PQC
     change records)
[10] Real-world competitive comparison — docs/architecture/real-world-comparison.md
     (Venafi/Keyfactor/Cryptosense/SCANOSS/Prowler/Trivy details)
