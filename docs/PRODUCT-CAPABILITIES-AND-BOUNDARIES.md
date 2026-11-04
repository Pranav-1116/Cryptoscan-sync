# What CryptoScan does, what it cannot do, and why the six BOMs are the only route to PQC

> **How to read this document.** Sections 1–4 describe what the product does, by surface, and name
> the file or route that proves each claim. Section 5 lists what it does **not** do — including the
> one this document was written to answer, *why it does not scan IoT sensor endpoints* — and why
> those refusals are design decisions rather than missing bells. Section 6 explains why no AI is in
> the decision path, with the code that enforces it. Section 7 explains why **hardware, network,
> software, cryptography and vendor** are jointly necessary for a post-quantum migration, and what
> breaks when one is missing. Section 8 explains why the same six BOMs are what future attack
> detection and threat intelligence will be built on.
>
> Everything in §1–4 is machine-checked somewhere in this repository; where a capability is
> modelled but not operational, this document says so in the same sentence. **A document that
> overstates the product is worse than no document**, because a bank will quote it to a regulator.

---

## 1. One paragraph

CryptoScan **integrates with the bank's existing estate and builds an evidence-backed cryptographic
and security estate model** — read-only, deterministic, and honest about what it could not read. It
collects from the surfaces the bank approves (source, binaries, containers, network, cloud, OT,
telecom, hardware, HSM, vendor documentation, CMDB, runtime), turns every observation into a fact
that carries its evidence id and its *class* of knowing, joins those facts into one canonical estate,
and projects six BOMs — SBOM, CBOM, HBOM, NBOM, VBOM, TechBOM — from that single model rather than
maintaining six inventories. On top of that model sit policy, drift, dependency impact, quantum risk,
migration planning, compliance evidence and reporting.

It is not a scanner that finds "everything". It is a measurement instrument with a stated error bar.

---

## 2. The rule the whole product is built on

```
observation → evidence check → normalise → identity → FACT → correlation → BOM
```

| Stage | Rule | Where it is enforced |
|---|---|---|
| Collection | A collector that cannot read a surface **says so**; it never returns an empty result that looks like a clean estate | `services/*_scanner/`, `FAILED` plane states |
| Evidence | Every observation carries an evidence id; an observation without one is refused as "a rumour" | `services/cbom/cbom/facts.py` (`Observation.__post_init__`) |
| Facts | Capability is not usage; a class is carried, never promoted; disagreement is preserved, not resolved | `facts.py` (`_LEGAL`, `DECIDING_CLASSES`, `aggregate`) |
| Absence | Four states: found / not-found-within-scope / not-observable / collection-failed — plus "nobody looked" | `facts.presence()` |
| Scoring | `UNKNOWN` never counts as a wrong answer, and never counts as free | `services/cbom/cbom/accuracy.py` |
| Output | A conflict carries no value into the BOM | `facts.cap_placement()` |

Three consequences worth stating plainly, because they shape every section below:

1. **"We found nothing" and "we could not look" are different outputs.** A failed HSM collection is
   `COLLECTION_FAILED`, never "no crypto".
2. **`OpenSSL 3.0.13 is installed` is not `AES-256-GCM is used`.** The first is a capability fact.
   Confusing the two is the single largest source of false positives in this product category, and
   the platform measures the cost of the confusion: see §7.4.
3. **No invented fact ever becomes an observation.** Where the product cannot establish something,
   the honest answer *is* the output.

---

## 3. The six BOMs — six products, not six names for one report

They are **projections of one canonical estate**, materialised on demand
(`GET /api/v1/estate/evidence/boms/{kind}/export?fmt=cyclonedx`). `shared_models/estate_graph.py`
defines exactly six kinds: `SBOM, CBOM, HBOM, NBOM, VBOM, TECHBOM`.

| BOM | The question it answers | Evidence behind it | Primary user |
|---|---|---|---|
| **SBOM** | What software and which versions are in this scope? | manifests, lockfiles, container/image packages, binary observations, imported supplier BOMs | AppSec, software supply chain |
| **CBOM** | Where are algorithms, keys, protocols and crypto libraries, and what needs migration? | crypto inventory + supporting scan/evidence records | cryptographic governance |
| **HBOM** | What hardware and firmware exists, and can it do PQC? | host readers, network device transports, HSM/TPM readers, vendor plugins | infrastructure, HSM owners |
| **NBOM** | What is actually on the wire — listeners, negotiated TLS, certificates, tunnels? | authorised active probes and passive captures | network security, cert operations |
| **VBOM** | Which suppliers are in the path, and what have they declared? | vendor register, questionnaires, documents, public posture, due-diligence revisions | third-party risk, procurement |
| **TechBOM** | How does it all fit together into systems and dependencies? | the joined estate: system/crypto/hardware/vendor inventory + declared dependency rows | enterprise architecture, CISO |

Each is accepted separately by a bank (they are six evidence views with six different confidence
levels), and each is **also** an input to the PQC argument in §7. That is not a documentation
flourish: an SBOM without a CBOM tells you a library is present but not whether its crypto is used; a
CBOM without an HBOM says the algorithm is vulnerable but not whether the HSM can hold its
replacement; an NBOM without a VBOM names a TLS endpoint but not who owns the appliance terminating
it.

---

## 4. What it does — by surface

### 4.1 The published scope register — nine domain areas plus shared layers

`GET /api/v1/platform/scope` (schema v3) is generated from `shared_models/platform_scope.py`, so this
list cannot drift from the code. The register holds **ten entries: nine domain areas and one
"shared layers" entry** describing the machinery every area sits on.

| # | Area (`id`) | What it means in practice |
|---|---|---|
| 1 | **z/OS mainframe crypto discovery** (`zos-crypto-discovery`) | Operator-produced z/OS extracts ingested — RACF `RACDCERT LIST`, ICSF key inventories, DB2 TLS, CICS `TCPIPSERVICE` — plus crypto-call detection in COBOL/PL-I/Natural/HLASM/JCL/REXX/CLIST (ICSF `CSN*`/`CSF*` verbs and PCI parameter blocks only) |
| 2 | **Source-tree crypto inventory** (`source-tree-crypto`) | Deterministic detection of crypto API usage — algorithms, modes, key sizes, hardcoded keys — across Java/C#/Go/Python/JS/TS/etc. Crypto only, not general SAST |
| 3 | **Network & TLS posture** (`network-tls`) | Negotiated protocol/cipher, certificate posture and expiry, weak-protocol detection, DNSSEC/IPsec targets |
| 4 | **Containers & IaC** (`containers-iac`) | Image layers, package manifests, embedded JARs and shared objects, Dockerfile/compose/K8s/Terraform crypto config |
| 5 | **Cloud accounts & tenants** (`cloud-tenants`) | Read-only AWS/Azure/GCP discovery inside the accounts the operator's credentials can reach — never "the whole cloud company" |
| 6 | **OT/ICS passive monitoring** (`ot-ics`) | Passive protocol inventory (OPC-UA, DNP3, Modbus, IEC 61850, S7comm, CIP, BACnet, IEC-104, PROFINET, MQTT) with a verified **zero-packet** promise toward OT networks |
| 7 | **Payment HSM / PCI** (`payment-hsm`) | HSM key inventory with ceremony provenance, TR-31 parsing, audit-trail ingestion, PAY policy rules — key **metadata** only |
| 8 | **Vendor & supply-chain crypto** (`vendor-supply-chain`) | Vendor crypto discovery (API scan, CBOM import, questionnaire, public posture) with 0–100 risk scores |
| 9 | **Certificates & PQC readiness** (`certs-pqc`) | Certificate inventory, quantum risk (Shor/Grover, HNDL, Mosca deadlines), evidence-supported PQC readiness — never asserted without evidence |
| — | **Shared layers** (`shared-layers`) | Evidence chain, normalization (IANA/CBOM/SPDX), deterministic policy, drift and CI gates, graph, remediation, compliance reporting, live monitoring |

The same module publishes six **non-goals** (general SAST, malware analysis, SIEM behaviour analytics,
mainframe business logic, employee endpoint agents, company-wide cloud scanning), the access model,
and five **invariants** — read-only collection, evidence-chained facts, metadata-only (never key
material), deterministic policy, honest status. §5 expands the non-goals; §2 lists the invariants as
they are enforced.

### 4.2 Collection surfaces (12)

| Surface | What is collected | Depth and honesty boundary |
|---|---|---|
| **Source code** | crypto API usage, algorithms, modes, key sizes, hardcoded-key patterns, config and key-inventory files, runtime logs | Java, C#, Go, Python, JS/TS, PHP, Ruby, Rust, Kotlin, Swift, C/C++, SQL, shell, XML; legacy: **COBOL, PL/I, RPG, Natural, HLASM, JCL, REXX/CLIST, 4GL, TAL, SAS, payShield console**. Crypto-only — not general SAST (`services/scanner/scanner/parsers/`) |
| **Binaries** | imported/exported crypto symbols, embedded libraries, string-level evidence | Bounded evidence with explicit partial/refusal states; it identifies crypto *libraries and configurations*, never analyses malware |
| **Containers & IaC** | image layers, package manifests, embedded JARs and shared `.so`s, Dockerfile/compose/K8s/Terraform crypto config | Layer-level facts only where the inspected image proves them |
| **Firmware & mobile & WASM** | firmware images, APK/IPA packages, WebAssembly modules | Bounded; obfuscated (R8/ProGuard) DEX and Swift-generic-only iOS crypto remain unproven and are stated as such |
| **Network** | negotiated TLS version/cipher/group, certificate posture and expiry, SSH/IPsec/WireGuard/OpenVPN/SSTP offers, DNSSEC, database handshakes (PostgreSQL/MySQL TLS), SMTP/IMAP/POP3/LDAP/FTPS/STARTTLS, MQTT/AMQP, K8S-API-TLS, SNMP | Active probes only against operator-configured targets; passive capture where the bank supplies it (`network_scanner/probing`, `network_scanner/passive`) |
| **Cloud** | read-only AWS/Azure/GCP inventory: KMS keys and rotation, certificates, load balancers/listeners, storage encryption, secrets metadata | **Only the accounts/tenants the credentials can see.** Never "scan the cloud provider" |
| **OT / ICS** | passive protocol inventory: S7comm, EtherNet/IP/CIP, BACnet/IP, OPC UA, Modbus, DNP3, IEC-104, IEC-61850, PROFINET, MQTT — plus cleartext-engineering flags | **Zero packets** to OT networks. Decoders read a span/mirror port or a supplied pcap; SIS/ESD are never touched |
| **Telecom** | 5G network-function TLS/certificate posture, SS7/Diameter/SIP/GTP-C parsing, key hierarchy, authentication flows, roaming/journey metadata | Lab targets only so far; not asserted as a live carrier measurement |
| **Payment HSM / PCI** | payment-key inventory with ceremony provenance, TR-31 key-block parsing, HSM audit-trail ingestion (JSONL/syslog/CSV), PAY-001..010 policy | Key **metadata** only — never key material |
| **Hardware** | Linux `/sys`, dmidecode, lspci, lsblk, lscpu, smartctl, TPM2, OpenSC; Windows CIM (12 allowlisted classes) as a **candidate**; SNMPv2c (ENTITY-MIB), NETCONF, RESTCONF; HSM via PKCS#11, KMIP, vendor REST; 32 device types incl. server/GPU/NIC/storage/HSM/TPM/PLC/industrial controller/IoT gateway | See §5.1 and §5.2 for exactly where this stops |
| **Runtime** | processes, loaded modules, services, listeners, package records, exec events (eBPF execve tracer, `deploy/ebpf/execve_trace.py`) | Metadata: it can say a process *has* a library loaded, not that it *invoked* AES-256-GCM |
| **Vendor & supply chain** | 30 vendor plugins across 9 collector modules, questionnaires, documentation extraction, public-posture checks, versioned supplier profiles, risk scoring | A declaration is `VENDOR_DECLARED` — recorded, displayed, and given no vote in a usage fact |

Plus: **CMDB import** (ServiceNow field-tested against one schema), **z/OS extracts** (RACF
`RACDCERT LIST`, ICSF key inventories, DB2 TLS, CICS `TCPIPSERVICE`), **bank-side agent**
(`services/agent`, Ed25519-signed observations, state-hash gated), and **security-control read-only
integration** (§4.6).

### 4.3 One canonical estate, six projections, live

- **Baseline once, then changes only.** A discovery of an unchanged estate writes `NO_CHANGE` — no
  run, no BOM revision. The agent posts only when its state hash moves; a failed collector is stored
  as a `FAILED` plane rather than a smaller estate.
- **Digital twin.** A read-only replica: live crypto states, versioned CBOMs, an append-only event
  journal (per-asset time travel), stored network probes (the same derivation the NBOM uses, so the
  two can never disagree), dependency edges, and the hardware fleet. `/digital-twin` measures its own
  fidelity — staleness, coverage, journal depth — with honest unknowns where the estate is unscanned.
- **Six BOMs projected on download**, never stored as six separate truths; a test fails if a second
  inventory per BOM type appears (`docs/bank-environment/128-hardware-discovery.md`).

### 4.4 Analysis and reasoning

| Capability | What it does | Where |
|---|---|---|
| Normalisation | findings → canonical crypto artefacts (IANA/CBOM/SPDX vocabularies, 114 normalisation tests) | `services/normalization/` |
| Algorithm registry & classification | classical / broken / Shor-vulnerable / Grover-affected / PQC | `shared_models/quantum_classify.py` (176 tests) |
| Quantum risk | Shor/Grover, HNDL exposure, Mosca deadline (`x + y > z`), PQC replacement suggestions | `services/quantum/risk.py`, `plan.py` |
| Crypto-agility scoring | how cheaply each asset could swap algorithms | `services/agility/` |
| Prioritisation & risk roll-up | deterministic ranking over findings + business context | `services/api/api/consistency.py`, `priorities` |
| Dependency graph & blast radius | edges with provenance and confidence; shared-asset union; Neo4j optional, in-process engine as the tenant-isolated fallback | `services/graph_engine/` |
| Cascade / "what breaks if X changes" | across code, network, system graph, process, hardware, vendor and library layers, with run history, diffs, migration waves, replay | `estate_graph.py`, `/cbom` console |
| Conflict classification | REAL vs EXPLAINED contradictions, never averaged | `services/api/api/estate_conflicts.py` |
| Completeness | per component: `UNMEASURED / INCOMPLETE / CONTRADICTED`, and whether it may be counted in a total | `services/cbom/cbom/inventory_completeness.py` |
| Accuracy | precision/recall per field with `UNKNOWN` excluded from the wrong-answer column, gated per dimension | `services/cbom/cbom/accuracy.py`, `docs/bank-environment/185-accuracy-ground-truth.md` |
| Simulation | 10 registered scenario slots plus a `COMPOSITE` sequence of up to five primitive scenarios applied in order to one copy, **all ten with a model**: `PQC_MIGRATION` full, nine partial — including `CUSTOM_SCENARIO` (an operator-authored expression over one evidence record) and `TRUST_COMPROMISE` (`CASCADE_TRUST_COMPROMISE` walks `issued_by`/`signed_by`/`verified_by`/`uses_certificate`, with trust-store and revocation blind spots named) — `shared_models/enterprise_scenarios.py` reports `EXISTS / PARTIAL / ABSENT` per slot | `/simulation`, `/what-if`, `GET /estate/evidence/twin/simulation-scenarios` |

### 4.5 Governance, evidence and operations

- **Policy** — versioned YAML rule packs (`services/policy/rule_definitions/`): BASELINE, PCI-DSS,
  NIST SP 800-131A-class, CNSA 2.0, FIPS, HIPAA, key-inventory, plus regional packs (Bahrain, Qatar,
  Saudi Arabia, UAE). Eleven sector profiles (banking, telecom, energy, government, healthcare,
  pharmaceutical, retail, manufacturing, automotive, cloud/SaaS, generic) select which packs and
  criticality weights apply. Every evaluation is reproducible from stored evidence. **No AI.**
- **Drift** — approved baselines, drift events, acknowledge/resolve, CI gate profiles
  (standard/strict/lenient) with GitHub/Jenkins/GitLab/ArgoCD snippets and a `ci_gate.py` CLI that
  exits 1 to block a pipeline.
- **Evidence chain** — SHA-256 content/chain/manifest hashes, audit packs, a verify endpoint,
  tamper-evident transfer, JWS-signed CBOMs, hash-chained audit trail with a verify + WORM-ready
  export.
- **Restore drill** — a real restore into a recovery database, measured row-by-row against the
  source, with a hash-chained receipt (`scripts/restore_drill.py`, guide 184). PITR remains
  **not provided**.
- **Identity & access** — users/roles/MFA, OIDC/SAML/LDAP, API keys, lockout, RBAC on writes,
  tenant scoping with **row-level security** provisioned by a tested script
  (`scripts/provision_runtime_role.py`).
- **Compliance** — nine report templates (PCI-DSS 4.0, NIST SP 800-53, NIST SP 800-131A, FIPS 140-3,
  ISO 27001, SOC 2, DORA, UAE PDPL, plus `custom`), requirement-by-requirement from policy evidence, attestation
  with a canonical hash (PKI for attestation is honestly absent), JSON/HTML/PDF, scheduled.
- **Remediation & migration** — 15 rules × 4 languages of before/after fixes, scan → project → tasks
  → velocity forecast, GitHub issue export.
- **Live monitoring 24/7** — watch-list daemon with backoff, alert-once, BLOCKED-honesty; monitor
  status API and console view.
- **Operations** — 52 service packages, 132 API router modules, ~1,285 operations, 133 Alembic migrations
  (head `0133`), PostgreSQL, Redis Streams (optional), Neo4j (optional), Kubernetes manifests with
  digest-pinned images and default-deny network policy, Prometheus/Grafana, compose CLI asserted in
  CI, air-gap transfer, offline CLI (`cli_remote.py`, HTTP-only, refuses plaintext non-loopback).

### 4.6 Output formats

CycloneDX 1.6 (schema-validated by `cbom/cyclonedx16.py`), CEF for SIEM, JSON/HTML/PDF reports,
SARIF for CI, GraphQL (read-only), SSE and WebSocket streams, webhooks, chatops, ITSM/SIEM
connectors, signed evidence packs and air-gap bundles.

### 4.7 The security-control layer (read-only over the bank's own controls)

Thirteen control types — FIREWALL, IDS, IPS, WAF, LOAD_BALANCER, API_GATEWAY, RATE_LIMIT, VPN, SIEM,
HSM, KMS, PKI, NETWORK — through one collector contract with six read-only verbs. It is **not** a
firewall, an IPS, a WAF, a rate limiter or an API gateway, and cannot become one: a spec naming a
mutating operation is refused when the adapter is registered. Findings export as CycloneDX 1.6 or
escaped CEF lines with the evidence id in an extension, so an alert can be joined back to the
snapshot it came from.

### 4.8 The console

**91 shipped surfaces across 7 areas**, each carrying a *stated limit* rather than a maturity badge
(`shared_models/capability_maturity.py`, `GET /api/v1/platform/capabilities`,
`docs/CAPABILITY-MATURITY.md`). Areas: Overview (12), Discovery (16), Intelligence (27), Governance
(16), Administration (15), Auth (4), Output (1). The full per-surface register — question, limit, and
the route that proves it — is the CAPABILITY-MATURITY table; it is generated from the same objects
the API serves, so the console, the API and the docs cannot drift apart.

Two things the register does *not* say, and it is important not to read them into it:

* **`ga` here means "shipped and supported", not "unlimited".** The honesty lives in the per-surface
  `limit` sentence (`CAPABILITY_LIMITS` in `frontend/src/lib/maturity.ts`, rendered on `/scope`), and
  in the five capability boundaries of §5.2. An unknown route resolves to `preview`, never upward.
* If an older document in this repository quotes a GA/beta/preview split (e.g. "33 / 32 / 12"), that
  is a stale count from before every shipped surface was classified uniformly; the generated tables
  and `GET /api/v1/platform/capabilities` are the truth.

---

## 5. What it does not do — and why each refusal is deliberate

### 5.1 It does not scan IoT sensors. It does scan the gateways and the traffic they emit

This is the boundary most often misread, so it gets the most detail. Four different things get called
"IoT", and the product sits on exactly one side of each:

| | What the product does | What it does not do |
|---|---|---|
| **IoT gateway / edge appliance** (Cisco IR, Dell Edge Gateway, industrial routers) | A first-class hardware device class (`iot_gateway`) with vendor/model/firmware, connected-device counts and crypto metadata where the device answers over IP (network/API discovery) | Nothing physical: no console port, no factory-image extraction |
| **IIoT telemetry over IP** (MQTT 1883 vs 8883, OPC UA security mode, Modbus/DNP3/IEC-104 cleartext) | Protocol records from a bank-supplied capture/telemetry feed, with `OT_UNENCRYPTED_MQTT`-class findings and *passive-only* decoding | It does not join a broker, subscribe to topics, or enumerate devices that publish to it |
| **Sensor endpoint nodes** (temperature, flow, vibration, smart meters, wearables) | **Nothing.** They are modelled as "connected devices" on a gateway at best | No discovery, no fingerprinting, no firmware, no key material, no attestation |
| **Radio layer** (BLE, Zigbee/802.15.4, Z-Wave, LoRaWAN, NB-IoT radio, Thread, Matter) | **Nothing.** There is no radio in the collection model at all | No sniffing, no pairing analysis, no mesh topology, no replay analysis |

> Verified by absence, not by promise: `zigbee`, `lorawan`, `802.15.4` and `jtag` appear **zero** times
> in the Python tree, and the hardware device classes are the 32 in
> `universal_vendor/hardware/models.py` — gateway, PLC, industrial controller, OT appliance, embedded
> — never "sensor".

**Why this is a decision and not a backlog item:**

1. **A sensor has no readable crypto over IP.** Its algorithm is in firmware you can only obtain
   physically (J-TAG/SWD/UART, desoldering, vendor CAS), and its key lives in a secure element you
   cannot read without an attack this product is not allowed to perform. Anything CryptoScan printed
   about it would be an *inference from the model number* — exactly the class of claim §2 forbids.
2. **Read-only means read-only.** Every collector runs with operator credentials over IP and writes
   nothing. Flashing a sensor image, holding a debug port, or joining a Zigbee mesh to enumerate
   nodes would each break the deployment model a bank's OT team signs off on.
3. **Sensor meshes are behind gateways by construction.** NB-IoT/LoRaWAN sensors reach the bank
   through a gateway or an operator platform; the bank's cryptographic control point *is* the
   gateway, its TLS to the broker, and the key it holds. The product measures that control point
   properly instead of guessing at 4,000 battery-powered nodes.
4. **OT safety.** The passive OT decoders never send a packet and never touch SIS/ESD. Probing a
   sensor network is one bad packet away from a physical process — a refusal that is worth more than
   the coverage it costs.

**What you get instead, and it is not nothing:** the gateway's firmware and PQC capability (HBOM), the
TLS the gateway negotiates to the broker (NBOM), the broker and its certificates (NBOM/CBOM), the
keys the gateway holds (CBOM/HSM metadata), the vendor's declared roadmap for that model (VBOM), and
the dependency edge from the business service that consumes the telemetry (TechBOM). That is the part
of an IoT estate a bank can act on, and it is the part that survives an audit.

### 5.2 The rest of the non-coverage, stated the same way

| Not done | The precise boundary |
|---|---|
| **General SAST / source-code hacking** | It finds crypto usage and security configuration. It does not hunt SQLi, XSS, buffer overflows or auth flaws (`platform_scope.NON_GOALS`) |
| **Malware analysis** | It identifies crypto libraries and configurations inside binaries; it does not analyse malicious behaviour |
| **SIEM behaviour analytics** | It emits findings to a SIEM (CEF) as an outbound sink; it does not do correlation hunting or endpoint telemetry analysis |
| **Employee endpoint agents** | No agents on workstations, no workstation scanning |
| **"Scan the whole cloud company"** | Only the accounts/tenants the credentials can see, and only explicitly configured external targets |
| **Mainframe business logic** | COBOL/PL-I/Natural/HLASM are read for ICSF `CSN*/CSF*` verbs and PCI parameter blocks only — no data flow, no modernisation analysis |
| **Core-banking transaction validation** | Out of scope entirely |
| **Decrypting traffic, breaking crypto, key recovery** | Never. Key *metadata* only; forbidden fields (`private_key`, `key_material`, `passphrase`, …) are banned in the evidence models and enforced by tests |
| **Writing to any device** | Not a firewall, IPS, WAF, rate limiter or API gateway; every collector declares read operations only and a mutating spec is refused at registration |
| **Proof of HSM cryptographic operations** | The HSM model is metadata (vendor, model, firmware, algorithm capability, key metadata, certificate relationships). It is not proof that a key operation ran inside the device |
| **A production Windows collector** | A **candidate** implementation: OS/uninstall/file/SCM, certificates, process/module inventory, TPM device info — with the server's own layer-by-layer "no" on completeness |
| **Complete hardware discovery** | Synthetic and metadata paths; a vendor/model/firmware catalogue and plugin seam, fed where a vendor exposes metadata |
| **Proof that a process invoked an algorithm** | Runtime gives process/binary/library/service metadata. "Loaded OpenSSL" ≠ "called AES-256-GCM" |
| **A generic enterprise simulation engine** | A real PQC-migration foundation plus ten scenario models (one full, nine partial), including a bounded custom expression and a trust-path cascade. What the partials cannot see is named per row — no arithmetic, joins or timelines in the expression language; no trust-store, cross-signing or revocation model in the trust walk |
| **Point-in-time recovery** | **Not provided.** `pg_dump`/`pg_restore` cannot replay WAL; a restore receipt is never PITR evidence |
| **A confidence gate on asset identity** | The graph records identity and aliases; an `UNRESOLVED_RELATIONSHIP` instead of a name-based guess is not yet one rule (guide 185 §6) |
| **A parser qualification matrix** | The crypto detectors are measured; every parser (malformed, duplicate, Unicode, huge, malicious) at ≥99% before qualification is not yet universal |
| **Real-bank accuracy numbers** | Every published precision/recall is scored against a planted answer key on a synthetic estate, and the report says so in its `scope` field |
| **Site acceptance, signed releases, 24/7 production certification** | Configured CI is not a signed release; local qualification is not a bank's acceptance |

The five capabilities a bank must never be told are operational — Windows collector, hardware
discovery, HSM operations, runtime crypto, simulation — are machine-read from
`shared_models/capability_boundaries.py` and served at
`GET /api/v1/estate/evidence/discovery/maturity`, each with the route that lets a reader check the
claim instead of trusting it.

---

## 6. Why there is no AI in this product

The product's claim is "every fact has evidence, and where we could not establish something we say
so". A language model is a machine for producing a *plausible next token*; that is orthogonal to
"reproducible from stored evidence". Eight reasons, in the order a bank's auditor would raise them:

1. **Reproducibility.** A finding must be re-derivable: same evidence in ⇒ same finding out, years
   later, in an air-gapped environment, by someone who is not us. A model's output depends on
   weights, sampling and context; a YAML rule does not. The evidence chain (SHA-256 content/chain/
   manifest hashes) is only meaningful if the *conclusion* is equally deterministic.
2. **Citation is structural, not stylistic.** Every fact names an evidence id, and
   `facts.Observation` raises when one is missing. A model can write a convincing citation to a
   record that does not exist — and a fabricated evidence id is exactly the failure mode the accuracy
   harness scores at 0% (see §7.4).
3. **The product's central promise is a refusal.** "Unknown is not secure." A model has no
   mechanism to decline; asked what an unreachable HSM uses, it will produce the most likely answer.
   The four-state absence model exists so the *system* can hold that refusal; a model would erode it
   on every prompt.
4. **Policy is a legal artefact.** PCI-DSS, NIST SP 131A, CNSA 2.0, FIPS and ISO mappings are
   reviewed, versioned, and diffable. "The model decided" is not an answer a regulator accepts, and
   a policy that cannot be diffed cannot be approved.
5. **Adversarial inputs.** A certificate CN, an SBOM supplier name or a firmware string is
   attacker-controlled text. Deterministic parsers treat it as data. A model reading that text inside
   its context is a prompt-injection target whose output lands in a security finding.
6. **Sovereignty and air-gap.** Banks run this offline. Sending estate data to a third-party
   inference endpoint is a data-residency and confidentiality decision that many banks cannot make at
   all, and a local model is another 10 GB of unpatched attack surface inside the perimeter.
7. **Testability.** 1,248 backend test files pin behaviour that must not drift. A model cannot be
   pinned by a test; it can only be sampled. "It got better on our eval" is not a regression gate.
8. **Explainability of impact.** "This asset breaks because these three edges exist" can be walked
   edge by edge in the console (`/estate-twin` reports `POPULATED / EMPTY / NOT_EVALUATED` per link).
   A model's blast radius is a paragraph, not a path.

**It is enforced, not just stated.** The services are classified as deterministic and the runtime
policies that follow from that are in the tree:

- `shared_models/platform_scope.py` — invariant `deterministic-policy`: *"Rules are versioned YAML;
  evaluations are deterministic and auditable."*
- `services/api/api/security/ai_boundary.py` — an eBPF `execve` classifier that marks any AI
  binary/tool invocation (CLI assistants, local LLM runners, AI code generators) as a **VIOLATION**
  on a deterministic service, and anything unclassified as **UNKNOWN** for review, never silently
  passed.
- seccomp profiles and read-only root filesystems strip the escape primitives underneath it.
- `docs/security-questionnaire.md`: *"deterministic and replayable — no AI/ML makes policy
  decisions."*

**Where AI could legitimately appear later, and what would have to be true first:** summarising facts
the platform already computed into prose, translating a finding into a local language, or drafting a
remediation ticket — all *downstream of the factual path*, all quoting evidence ids, all disabled by
default, and all with a test that fails if a model ever enters collection, normalisation, policy or
scoring. That test does not exist yet, and guide 185 §6 names it as an open item rather than claiming
the guarantee is enforced end-to-end.

---

## 7. Why PQC migration needs hardware **and** network **and** software **and** cryptography **and** vendor

A post-quantum migration is not "replace RSA with ML-KEM". It is a change to five coupled inventories,
and a plan that is missing any one of them is a plan that fails in a specific, predictable way. The
product's answer is not to guess at the missing plane — it is to make all five measurable in one
estate and to show the gap.

### 7.1 What each plane contributes

| Plane | The question it answers for PQC | Source of truth in the product | Without it |
|---|---|---|---|
| **Cryptography** | Which algorithms, key sizes, modes and protocols exist, and which are Shor-vulnerable / Grover-weakened? | **CBOM** (`quantum_classify`, `quantum/risk.py`) | You cannot size the problem: no population, no priority, no Mosca inputs |
| **Software** | Which libraries and versions implement them, and where must code change? | **SBOM** + CBOM call sites | You migrate a spreadsheet instead of a codebase; unpatched call sites keep the old algorithm alive |
| **Hardware** | Can the HSM/TPM/appliance actually hold ML-KEM/ML-DSA — firmware, FIPS certification, key import, capacity, performance? | **HBOM** (host readers, PKCS#11/KMIP/REST, TPM) | You plan a hybrid TLS rollout that the payment HSM cannot execute; the migration dies at key generation |
| **Network** | What actually negotiates on the wire — TLS 1.3 hybrid groups, middleboxes, terminators, certificate chains? | **NBOM** (active probes + passive capture) | Client and server both support ML-KEM and a load balancer silently drops the ClientHello; nothing in your plan predicted it |
| **Vendor** | Who owns the code you cannot patch, and what have they committed to, by when? | **VBOM** (declarations, questionnaires, due diligence) | You plan for 100% of your estate and can actually change 40%; the rest is a contract negotiation you started too late |

**TechBOM is the join.** It is the only place where "this certificate on this load balancer, issued by
this CA, used by this application, running on this host, whose traffic passes through this HSM, built
from this supplier's library" exists as one row set. Without it, five accurate inventories do not add
up to one answer.

### 7.2 The five ways a single-plane plan fails

1. **Crypto-only** ("we know RSA-2048 is used in 1,412 places"): tells you the size of the problem and
   nothing about the order of work. It cannot tell you that 300 of those are in a vendor product you
   cannot modify, or that 47 terminate on an appliance whose firmware has no ML-KEM.
2. **Software-only** ("we upgraded BouncyCastle"): leaves the *deployed* population unchanged. A
   library that supports ML-KEM changes nothing if the TLS stack above it is pinned to `secp256r1` and
   the HSM below it cannot store the key.
3. **Hardware-only** ("we bought PQC-capable HSMs"): capability is not use. The HSM supports ML-DSA;
   the applications still call `RSA_sign`, and no inventory says which.
4. **Network-only** ("we enabled hybrid TLS on the perimeter"): covers the hop you can see. The
   internal re-encryption hop, the database TLS session and the service-mesh mTLS are still classical,
   and the NBOM's per-hop view is the only thing that shows it.
5. **Vendor-only** ("our suppliers say they are PQC-ready"): a declaration is not an observation. The
   platform records it as `VENDOR_DECLARED`, which is a legitimate fact about the declaration and
   never a fact about the deployment.

### 7.3 Mosca's inequality makes the omission expensive

Timing is `x + y > z` — data shelf-life plus migration time against time to a cryptographically
relevant quantum computer (`quantum/plan.py`). `x` and `z` are usually estimated. **`y` is the term
that hides the five planes**: migration time is set by the *slowest* of code, firmware, hardware
refresh and supplier delivery. A plan built on code alone produces an `y` that is too small — and
HNDL means the data being harvested today is judged against the wrong deadline.

### 7.4 The product measures its own honesty here

Because this argument drives investment decisions, the platform scores the rules against a planted
answer key (`docs/bank-environment/185-accuracy-ground-truth.md`). Against the same corpus:

| Metric | The fact rule | The `collector → CBOM` shortcut |
|---|---|---|
| algorithm precision / recall | 100% / 100% | **68.9% / 81.6%** |
| evidence attribution | 98.7% | **0%** |
| false-positive rate | 0% | **100%** |
| false-negative rate | 0.7% | 52.4% |

The shortcut is "a library can do AES-256-GCM, so the application uses it" — i.e. a CBOM built by
ignoring the distinction between capability and usage. Its precision collapses because, in a real
estate, *every* application ships a library that can do everything. That is the concrete reason the
five planes are kept apart in code and not just in prose.

---

## 8. Why the same six BOMs are the foundation for attack detection and threat intelligence

The BOMs are not an export format bolted on at the end. They are the **graph that makes an alert
mean something**, and the product already uses them that way.

### 8.1 Detection starts from a baseline, not from a rule

- Collectors observe continuously; the platform stores a baseline **once** and then only changes
  (`NO_CHANGE` writes nothing). A quiet estate and a stopped agent look identical, so connection age
  is stated on the surface rather than implied.
- Stored changes correlate into **attack patterns** (`shared_models/attack_patterns.py`): several
  independent changes in one window are grouped into a `CORRELATED_PATTERN` — the strongest statement
  the platform will make.
- **`MULTI_PLANE_AGREEMENT`** raises review priority when a change lands on a subject that two or more
  independent planes describe. **`PLANE_CONTRADICTION`** — one plane witnesses a subject another
  records as absent — is a finding about *evidence* (one collector has a narrower scope), not a
  verdict about the estate.
- **A collection gap outranks the activity inside it**: changes seen while a plane was blind are
  reported as *unattributable*, not as suspicious.

And it stops where it must: **the platform never assigns `SECURITY_INCIDENT`** (level 3). It has no
engagement, no authorisation and no external intelligence match, so promoting correlation to incident
would be inventing the one claim a bank cannot afford to inherit from a tool.

### 8.2 The BOMs are what turn an advisory into a work item

A threat-intel advisory says *"algorithm X is broken/withdrawn"*. That sentence becomes actionable
only when the estate can answer five follow-ups, which are exactly the six projections:

| Question the analyst asks | Which BOM answers it |
|---|---|
| Who uses X? | **CBOM** — assets, call sites, protocols, key sizes |
| Which version of which package carries it? | **SBOM** — component and version |
| What negotiates X on the wire right now? | **NBOM** — endpoint, negotiated version/cipher, certificate |
| Is X inside a device we cannot patch? | **HBOM** — firmware, algorithm capability, HSM/TPM |
| Whose code is it, and have they fixed it? | **VBOM** — supplier, declaration, due-diligence revision |
| What business service depends on all of the above? | **TechBOM** — the join, plus blast radius |

The platform already ships the ingestion half: `POST /api/v1/threat-intel/advisories/import` accepts
advisories as a **signed bundle** (the air-gap convention) or an admin list, idempotent per
`(source, advisory_id)`; `GET /threat-intel/algorithms/{algorithm}` gives the advisory picture for an
algorithm; `GET /threat-intel/assets/{asset_id}` is an **annotation-only** overlay — which advisories
name this asset's algorithm. Annotation only, because an advisory naming an algorithm is not a
finding that the asset is exposed.

### 8.3 Why PQC and detection are the same problem

HNDL is a *harvest-now, decrypt-later* threat: the compromise happens years before it is detectable
by decryption. That makes PQC readiness a detection problem (what is being protected, by what, for
how long) and detection a PQC problem (which traffic is classical today). Both are answered by the
same five planes, so the product refuses to build a second inventory for "security posture" — the
model in `docs/bank-environment/128-hardware-discovery.md` is explicit that a second inventory per
BOM type is the failure mode, and a test fails if one appears.

### 8.4 What a future SOC can build on top

Because every fact carries an evidence id, an observation class and a scope, a bank's SOC/UEBA can
consume findings via CEF, join them back to the snapshot, and apply its own behavioural analytics —
which is precisely the layer this product does **not** claim to be (§5.2). The boundary is the
feature: the platform supplies **reproducible, attributed, gap-aware facts**; correlation hunting,
incident declaration and response stay with the people who are authorised to make them.

---

## 9. Honest open items

Named here so no reader has to discover them by surprise:

1. **Estate-level coverage denominators** — per-component completeness exists; the join to the bank's
   own register does not.
2. **Identity confidence gate** — canonical identity with aliases and `UNRESOLVED_RELATIONSHIP`
   before a relationship is created.
3. **Parser qualification matrix** — every parser at ≥99% on malformed/duplicate/Unicode/huge/
   malicious input before qualification.
4. **A test that fails if a model enters the factual path** — the boundary is enforced at runtime
   (`ai_boundary.py`) but not asserted at build time.
5. **PITR** — not provided, pending physical base backup + WAL archive.
6. **Windows collector, complete hardware discovery, HSM operations, runtime invocation proof,
   generic simulation** — the five `capability_boundaries` statements, each with its own route.
7. **Real-bank measurement** — the first honest accuracy number comes from a bank, not from a corpus.
8. **Scheduled workflows** — the restore drill and the accuracy gate are generated
   (`scripts/pending_workflows.py`) and need a token with `workflows` permission to land in
   `.github/workflows/`.

---

## 10. Where to check any claim in this document

| Claim | Check it at |
|---|---|
| What the platform is / is not (machine-readable) | `GET /api/v1/platform/scope`, `shared_models/platform_scope.py` |
| The five non-operational capabilities | `GET /api/v1/estate/evidence/discovery/maturity`, `shared_models/capability_boundaries.py` |
| Every console surface + its stated limit | `GET /api/v1/platform/capabilities`, `docs/CAPABILITY-MATURITY.md` |
| Six BOMs and their projection | `GET /api/v1/estate/evidence/boms/{kind}/export`, `shared_models/estate_graph.py` |
| Capability vs usage, conflicts, absence states | `services/cbom/cbom/facts.py` + `services/cbom/tests/test_facts.py` |
| Accuracy and its gate | `scripts/accuracy_ground_truth.py`, `docs/bank-environment/185-*` |
| Quantum risk and Mosca planning | `services/quantum/risk.py`, `plan.py`, `GET /api/v1/quantum/*` |
| Threat-intel advisories | `services/api/api/routers/threat_intel.py` |
| Attack patterns and their refusals | `shared_models/attack_patterns.py` |
| Policy packs (and "no AI") | `docs/CAPABILITY-MATURITY.md`, `shared_models/platform_scope.py` |
| AI-execution boundary | `services/api/api/security/ai_boundary.py`, `deploy/ebpf/execve_trace.py` |
| Restore drill and PITR refusal | `scripts/restore_drill.py`, `docs/bank-environment/184-security-control-layer.md` |
| OT passivity | `services/network_scanner/network_scanner/passive/ot_protocols.py`, `services/ot_scanner/` |
| The bank-facing operating model | `docs/bank-environment/README.md` (guides 1–185) |
| Comparison against real-world tools | `docs/architecture/real-world-comparison.md` |
