# HBOM review, 2026-11-03 — as received, and what this round does with it

The review that arrived for the hardware layer, kept as the record of the argument rather
than a summary of the answer. Guide 167 (`docs/bank-environment/167-hbom.md`,
`cbom.hbom_graph`) is the implementation; guide 164 (`cbom.techbom`) is the graph it
projects into, and guide 166 (`cbom.techbom_estate`) is the adapter from the stored
inventory. The table at the end is ownership, not approval.

## The line the review draws

A server is not a row. An HSM is not a vendor and a model. And an HBOM is not a fourth
database beside the SBOM, CBOM, NBOM and VBOM — it is the **hardware view of one estate
graph**:

```
Collectors → Evidence → Canonical Asset Identity → Digital Twin / Estate Graph
                                                        │
                                        ┌───────────────┼───────────────┐
                                        ▼               ▼               ▼
                                      SBOM            CBOM            HBOM
                                        │               │               │
                                        └───────────────┼───────────────┘
                                                        ▼
                                                      NBOM
                                                        │
                                                      VBOM
```

The same hardware asset therefore appears consistently in HBOM, TechBOM, the CBOM
relationships, the NBOM path and the vendor view — because there is one identity, not five.

## Point by point, as received

1. **Physical hardware discovery is incomplete.** The hardware model has to be a device
   tree, not a row: `Server → CPU, Memory, Motherboard, BIOS, Firmware, TPM, NIC, Storage,
   RAID controller, GPU, PCI devices, Crypto accelerator, HSM`, and each asset needs
   `asset_id, asset_type, manufacturer, model, serial_number, part_number,
   firmware_version, bios_version, hardware_revision, location, datacenter, rack, slot,
   owner, environment, status, first_seen, last_seen, evidence_id`. CycloneDX's hardware
   model also carries manufacturer, serial number, SKU, location and certifications.
2. **HSM is the biggest HBOM gap.** `HSM-001 / Vendor: X / Model: Y` is not an HSM. An HSM
   needs vendor, product, model, firmware, cluster, HA members, partitions, supported
   algorithms, key types, key sizes, crypto operations, certificates, applications and
   systems. **Never collect private keys, key material or plaintext — only metadata and key
   references.**
3. **Hardware → software is missing or weak.** `Business System → Application → Process →
   Host → Hardware` (e.g. `Payments System → Payments API → payments-api process →
   BANK-SRV-001 → CPU / NIC / TPM / HSM`), and every relationship carries evidence.
4. **Hardware → crypto is critical.** `HSM SUPPORTS RSA-2048`, `HSM PERFORMS RSA-SIGN`,
   `Payment API USES HSM`, `Payment API USES RSA-2048`, `RSA-2048 PROTECTED_BY HSM`.
   *"HSM supports RSA" is not "the application uses RSA"* — those are different facts, and
   the evidence classes have to show it: `CAPABILITY, CONFIGURED, OBSERVED,
   RUNTIME_OBSERVED, NETWORK_OBSERVED, IMPORTED, VENDOR_DECLARED, UNKNOWN`.
5. **Hardware → vendor must go deeper.** `Vendor → Product → Model → Firmware → Physical
   Asset → Application/System`, so firmware EOL, a vendor vulnerability announcement, a
   dropped algorithm, new PQC support, a required upgrade or a retired model all become a
   blast radius rather than a note.
6. **Hardware → network is missing.** Network hardware belongs in the HBOM:
   `Internet → Firewall → WAF → Load Balancer → API Gateway → Application Server → HSM →
   Database`, and each device carries IP, MAC, interface, VLAN, zone, subnet, routing, HA
   role, firmware, vendor, model, TLS capability, certificate and HSM reference, so HBOM
   and NBOM can correlate.
7. **Hardware → business system is weak** — and it is the most valuable relationship.
   `Payment System → Payments API → Application Server → HSM → Firmware → Vendor` turns
   "HSM firmware outdated" into *1 HSM, 3 applications, 2 business systems, 7 cryptographic
   assets, 2 network paths affected*.
8. **Firmware must be first-class.** Hardware → firmware → version → release date →
   security status → EOL/EOS → known vulnerabilities, with the affected set named.
9. **Hardware drift is incomplete.** `CPU_CHANGED, RAM_CHANGED, NIC_CHANGED,
   FIRMWARE_CHANGED, BIOS_CHANGED, TPM_CHANGED, HSM_FIRMWARE_CHANGED,
   HSM_CONFIGURATION_CHANGED, DEVICE_ADDED, DEVICE_REMOVED, DEVICE_REPLACED,
   NETWORK_INTERFACE_CHANGED` — and drift has to be correlated with crypto impact.
10. **Stable hardware identity matters.** Not hostname, IP or MAC: a canonical id such as
    `ASSET-HW-928182` with identity evidence (manufacturer, model, serial, asset tag,
    firmware, location, device identifiers). An IP moving from `10.10.1.20` to
    `10.10.1.45` must not create a new hardware asset.
11. **Virtual hardware needs correlation.** `Physical Host → Hypervisor → VM → OS →
    Application`; for cloud, `Cloud Account → Region → Instance → vCPU / vNIC / Disk →
    Application`.
12. **Container/Kubernetes relationships.** `Physical Host → VM → Kubernetes Node → Pod →
    Container → Process`, then `Container → Crypto library → Crypto operation → HSM`,
    without pretending a container is physical hardware.
13. **The evidence model needs improvement.** Every fact answers *how do you know this
    hardware exists*: `evidence_id, collector, collector_version, target_id, observed_at,
    source, evidence_type, raw_reference, normalized_fact, hash, confidence`.
14. **Coverage must be explicit.** Not "120 hardware assets discovered" but expected 200,
    collected 120, unavailable 50, permission denied 20, unknown 10 → `PARTIAL`.
15. **HBOM must correlate with the other BOMs** — HBOM → CBOM → SBOM → application → NBOM
    → VBOM, with BOM-Link able to connect separate documents.
16. **HBOM must not become another source of truth.** Not five databases with independent
    relationships but `Collectors → Evidence → Canonical Asset Identity → Digital Twin →
    HBOM projection`.

## Where each point lives now

| # | Point | Where it lives now |
|---|---|---|
| 1 | The device is a tree, with the full field set | guide 167 `hardware()` + `device()`; kinds `CPU, MEMORY, MOTHERBOARD, BIOS, NIC, STORAGE, RAID_CONTROLLER, GPU, PCI_DEVICE, CRYPTO_ACCELERATOR, TPM, HSM` and `HAS_COMPONENT` / `RUNS_BIOS`; `unknown_fields` names every field the collector did not supply |
| 2 | HSM depth | `hsm()` — vendor, product, model, firmware, `HSM_CLUSTER`, HA members, `HSM_PARTITION`, capabilities, key types, key sizes, operations, certificates, applications, systems |
| 3 | Hardware → software | `RUNS_ON` (`PROCESS`/`APPLICATION` → `HOST`/`VM`/`KUBERNETES_NODE`/`CLOUD_INSTANCE`), `RUNS_APPLICATION` (`OS` → `APPLICATION`), `SCHEDULED_ON`; every edge a claim with a basis |
| 4 | Hardware → crypto, capability ≠ use | `SUPPORTS` (capability) vs `PERFORMS` (an operation happened) vs `USES_CRYPTO`/`USES_HSM` (the application uses it) vs `PROTECTED_BY` (the key is held there); `RELATION_MIN_CONFIDENCE` refuses a `PERFORMS` claim a datasheet cannot carry |
| 5 | Vendor depth | `VENDOR → VENDOR_PRODUCT → FIRMWARE → asset → application → system` via `HAS_MODEL`, `SUPPLIED_BY`, `RUNS_FIRMWARE`, `USES_HSM`, `OWNS`; `impact()` walks it back |
| 6 | Network hardware | `FIREWALL`, `NETWORK_SEGMENT`, `NIC ATTACHED_TO`, `firmware`/`vendor`/`model` on the device, `FORWARDS_TO` from the firewall, TLS capability on the endpoint — HBOM and NBOM share the graph |
| 7 | Business mapping | `blast_radius`/`impact` over the same graph, reported in the review's units (HSMs, applications, business systems, crypto assets, network paths) |
| 8 | Firmware first-class | `firmware()` with release date, `SUPPORTED`/`EOL`/`EOS`, `HAS_VULNERABILITY`, `RUNS_FIRMWARE` from every device that runs one |
| 9 | Drift | `drift()` — the review's twelve change types, `HARDWARE_DRIFT` as the category, and a crypto-impact block per change |
| 10 | Identity | `identity()` — `ASSET-HW-…` from manufacturer/model/serial or asset tag; network identifiers are refused as anchors and reported as `ignored`; a rename or a new IP is `NETWORK_INTERFACE_CHANGED`, not a new device |
| 11 | Virtual and cloud | `PHYSICAL_SERVER → HYPERVISOR → VM → OS → APPLICATION`, `CLOUD_INSTANCE → IN_REGION → CLOUD_REGION → IN_ACCOUNT → CLOUD_ACCOUNT` |
| 12 | Containers | `RUNS_HYPERVISOR`/`HOSTS_OS`/`SCHEDULED_ON` → `POD` → `PROCESS` → `LOADS` → `CRYPTO_LIBRARY`; a container is never given a hardware substrate it cannot prove |
| 13 | Evidence register | `evidence()` — collector, version, target, observed_at, source, type, raw reference, normalized fact, hash, confidence; `build()` refuses an evidence record without a hash |
| 14 | Coverage | `coverage()` — expected / collected / unavailable / permission denied / unknown, with `COVERAGE_DOES_NOT_RECONCILE` when the buckets do not add up |
| 15 | Cross-BOM correlation | `correlate()` — one hardware asset walked into its CBOM algorithm, SBOM library, application, NBOM endpoint and VBOM vendor |
| 16 | Not a source of truth | `build()` takes a canonical estate, `from_document()` refuses an HBOM or a TechBOM, and there is no second table |

A second read of the same text, line by line, found nine more things the first pass had
answered only in prose — device metadata, the review's direction of "runs", the two
evidence classes, product lifecycle, network appliances with all fourteen facts, the
review's sentence as a number, `DEVICE_REPLACED`, evidence as nodes, and the certificates
an HSM holds. Each is now built, and guide 168
(`docs/bank-environment/168-hbom-gaps.md`, **9 pass · 0 partial · 0 fail**) measures it.

## Scope decisions taken here

- **A hardware asset is a typed node in the one graph, never a row in a hardware table.**
  The HBOM document is rendered from the estate at read time, like the TechBOM, so an HSM
  cannot have one identity in HBOM and another in the CBOM relationship that names it.
- **The device field set is declared, not assumed.** A collector that sees a serial number
  and a model but no BIOS version records what it saw; `unknown_fields` lists the rest, and
  the coverage block counts them per field. A missing field is a fact about the collector,
  and hiding it is how a BOM becomes fiction.
- **Capability and use are separated by relation, not by prose.** `SUPPORTS` ends at a
  `CRYPTO_CAPABILITY`, `PERFORMS` needs at least `CONFIGURED` evidence, and
  `APPLICATION → CRYPTO_ASSET` stays `USES_CRYPTO` with the evidence class that produced
  it. A vendor datasheet can never become "the application uses RSA".
- **Key material is refused at the door.** Attribute names and values are scanned; a
  private key, a plaintext or a wrapped key is refused by name with
  `KEY_MATERIAL_REFUSED`, and what stays is a key *reference* — `HOLDS_KEY` was already
  the shape of that claim, and it is not given new powers here.
- **Identity is evidence, not a hostname.** A device whose only identifiers are a
  hostname, an IP and a MAC gets a **provisional** id and says so, because the next DHCP
  lease would otherwise mint a new server.
- **Coverage is a reconciliation, not a count.** The buckets have to add up to the
  expected number or the block refuses, because a coverage percentage computed from
  numbers that do not reconcile is worse than no percentage.
