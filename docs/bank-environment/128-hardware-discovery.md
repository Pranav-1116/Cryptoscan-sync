# Hardware discovery — from collectors to a twin, not to a second inventory

`cryptoscan.hardware-discovery/1` · generated 2026-11-02T12:05:02.558406+00:00 · **6 pass · 1 partial · 0 fail**

The review this answers set one architectural rule above all others: hardware is not an independent scanner that emits an HBOM. Collectors feed an evidence engine; the evidence engine feeds the canonical estate; the estate feeds the digital twin; and HBOM, CBOM, NBOM and TechBOM are **projections of that one truth**. A second inventory per BOM document type is the failure mode, and the `single_source_of_truth` row below fails if one appears.

```
        Linux      Windows      Network      HSM/TPM
          │           │            │            │
          └───────────┴─────┬──────┴────────────┘
                            ▼
                     Evidence engine
                            ▼
                    Canonical estate
                            ▼
                     Digital twin
                ┌───────────┼───────────┐
               HBOM        CBOM        NBOM / TechBOM
```

| Phase | Question | Verdict | What was measured |
|---|---|---|---|
| hardware foundation — identity, fact schema, evidence | **is there a hardware fact schema and a stable identity behind it?** | **PASS** | 9 probe(s), all passing |
| collectors — Linux, Windows, network | **do collectors exist for the estate a bank actually has, and does each emit fields?** | **PARTIAL** | 22 probe(s), failing: windows-reader |
| security hardware — HSM and TPM | **is HSM/TPM discovery deep enough to be worth anything, and can it leak a key?** | **PASS** | 5 probe(s), all passing |
| correlation — evidence-backed relationships | **is a hardware dependency proven by evidence, or assumed because both exist?** | **PASS** | 5 probe(s), all passing |
| drift — firmware, capability, PQC | **does hardware drift name what moved — firmware, capability, PQC — or just that something did?** | **PASS** | 6 probe(s), all passing |
| qualification — a synthetic bank estate | **does any of it survive a synthetic bank-sized estate?** | **PASS** | 4 probe(s), all passing |
| one truth, multiple projections | **is HBOM a projection of the estate, or a second inventory?** | **PASS** | 3 probe(s), all passing |

## How the review's pieces map to the tree

Every box in the diagram above is a module, and the mapping is the point: a review that is answered by prose and not by a call path is not answered. Paths are relative to the repository root.

| Review piece | Where it lives | State |
|---|---|---|
| collectors (Linux, Windows, network, vendor) | `universal_vendor/hardware/plugins/` — 9 modules, 30 vendor plugins; `hardware/discovery.py` — three discovery methods | schema complete |
| the Linux reader | `hardware/host/linux.py` — `/sys` allowlist, dmidecode, lsblk, lspci, smartctl through an argv allowlist | built, executed here |
| the Windows reader | — | **not built**; WMI/CIM is the gap |
| the network transports | `hardware/host/snmp_bridge.py` over the network scanner's SNMPv2c client (`enterprise/vendors/snmp.py`, now with ENTITY-MIB); `hardware/host/netconf.py` and `hardware/host/restconf.py` for the devices that do not answer SNMP | built, executed here; all three produce one `NetworkDeviceFacts` and one observation projection |
| identity + confidence | `hardware/identity.py` (signals, `first_seen`/`last_seen`), `hardware/fingerprint.py` | deterministic; confidence follows corroboration |
| evidence engine | `hardware/fingerprint.py` — per-source weights; `universal_vendor/evidence.py` — content-hash chain; `HardwareObservation` keeps `discovery_sources` and `identity_conflicts` | every contributing source stays visible, conflicts are uncertainty not overwrite |
| canonical estate | `hardware/models.py` — `HardwareObservation`, 32 device types, `CryptoCapability` | one schema for every device class |
| digital twin | `hardware/hbom.py` versioned snapshots over observations | no table of its own |
| HBOM / CBOM / NBOM / TechBOM | `services/api/api/estate_bom_sources.py`, `bom_maturity.py`, `routers/hbom.py` | projections, not inventories |
| relationships | `hardware/relationships.py` | evidence required to form an edge |
| drift | `hardware/drift.py`, `hardware/live/events.py` | firmware, capability, PQC |
| safety | `hardware/safety.py` — `refuse_secret_material` | raises, never asserts |
| HSM / TPM depth | `hardware/hsm_hw.py`, `hardware/tpm.py` | metadata only |
| HSM *usage* (a different question) | `services/api/api/hsm_usage.py` — KMIP, spec 67 §17 | read-only, no `Get` |

## What a collector may observe

The review drew a line, and it is enforced by code rather than by a promise in a README. Both scanners refuse the whole payload on a single forbidden token, and the refusal is an exception (`SecretMaterialRefused`), so `python -O` cannot compile the guard away — a probe below runs the same payload under `-O` to prove it.

| Device | Collected | Never collected |
|---|---|---|
| HSM | vendor, model, serial reference, firmware, cluster, HA state, partition *counts*, algorithm capabilities incl. ML-KEM/ML-DSA, key **type and usage** metadata, certificate dependencies | private keys, key material, PINs, SO/partition passwords, credentials, plaintext blobs |
| TPM | presence, version, manufacturer, firmware, capabilities, PCR metadata, secure-boot relationship | seeds, private keys, owner auth values, PCR *values* beyond the metadata the review asked for |
| evidence pointers | a location — file path, API route, device identifier | a value: a reference naming `password`/`secret`/`key_material` is refused |

## Security blockers

| Blocker | How it is held | Where it is proven |
|---|---|---|
| minimized privilege | plugin contract is `read_only = True`; collectors receive a context dict, they do not dial out on their own | this artifact, rows `collectors-exist` and `security_hardware` |
| allowlisted commands only, no arbitrary shell | no shell sink in the platform's 91 argv-list call sites; argument injection closed on `ssh-keyscan`, `git clone`, `docker pull` | [guide 122](122-command-execution.md) |
| no hardware credentials, keys or plaintext in output | `refuse_secret_material` + `scrub_secrets` on vendor-specific payloads | this artifact, `secret-material-refused` and `guard-survives-python-O` |
| mTLS agent identity | peer certificate read from a real handshake, SPKI bound to a registered agent, observation signature must match | [guide 124](124-agent-identity.md) |
| evidence first, relationship second | an edge without a citation raises `UnevidencedRelationship`; edge confidence is the weakest citation | this artifact, `evidence_relationships` |
| tenant isolation | forced row-level policies on tenant tables | [guide 126](126-tenant-isolation.md) |

## The phase plan, honestly

| Phase | Scope | State |
|---|---|---|
| H1 | fact schema, identity, fingerprint, safety | built, executed here |
| H2 | Linux: `/sys`, dmidecode, `lsblk`, `lspci`, `smartctl`, `/dev` validation | built, executed here — allowlisted argv only, `shell=False`, refusals tested |
| H3 | Windows: WMI/CIM, TPM APIs, never a PowerShell string built from input | **not built** |
| H4 | HSM depth per vendor: PKCS#11 attributes, KMIP `Query`, vendor REST | observation fields built; readers not |
| H5 | network hardware: SNMP/NETCONF/REST per authorized class | built end to end on all three — SNMP/ENTITY-MIB, NETCONF `ietf-hardware`, RESTCONF `ietf-hardware`; vendor-specific YANG models not read |
| H6 | correlation: evidence-backed relationships, blast radius | built, executed here |
| H7 | drift: firmware, crypto capability, PQC, correlated with cert/app/policy change | built, executed here |
| H8 | qualification against a real bank estate | synthetic only; precision and recall need ground truth |

## Row by row

### `hardware_foundation` — PASS

*is there a hardware fact schema and a stable identity behind it?* (phase H1)

- **PASS** `taxonomy-compute` — 6 required compute types present: ['server', 'blade_server', 'hypervisor_host', 'virtualization', 'gpu', 'accelerator']
- **PASS** `taxonomy-network` — 5 required network types present: ['router', 'switch', 'firewall', 'load_balancer', 'network_appliance']
- **PASS** `taxonomy-security` — 4 required security types present: ['hsm', 'tpm', 'smart_card', 'security_appliance']
- **PASS** `taxonomy-storage` — 4 required storage types present: ['san', 'nas', 'raid_controller', 'storage_appliance']
- **PASS** `taxonomy-infrastructure` — 4 required infrastructure types present: ['iot_gateway', 'industrial_controller', 'plc', 'ot_appliance']
- **PASS** `taxonomy-vendor-neutral` — 32 hardware types in the catalogue
- **PASS** `fingerprint-is-deterministic` — two identical observations produced identical fingerprints (confidence HIGH)
- **PASS** `serial-separates-identical-models` — two identical models with different serials are two assets
- **PASS** `confidence-follows-corroboration` — three corroborating sources outrank one weak source

### `collector_breadth` — PARTIAL

*do collectors exist for the estate a bank actually has, and does each emit fields?* (phase H2/H3/H5)

- **PASS** `collectors-exist` — 9 collector module(s): ['gpu', 'hsm', 'industrial', 'iot', 'network', 'server', 'storage', 'tpm', 'virtualization']
- **PASS** `collector-server-identity` — DMI identity reached the record: ['manufacturer', 'model', 'serial_reference', 'firmware']
- **PASS** `collector-server-memory-disk` — memory and disk inventory from the agent reached the record: ['memory', 'disk']
- **PASS** `collector-gpu` — GPU inventory reached the record: ['model', 'memory']
- **PASS** `collector-virtualization` — hypervisor inventory reached the record: ['cluster', 'guests']
- **PASS** `collector-tpm` — TPM metadata reached the record: ['pcr', 'secure_boot']
- **PASS** `collector-network` — network inventory and TLS posture reached the record: ['serial', 'firmware', 'tls']
- **PASS** `collector-storage` — storage inventory and encryption state reached the record: ['serial', 'firmware', 'disk_encryption']
- **PASS** `linux-reader-reads-sysfs` — the Linux reader took manufacturer, serial and 2 interface(s) straight from a sysfs tree, with no binary involved
- **PASS** `linux-reader-parses-allowlisted-commands` — 1 memory module(s), 2 disk(s), SMART health and 1 PCI device(s) from 5 command(s): ['dmidecode', 'lsblk', 'smartctl', 'smartctl', 'lspci']
- **PASS** `linux-reader-refuses-arbitrary-commands` — a shell, a metacharacter argument, a traversal device path and a non-device file were all refused (4/4)
- **PASS** `linux-reader-runs-no-shell` — the only subprocess call site passes an argv list with shell=False
- **FAIL** `windows-reader` — no WMI/CIM reader anywhere in the tree: on Windows the collectors still wait for a caller to supply the context
- **PASS** `snmp-reads-a-switch` — a switch resolved to Cisco C9300-48P serial FDO2140A1B2 firmware 17.9.4a from ENTITY-MIB over a real BER walk (19 request(s))
- **PASS** `snmp-credential-is-not-inventory` — the community string is used and dropped; the fact record carries no credential reference
- **PASS** `snmp-feeds-the-estate` — the same device becomes a canonical switch observation with its serial, firmware and TLS-termination seam, not a second network inventory
- **PASS** `snmp-refuses-a-credential-echo` — a device that echoes the community string in sysDescr is refused rather than inventoried
- **PASS** `netconf-reads-a-firewall` — a firewall resolved to Cisco C9300-48P, serial FDO2140A1B2, firmware 17.9.4a over a negotiated NETCONF session (2 exchange(s))
- **PASS** `netconf-is-read-only` — the only RPC this collector can send is a read-only <get>; there is no edit-config path in the module to misuse
- **PASS** `restconf-reads-a-switch` — a switch resolved to Juniper EX4300-48T, serial JNP-7788 over RESTCONF and projected through the same observation path as SNMP
- **PASS** `restconf-refuses-cleartext` — an http:// device URL is refused: a bank's inventory is not read over cleartext
- **PASS** `netconf-refuses-a-credential-echo` — a device that echoes the credential in a field the collector carries is refused, not inventoried

### `security_hardware` — PASS

*is HSM/TPM discovery deep enough to be worth anything, and can it leak a key?* (phase H4)

- **PASS** `hsm-observation-depth` — the HSM observation carries 12 field(s) the review asked for, including cluster, HA state and PQC algorithms
- **PASS** `tpm-observation-depth` — the TPM observation carries 8 field(s), including PCR and secure-boot relationships
- **PASS** `secret-material-refused` — an HSM payload carrying private_key was refused with SecretMaterialRefused
- **PASS** `guard-survives-python-O` — the same refusal happens under `python -O`, where an assert is compiled out
- **PASS** `observation-carries-no-key-material` — the rendered HSM observation contains no key material

### `evidence_relationships` — PASS

*is a hardware dependency proven by evidence, or assumed because both exist?* (phase H6)

- **PASS** `config-evidence-produces-an-edge` — a PKCS#11 token line produced payment-api -USES_HSM-> HSM-01
- **PASS** `confidence-is-the-weakest-citation` — a config edge corroborated only by a CMDB row reports MEDIUM, not HIGH
- **PASS** `an-unevidenced-edge-is-refused` — asking for an edge with no record raises UnevidencedRelationship
- **PASS** `evidence-pointer-cannot-carry-a-secret` — an evidence reference naming a password is refused: the pointer is a location, not a value
- **PASS** `blast-radius-walks-evidenced-edges` — HSM-01 failure reaches 1 application(s), 1 system(s), and the flow(s) ['card-authorisation']

### `hardware_drift` — PASS

*does hardware drift name what moved — firmware, capability, PQC — or just that something did?* (phase H7)

- **PASS** `firmware-change-is-its-own-event` — a firmware bump produces FIRMWARE_CHANGED and nothing else (not a replacement)
- **PASS** `model-change-is-a-replacement` — a different model is classified REPLACEMENT, not a firmware bump
- **PASS** `pqc-capability-arrives-as-its-own-row` — adding ML-DSA-65 produced ['CRYPTO_CAPABILITY_CHANGED', 'PQC_CAPABILITY_ADDED', 'HSM_CAPABILITY_CHANGED']
- **PASS** `losing-pqc-capability-is-high-severity` — losing ML-KEM-768 is PQC_CAPABILITY_REMOVED at HIGH severity — a capability that disappeared is an incident, not a tidy-up
- **PASS** `spelling-is-not-a-change` — the same algorithms written differently produce no events
- **PASS** `two-assets-are-never-one-history` — diffing two different assets is refused rather than producing a confidently wrong change log

### `qualification` — PASS

*does any of it survive a synthetic bank-sized estate?* (phase H8)

- **PASS** `synthetic-estate-projects` — 600 synthetic hardware assets across 4 vendors and 6 device types, projected in 0.01s
- **PASS** `identity-does-not-collide` — 600 distinct identities from 600 observations (serial is the key, and it held)
- **PASS** `drift-scales-with-change-not-with-estate` — 400 change event(s) from 120 upgraded assets in an estate of 600: per-device-type counts {'firewall': 3, 'hsm': 4, 'load_balancer': 3, 'san': 3, 'server': 3, 'tpm': 4}, and no record named an asset that did not change (0 leaked)
- **PASS** `a-missing-observation-is-not-a-deletion` — identity is retained across observations; an asset that is not re-observed is not silently removed (retirement is its own decision)

Measured: `{"assets": 600, "vendors": 4, "device_types": 6, "changes": 400, "seconds": 0.007}`

### `single_source_of_truth` — PASS

*is HBOM a projection of the estate, or a second inventory?* (phase architecture)

- **PASS** `hbom-owns-no-table` — HBOM is generated from observations and holds no table of its own
- **PASS** `bom-projections-read-the-estate` — 3 projection module(s) read the estate rather than keeping a second inventory
- **PASS** `one-hardware-table-family` — 3 hardware table(s): state, event journal, agent health — one truth, not a BOM per document type

## The negative control

The executable rows re-run against a copy of the package with three guards removed. Each removal must make at least one probe in the row that watches for it fail:

| Removed guard | Row | Result |
|---|---|---|
| the secret-material guard becomes a no-op | `security_hardware` | caught — secret-material-refused, guard-survives-python-O |
| an edge no longer needs evidence | `evidence_relationships` | caught — an-unevidenced-edge-is-refused |
| post-quantum algorithms stop being distinguished | `hardware_drift` | caught — pqc-capability-arrives-as-its-own-row, losing-pqc-capability-is-high-severity |

Every injected defect was caught.

## What this does not prove

- no bank hardware was touched: every HSM and TPM here is a synthetic payload, and no appliance, hypervisor or network device was contacted
- collector breadth feeds each collector a synthetic payload and drives the Linux reader against a fixture sysfs tree and a recorded transcript; no bank host was read, and real hosts differ — dmidecode absent, root denied, vendor quirks its allowlist has not seen
- the Linux reader is unprivileged by design, so on a hardened host its memory, disk-health and PCI facts degrade to `unavailable` reasons rather than to data
- the SNMP row runs against a fake socket and NETCONF/RESTCONF against scripted replies: no appliance was contacted, and a real device's ENTITY-MIB or `ietf-hardware` model may be sparse, vendor-extended or absent entirely
- only the standard YANG models are read (`ietf-system`, `ietf-hardware`): vendor models expose extra facts — licence state, HA role, crypto policy — that this artifact does not collect
- the synthetic estate measures identity, drift volume and runtime, not discovery precision or recall against real vendor firmware
- encryption at rest, per-tenant key custody and vendor attestation are outside this artifact entirely

## What I would build next, in the order the review proposed

The PASS rows are the parts already in the tree; the PARTIAL and FAIL rows name what is not, probe by probe. In order:

1. **H3 the Windows reader** — the probe that still fails. WMI/CIM is not a PowerShell string built from input: fixed classes (`Win32_ComputerSystem`, `Win32_DiskDrive`, `Win32_PhysicalMemory`), a fixed argv to a fixed helper, the same allowlist discipline as the Linux reader, and the TPM APIs read through the OS surface rather than a vendor tool. It must be tested on Windows, which no CI here can do — so it will ship with the gap stated, not with a green row.
2. **Vendor YANG and vendor REST models** — the standard `ietf-hardware` model carries serial, model and firmware; it does not carry HA role, licence state or crypto policy. Those live in vendor models (`Cisco-IOS-XE-*`, `junos-*`), and each one needs its own parser and its own negative control before it is trusted.
3. **H4 HSM depth per vendor** — partition, cluster and HA state are in the observation model; what is missing is a reader per vendor (PKCS#11 attributes, KMIP `Query`, vendor REST) and a burn-in against each.
4. **H6 correlation for network hardware** — a switch is now in the estate, but nothing links it to the certificates it terminates or the flows it carries; the relationship engine can express that edge and has no network evidence source feeding it yet.
5. **H8 qualification against a real bank estate** — the synthetic run above is a floor. Precision and recall need ground truth only a customer can provide.

**The verdict this artifact supports:** the hardware foundation, the identity model, the security-hardware metadata model, the evidence rule for relationships and the drift vocabulary are implemented and executed here, and the projection architecture the review asked for is the one in the code. What is *not* done is collector reach into Windows and hypervisor estates, per-vendor HSM readers, vendor YANG models, and a run against real hardware — the Linux reader is driven by a fixture and a transcript, the SNMP walk by a fake socket, and NETCONF and RESTCONF by scripted replies. Each is named above rather than folded into the score.
