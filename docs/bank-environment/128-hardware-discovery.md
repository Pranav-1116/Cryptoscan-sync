# Hardware discovery — from collectors to a twin, not to a second inventory

`cryptoscan.hardware-discovery/1` · generated 2026-11-02T12:55:21.210221+00:00 · **7 pass · 0 partial · 0 fail**

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
| collectors — Linux, Windows, network | **do collectors exist for the estate a bank actually has, and does each emit fields?** | **PASS** | 25 probe(s), all passing |
| security hardware — HSM and TPM | **is HSM/TPM discovery deep enough to be worth anything, and can it leak a key?** | **PASS** | 15 probe(s), all passing |
| correlation — evidence-backed relationships | **is a hardware dependency proven by evidence, or assumed because both exist?** | **PASS** | 10 probe(s), all passing |
| drift — firmware, capability, PQC | **does hardware drift name what moved — firmware, capability, PQC — or just that something did?** | **PASS** | 14 probe(s), all passing |
| qualification — a synthetic bank estate | **does any of it survive a synthetic bank-sized estate?** | **PASS** | 4 probe(s), all passing |
| one truth, multiple projections | **is HBOM a projection of the estate, or a second inventory?** | **PASS** | 3 probe(s), all passing |

## How the review's pieces map to the tree

Every box in the diagram above is a module, and the mapping is the point: a review that is answered by prose and not by a call path is not answered. Paths are relative to the repository root.

| Review piece | Where it lives | State |
|---|---|---|
| collectors (Linux, Windows, network, vendor) | `universal_vendor/hardware/plugins/` — 9 modules, 30 vendor plugins; `hardware/discovery.py` — three discovery methods | schema complete |
| the Linux reader | `hardware/host/linux.py` — `/sys` allowlist, dmidecode, lsblk, lspci, smartctl through an argv allowlist | built, executed here |
| the Windows reader | `hardware/host/windows.py` — `Get-CimInstance` over eight allowlisted classes, named properties only, argv list with `shell=False` | built, executed here against a recorded CIM transcript; no Windows host was available |
| the network transports | `hardware/host/snmp_bridge.py` over the network scanner's SNMPv2c client (`enterprise/vendors/snmp.py`, now with ENTITY-MIB); `hardware/host/netconf.py` and `hardware/host/restconf.py` for the devices that do not answer SNMP | built, executed here; all three produce one `NetworkDeviceFacts` and one observation projection |
| identity + confidence | `hardware/identity.py` (signals, `first_seen`/`last_seen`), `hardware/fingerprint.py` | deterministic; confidence follows corroboration |
| evidence engine | `hardware/fingerprint.py` — per-source weights; `universal_vendor/evidence.py` — content-hash chain; `HardwareObservation` keeps `discovery_sources` and `identity_conflicts` | every contributing source stays visible, conflicts are uncertainty not overwrite |
| canonical estate | `hardware/models.py` — `HardwareObservation`, 32 device types, `CryptoCapability` | one schema for every device class |
| digital twin | `hardware/hbom.py` versioned snapshots over observations | no table of its own |
| HBOM / CBOM / NBOM / TechBOM | `services/api/api/estate_bom_sources.py`, `bom_maturity.py`, `routers/hbom.py` | projections, not inventories |
| relationships | `hardware/relationships.py` | evidence required to form an edge |
| network correlation | `hardware/network_correlation.py` — a device to the certificates it terminates, and to the HSM its config names | built, executed here |
| drift | `hardware/drift.py`, `hardware/live/events.py` | firmware, capability, PQC |
| drift correlation | `hardware/change_correlation.py` — a hardware change beside certificate/app/policy movement in the same window, and the PQC adoption question; `hardware/live/change_feed.py` puts every drift row on the live event bus and fills the correlation window from the pipeline | built, executed here |
| safety | `hardware/safety.py` — `refuse_secret_material` | raises, never asserts |
| HSM / TPM depth | `hardware/hsm_hw.py`, `hardware/tpm.py` | metadata only |
| HSM readers | `hardware/hsm_readers/pkcs11.py` (CK_TOKEN_INFO + mechanisms, PIN never on argv), `hardware/hsm_readers/kmip_query.py` (Query: vendor, operations, objects, profiles), `hardware/hsm_readers/rest.py` (documented vendor REST: a manifest per vendor with a citation per endpoint, refused for vendors whose documentation was not read) | built, executed here against recorded replies |
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
| H3 | Windows: WMI/CIM, TPM APIs, never a PowerShell string built from input | built, executed here against a recorded CIM transcript and a closed class allowlist; not yet run on a Windows host |
| H4 | HSM depth per vendor: PKCS#11 attributes, KMIP `Query`, vendor REST | built and executed here for PKCS#11, KMIP `Query` and one documented REST manifest (Thales Luna); Utimaco, Entrust nShield and Fortanix DSM are named as undocumented rather than guessed |
| H5 | network hardware: SNMP/NETCONF/REST per authorized class | built end to end on all three — SNMP/ENTITY-MIB, NETCONF `ietf-hardware`, RESTCONF `ietf-hardware`; vendor-specific YANG models not read |
| H6 | correlation: evidence-backed relationships, blast radius | built, executed here for applications and for network devices; certificate→application (which app the TLS protects) is not correlated |
| H7 | drift: firmware, crypto capability, PQC, correlated with cert/app/policy change | built, executed here; drift rows reach the live bus and the correlation window from the pipeline, but the certificate and application sides are records handed in, not feeds subscribed to |
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

### `collector_breadth` — PASS

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
- **PASS** `windows-reader-reads-cim` — identity Dell Inc. PowerEdge R760 serial SN-WIN-0001, BIOS 1.9.3 (2024-02-14), 2 disk firmware revisions and a TPM 2.0, 0, 1.16 — with the TPM capabilities WMI does not expose left absent rather than invented
- **PASS** `windows-reader-allowlist-is-closed` — 8 CIM classes may be read, each for named properties only; a class outside the table (Win32_Process) is refused rather than run, and no generated script contains a verb that evaluates text or starts a process
- **PASS** `windows-reader-runs-no-shell` — PowerShell is invoked with an argv list and shell=False, and the module cannot build a command from input at all: the text comes from the class table, there is no encoded-command path and no write verb. The script a caller could not write is run, not typed
- **PASS** `windows-reader-refuses-key-material` — a CIM reply carrying key material stops the read instead of being stored, on the same guard the Linux and HSM readers use
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
- **PASS** `pkcs11-reads-a-partition` — a Luna partition resolved to Thales Luna K7, serial 1234567890, firmware 7.8.1, across 2 partition(s) from CK_TOKEN_INFO
- **PASS** `pkcs11-reads-pqc-mechanisms` — the mechanism list yielded 6 mechanism(s) and PQC families ['ML-KEM', 'ML-DSA', 'SLH-DSA'], which reach the same HSM observation as the questionnaire path
- **PASS** `pkcs11-pin-never-on-argv` — the partition PIN travelled in the child's environment, never in argv where `ps` would show it to every user on the host
- **PASS** `pkcs11-refuses-a-pin-argument` — a caller that tries to put the PIN on the command line is refused before the process is spawned
- **PASS** `kmip-query-names-the-appliance` — KMIP Query returned vendor 'Thales Luna K7', 5 operation(s), 3 object type(s) and profile(s) ['KMIP 2.0 Profile']
- **PASS** `kmip-query-is-read-only` — the only message this reader can build is a Query (operation 0x18); there is no Get, Locate, Create or Destroy path in the module
- **PASS** `vendor-rest-reads-a-luna-appliance` — the appliance named itself: Thales K7 Base firmware 7.8.2, FIPS mode True, partition PAYMENTS01 holding 42 object(s) with 2 role(s) by name
- **PASS** `vendor-rest-is-cited-not-guessed` — 5 endpoint(s) across 1 vendor manifest(s), each a GET citing the https page it was read from and the fact that page says it returns; a vendor whose documentation was not read (Utimaco, Entrust nShield, Fortanix DSM) is refused by name instead of having a path invented for it
- **PASS** `vendor-rest-is-read-only` — every shipped endpoint is a GET, an endpoint the manifest does not name is refused, and a parameter is a single encoded path segment — a serial cannot walk into a zeroize action
- **PASS** `vendor-rest-yields-metadata-only` — a reply carrying a wrapped key stores nothing outside the named fields, and a secret inside a field the reader does project stops the read — the vendor's own `authenticationMethod` is dropped for the same reason

### `evidence_relationships` — PASS

*is a hardware dependency proven by evidence, or assumed because both exist?* (phase H6)

- **PASS** `config-evidence-produces-an-edge` — a PKCS#11 token line produced payment-api -USES_HSM-> HSM-01
- **PASS** `confidence-is-the-weakest-citation` — a config edge corroborated only by a CMDB row reports MEDIUM, not HIGH
- **PASS** `an-unevidenced-edge-is-refused` — asking for an edge with no record raises UnevidencedRelationship
- **PASS** `evidence-pointer-cannot-carry-a-secret` — an evidence reference naming a password is refused: the pointer is a location, not a value
- **PASS** `blast-radius-walks-evidenced-edges` — HSM-01 failure reaches 1 application(s), 1 system(s), and the flow(s) ['card-authorisation']
- **PASS** `network-device-terminates-a-certificate` — a load balancer gained 3 evidenced TERMINATES_TLS edge(s): ['cert:ab12cd34', 'cert:BANK-ROOT', 'cert:card-auth']
- **PASS** `network-device-config-uses-the-hsm` — the same device config that names its certificate also named the HSM token, so lb-01 -USES_HSM-> HSM-01 exists on CONFIG evidence
- **PASS** `an-ha-pair-shares-its-certificate` — two load balancers presenting one certificate are reported as sharing it, which is only visible because the certificate is the edge subject
- **PASS** `a-certificate-is-never-misattributed` — a TLS observation taken from lb-01 cannot be filed against lb-02
- **PASS** `a-certificate-is-not-an-application` — blast radius counts applications that depend on the device and lists the certificates at risk beside them, instead of counting a certificate as an application

### `hardware_drift` — PASS

*does hardware drift name what moved — firmware, capability, PQC — or just that something did?* (phase H7)

- **PASS** `firmware-change-is-its-own-event` — a firmware bump produces FIRMWARE_CHANGED and nothing else (not a replacement)
- **PASS** `model-change-is-a-replacement` — a different model is classified REPLACEMENT, not a firmware bump
- **PASS** `pqc-capability-arrives-as-its-own-row` — adding ML-DSA-65 produced ['CRYPTO_CAPABILITY_CHANGED', 'PQC_CAPABILITY_ADDED', 'HSM_CAPABILITY_CHANGED']
- **PASS** `losing-pqc-capability-is-high-severity` — losing ML-KEM-768 is PQC_CAPABILITY_REMOVED at HIGH severity — a capability that disappeared is an incident, not a tidy-up
- **PASS** `spelling-is-not-a-change` — the same algorithms written differently produce no events
- **PASS** `two-assets-are-never-one-history` — diffing two different assets is refused rather than producing a confidently wrong change log
- **PASS** `drift-correlates-with-other-change` — an ML-DSA arrival was paired with the TLS profile switch and the certificate reissue that followed it inside the window
- **PASS** `a_capability_nobody_uses_is_named` — the same capability with nothing beside it is reported as unaccompanied rather than as a migration
- **PASS** `adoption-is-not-assumed` — a capability that arrived and is unused is stated as an available migration, not as an achievement
- **PASS** `proximity-is-bounded-and-declared` — a change five minutes outside the window is not a companion, and the result says in its own words that proximity is not causation
- **PASS** `drift-reaches-the-live-bus` — 4 drift rows became live events, each chained to evidence and each carrying its correlation verdict in the same response
- **PASS** `the-same-change-is-not-counted-twice` — a change that crosses the feed/controller seam twice is one row, because a correlation count that double-counts its own input is worse than no count
- **PASS** `proximity-never-mints-an-edge` — a firmware bump with nothing beside it stays one event and one unaccompanied row — proximity is reported as proximity, and no relationship edge is minted from a timestamp
- **PASS** `an-unknown-change-is-not-dropped` — a change the mapping does not recognise is emitted as HARDWARE_CHANGED with the original type in its payload instead of vanishing

### `qualification` — PASS

*does any of it survive a synthetic bank-sized estate?* (phase H8)

- **PASS** `synthetic-estate-projects` — 600 synthetic hardware assets across 4 vendors and 6 device types, projected in 0.00s
- **PASS** `identity-does-not-collide` — 600 distinct identities from 600 observations (serial is the key, and it held)
- **PASS** `drift-scales-with-change-not-with-estate` — 400 change event(s) from 120 upgraded assets in an estate of 600: per-device-type counts {'firewall': 3, 'hsm': 4, 'load_balancer': 3, 'san': 3, 'server': 3, 'tpm': 4}, and no record named an asset that did not change (0 leaked)
- **PASS** `a-missing-observation-is-not-a-deletion` — identity is retained across observations; an asset that is not re-observed is not silently removed (retirement is its own decision)

Measured: `{"assets": 600, "vendors": 4, "device_types": 6, "changes": 400, "seconds": 0.005}`

### `single_source_of_truth` — PASS

*is HBOM a projection of the estate, or a second inventory?* (phase architecture)

- **PASS** `hbom-owns-no-table` — HBOM is generated from observations and holds no table of its own
- **PASS** `bom-projections-read-the-estate` — 3 projection module(s) read the estate rather than keeping a second inventory
- **PASS** `one-hardware-table-family` — 3 hardware table(s): state, event journal, agent health — one truth, not a BOM per document type

## The negative control

The executable rows re-run against a copy of the package with 4 guards removed. Each removal must make at least one probe in the row that watches for it fail:

| Removed guard | Row | Result |
|---|---|---|
| the Windows CIM class allowlist accepts any class | `collector_breadth` | caught — windows-reader-allowlist-is-closed, windows-reader-refuses-key-material |
| the secret-material guard becomes a no-op and any HSM vendor is given a manifest | `security_hardware` | caught — secret-material-refused, guard-survives-python-O, vendor-rest-is-cited-not-guessed, vendor-rest-yields-metadata-only |
| an edge no longer needs evidence | `evidence_relationships` | caught — an-unevidenced-edge-is-refused |
| post-quantum algorithms stop being distinguished | `hardware_drift` | caught — pqc-capability-arrives-as-its-own-row, losing-pqc-capability-is-high-severity |

Every injected defect was caught.

## What this does not prove

- no bank hardware was touched: every HSM and TPM here is a synthetic payload, and no appliance, hypervisor or network device was contacted
- collector breadth feeds each collector a synthetic payload and drives the Linux reader against a fixture sysfs tree and a recorded transcript; no bank host was read, and real hosts differ — dmidecode absent, root denied, vendor quirks its allowlist has not seen
- the Linux reader is unprivileged by design, so on a hardened host its memory, disk-health and PCI facts degrade to `unavailable` reasons rather than to data
- the Windows reader runs against a recorded CIM transcript on a Linux runner: the allowlist, the projection and the refusals are executed, but no Windows host was read — WMI can be disabled by policy, a vendor's `Win32_Tpm` may be absent, and appliance-specific classes are not in the table
- the SNMP row runs against a fake socket and NETCONF/RESTCONF against scripted replies: no appliance was contacted, and a real device's ENTITY-MIB or `ietf-hardware` model may be sparse, vendor-extended or absent entirely
- drift correlation now fills its hardware side from the live pipeline (`hardware/live/change_feed.py`, wired into `LiveHardwareController.ingest`), but the certificate, application and policy records still have to be handed in: those feeds are not subscribed, so an unaccompanied finding can mean the other feed has not been wired rather than that nothing moved
- network correlation reads a TLS observation and a device config it is given; nothing yet pulls those from the certificate probes or the running configuration of a live device, so a device that was never probed has no edges
- only the standard YANG models are read (`ietf-system`, `ietf-hardware`): vendor models expose extra facts — licence state, HA role, crypto policy — that this artifact does not collect
- the HSM readers run against recorded `pkcs11-tool` output and a hand-built KMIP response: no appliance was opened, and real Luna/nShield/Utimaco tokens differ in which mechanisms they list and which attributes they let an unprivileged session read
- the vendor REST reader has one manifest — Thales Luna, whose reference guide was read — and it is exercised against replies shaped like that guide's examples; Utimaco, Entrust nShield and Fortanix DSM are named as undocumented, so an appliance from one of those vendors is still described by hand
- the Luna manifest reads the HSM and the single-partition resources only: the guide does not pin a partition *list* shape, so partition ids come from the operator's inventory rather than from a guessed parse
- the synthetic estate measures identity, drift volume and runtime, not discovery precision or recall against real vendor firmware
- encryption at rest, per-tenant key custody and vendor attestation are outside this artifact entirely

## What I would build next, in the order the review proposed

Every row is PASS. A PASS row does not mean the hardware estate is covered; it means the code that exists survived the probes it was given. What is still missing is reach, and in order:

1. **A Windows host to run the reader against** — the reader is built, the class allowlist is closed and the projection is executed, but nothing here has watched a real `Win32_Tpm` answer. Until a Windows agent runs it, the honest claim is "the code path is tested", not "Windows discovery works".
2. **Manifests for the other HSM vendors** — Utimaco, Entrust nShield and Fortanix DSM are named in `hsm_readers/rest.py` as undocumented rather than guessed. Each needs the same treatment Luna got: a reference guide read page by page, one `DocumentedEndpoint` per fact with its source URL, and a recorded reply shaped like the guide's own example — never a path from memory.
3. **Vendor YANG models** — the standard `ietf-hardware` model carries serial, model and firmware; it does not carry HA role, licence state or crypto policy. Those live in vendor models (`Cisco-IOS-XE-*`, `junos-*`), and each one needs its own parser and its own negative control before it is trusted.
4. **H6 correlation for network hardware from live evidence** — a switch is in the estate and the edge types exist, but nothing yet pulls a TLS observation or a running config from a live device; a device that was never probed has no edges.
5. **H8 qualification against a real bank estate** — the synthetic run above is a floor. Precision and recall need ground truth only a customer can provide.

**The verdict this artifact supports:** the hardware foundation, the identity model, the security-hardware metadata model, the evidence rule for relationships and the drift vocabulary are implemented and executed here, and the projection architecture the review asked for is the one in the code. What is *not* done is execution against real hardware: the Linux reader is driven by a fixture and a transcript, the Windows reader by a recorded CIM transcript, the SNMP walk by a fake socket, NETCONF and RESTCONF by scripted replies, and the HSM readers by recorded `pkcs11-tool` output, a hand-built KMIP response and Luna replies shaped like the vendor guide. Reach is the remaining gap, and it is named above rather than folded into the score.
