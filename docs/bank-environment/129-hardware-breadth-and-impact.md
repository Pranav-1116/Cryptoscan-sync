# Hardware breadth, usage evidence and business impact

`cryptoscan.hardware-breadth/1` · generated 2026-11-02T13:33:53.552214+00:00 · **6 pass · 0 partial · 0 fail**

Guide 128 answered *does the hardware architecture exist*. This one answers the harder follow-up: **host collection is not a complete hardware scanner**. A collector that returns a DMI blob, a disk list and a NIC list has collected facts; it has not told a bank what hardware it owns, which applications depend on it, or what breaks when a part fails.

Three ideas hold the artifact together, and each of them is a probe below:

1. **A component has three states, not two.** `PRESENT`, `ABSENT` (the reader looked and there is none) and `UNKNOWN` (nobody looked, and here is why). Turning `UNKNOWN` into `ABSENT` is how an unprivileged collector reports a machine with no GPU, no TPM and no crypto accelerator.
2. **A relationship is a record, not a coincidence.** `HSM-01 —USED_BY→ Payment API` exists only where a configuration names both ends; a label nobody discovered is `UNRESOLVED`, a label two appliances claim is `AMBIGUOUS` and refused.
3. **An unknown is not a zero.** An application with no business mapping is named in the impact statement, not counted as `0 services affected`.

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `component_breadth` | does the estate know what hardware a host contains, class by class — and does it admit which classes nobody looked at? | **PASS** | 10, 0 failing |
| `hsm_evidence_path` | does an HSM carry the twelve facts a bank needs — and none of the five it must never carry? | **PASS** | 6, 0 failing |
| `usage_evidence` | is 'this application uses this HSM' proven by a record that names both ends, or assumed because both exist? | **PASS** | 7, 0 failing |
| `business_impact` | if this HSM fails, what breaks — and is the answer evidenced at every hop? | **PASS** | 7, 0 failing |
| `drift_first_class` | is a hardware change first class — named, evidenced, versioned and correlated — or just a log line? | **PASS** | 8, 0 failing |
| `security_qualification` | do the collection guards actually refuse — under a hostile path, a moving file and an elevated process? | **PASS** | 6, 0 failing |

## Platform qualification

Computed from what the tree contains and what this artifact executed — not from an opinion about the platform.

| Platform | Reader | State | What that means |
|---|---|---|---|
| Linux | `host/linux.py` | implemented, qualified against fixtures | executed here on a fixture sysfs tree and a recorded command transcript |
| Windows | `host/windows.py` | implemented, candidate | allowlist and projection executed here; no Windows host has run it |
| Network | `host/snmp_bridge.py, netconf, restconf` | implemented, qualified against scripted replies | no appliance was contacted |
| HSM | `hsm_readers/ (PKCS#11, KMIP Query, documented REST)` | implemented, qualified against recorded replies | Luna REST is documented and cited; Utimaco/Entrust/Fortanix are named gaps |
| OCI | `inventory/oci_image.py` | partial/candidate | image metadata, not hardware; outside this artifact's probes |
| Cloud KMS | `inventory/cloud_kms.py` | partial/candidate | managed-key inventory, not physical hardware |

## Reclassification after this artifact (review item 14)

Each rating is computed, not asserted: it is the verdict of the row that proves the area, capped by a ceiling where a known gap survives a green row (no PC/SC reader, no Windows host). A failing probe degrades its area in the same run that breaks it, so this table cannot quietly outlive its evidence.

| Area | Rating | Was | Rests on | Still open |
|---|---|---|---|---|
| Linux collection security | 🟢 | 🟢 | guards executed on this runner: hostile path, hard link, FIFO, oversized input, mid-read mutation, PEM and human spellings of secret material, and a per-argument allowlist on the two new readers (`security_qualification` PASS) | none outstanding for the Linux reader; Windows traversal guards need a Windows host |
| Linux evidence model | 🟢 | 🟢 | every component carries PRESENT/ABSENT/UNKNOWN with the reader and evidence that produced it; nothing is inferred from a neighbour (`component_breadth` PASS) | the model is proved against fixtures, not against bank hosts |
| Linux host collector | 🟢 | 🟢 | foundation: 15 component classes projected from DMI, lscpu, lspci, tpm2_getcap, opensc-tool, firmware and disk facts behind a per-argument allowlist (`component_breadth` PASS) | breadth comes from allowlisted binaries, so a class with no binary is UNKNOWN |
| Cloud KMS | 🟡 | 🟡 | managed-key inventory exists per provider, so the estate can name a key and its provider (`component_breadth` PASS) | green only where a probe covers it; nothing in this artifact does, and it is not physical hardware |
| HSM | 🟡 | 🟠 | review item 10: twelve metadata facts and five refusals through the scanner itself — never a private key, secret key, PIN, wrapped key or plaintext (`hsm_evidence_path` PASS) | Luna REST is documented and cited; Utimaco, Entrust and Fortanix readers are named gaps |
| Hardware drift | 🟡 | 🟡 | review item 13: FIRST-CLASS FOUNDATION — named changes, evidence ids, live bus correlation, twin version bump and a crypto delta (`drift_first_class` PASS) | single-appliance diff; a cluster rollback is not modelled |
| Hardware relationships | 🟡 | 🟠 | review item 11: an edge exists only where a configuration names both ends, carries an evidence id, and is refused when unproven or ambiguous (`usage_evidence` PASS) | configuration-proven only: no session observation catches an application using an HSM it never configured |
| Linux production qualification | 🟡 | 🟡 | the collector has never run on a bank-managed Linux host with the bank's privilege model (`security_qualification` PASS) | a real host and a real manifest are required |
| OCI inventory | 🟡 | 🟡 | image metadata exists; it is inventory of images, not of hardware (`component_breadth` PASS) | outside this artifact's probes |
| Physical hardware breadth | 🟡 | 🟠 | review item A: CPU, memory, motherboard, BIOS, firmware, PCI, GPU, NIC, storage controller, disk, RAID, TPM, HSM, smart card and crypto accelerator now have a class, a reader and a projection on both Linux and Windows (`component_breadth` PASS) | an accelerator has no enumerable class on either platform, RAID has none on Windows, and a smart-card reader is not the card's content |
| Windows collector code | 🟡 | 🟡 | implemented and candidate: twelve allowlisted CIM reads, and the device tree now names PCI, GPU, NIC, storage controllers and smart-card readers (`component_breadth` PASS) | no Windows host has run it, and RAID/accelerator have no Windows class to read |
| Windows production qualification | 🟡 | 🟡 | missing: the device tree is read and projected against a recorded transcript, but no Windows host has produced one (`component_breadth` PASS) | a Windows host and a real transcript |

Totals: 3 green · 9 amber · 0 orange · 0 red.

### Security: broad concern → qualification outstanding (review item 15)

Security moves from 🔴 broad concern to 🟡 qualification still required: the collection guards refuse rather than assert, and what remains is qualification on a bank host and a Windows runner, not an open security hole.

## `component_breadth` — PASS

*does the estate know what hardware a host contains, class by class — and does it admit which classes nobody looked at?* (review item A)

- **PASS** `fifteen-component-classes` — every class the review named is reported for this host: cpu=PRESENT, memory=PRESENT, motherboard=PRESENT, bios=PRESENT, firmware=PRESENT, pci=PRESENT, gpu=PRESENT, nic=PRESENT, storage_controller=ABSENT, disk=PRESENT, raid=PRESENT, tpm=PRESENT, hsm=PRESENT, smart_card=PRESENT, crypto_accelerator=ABSENT
- **PASS** `host-facts-reach-the-cpu-and-memory` — processor Intel(R) Xeon(R) Gold 6430 from lscpu, 2 memory module(s) from dmidecode -t memory
- **PASS** `pci-classes-name-the-component` — GPU 'ASPEED Graphics [2000]', RAID 'PERC H755 [10e2]' and NICs from the PCI class codes; a non-RAID storage controller is ABSENT (the bus answered) rather than UNKNOWN
- **PASS** `firmware-is-per-component` — 2 firmware revision(s) recorded against the component that carries each one
- **PASS** `an-unread-bus-is-unknown-not-empty` — with lspci unavailable the GPU, RAID and storage classes are UNKNOWN and name the reason — not ABSENT, which would have read as 'this server has no GPU'
- **PASS** `an-unlooked-tpm-is-unknown-not-absent` — with the reader stripped the TPM is UNKNOWN and says nobody looked; with tpm2_getcap in the transcript it is PRESENT (IFX firmware 7.63.8.13139) — the third state is what keeps the first answer honest
- **PASS** `a-smart-card-reader-is-not-a-card` — 1 reader(s) from opensc-tool with card_present=True; the two facts are separate because an empty reader and an absent reader are different findings
- **PASS** `windows-collects-its-device-tree` — Windows fills CPU, memory modules, BIOS, motherboard, disk and TPM from CIM, and the device tree now names PCI, GPU, NIC and storage controllers too — only RAID and a crypto accelerator stay UNKNOWN, because Windows exposes an array as a property of its controller and has no accelerator class at all
- **PASS** `a-class-is-unknown-for-a-named-reason-on-every-platform` — both UNKNOWN classes on Windows carry the reason the platform gives, and a Windows reader that did not read the device tree says so instead of reporting an empty bus
- **PASS** `the-inventory-is-a-projection-not-a-store` — every component is derived from facts the readers already produced; the module owns no table, so a component cannot drift away from the observation behind it

## `hsm_evidence_path` — PASS

*does an HSM carry the twelve facts a bank needs — and none of the five it must never carry?* (review item 10)

- **PASS** `the-twelve-facts-an-hsm-must-carry` — 12/12 facts present on the observation: vendor, model, firmware, device identity, HA state, partitions, algorithms, key types, certificates, capabilities and PQC
- **PASS** `the-five-things-an-hsm-must-never-carry` — 5/5 refusals through the HSM scanner itself: private key, secret key, pin, wrapped key, plaintext
- **PASS** `certificate-dependencies-are-references` — certificate dependencies arrive as references, so the twin draws them as edges only where a record names both ends
- **PASS** `application-relationships-are-edges-not-a-text-field` — an application→HSM relationship is an evidenced edge in the usage graph, not a string on the observation: a text field could not carry the evidence id the twin needs
- **PASS** `post-quantum-capability-is-named-not-implied` — PQC capability is explicit: ['ML-DSA-65'] on firmware 8.2.1
- **PASS** `the-observation-is-scanner-shaped-not-invented-here` — the row reads the scanner's own observation (hsm, firmware 8.2.1), so guide 129 cannot drift from the HSM model in guide 128

## `usage_evidence` — PASS

*is 'this application uses this HSM' proven by a record that names both ends, or assumed because both exist?* (review item 11)

- **PASS** `a-config-names-both-ends-and-that-is-the-edge` — 1 application(s) use HSM-01: Payment API (HIGH, EV-9b3c809b2a5f)
- **PASS** `an-application-that-merely-exists-has-no-edge` — Statement Worker shares the estate with the appliance and shares no configuration with it, so no edge exists — coexistence is not a dependency
- **PASS** `a-label-nobody-discovered-is-a-finding-not-an-edge` — a config naming a token label no discovered appliance carries is reported UNRESOLVED, because a dependency on something the estate has not found is worth knowing
- **PASS** `a-label-two-appliances-claim-is-refused` — when two appliances carry the same token label the edge is refused as AMBIGUOUS with both candidates named; picking one would be a guess wearing an evidence id
- **PASS** `capability-is-evidenced-and-than-named` — 4 SUPPORTS link(s) from the observation: RSA-3072 (RSA), ECDSA-P256 (ECDSA), AES-256 (AES), ML-DSA-65 (PQC)
- **PASS** `an-evidence-free-edge-cannot-be-constructed` — the edge type itself refuses a construction with no evidence, so the graph cannot be filled by assertion even by a caller that skips the helpers
- **PASS** `the-graph-reports-its-own-shape` — resolved=1, unresolved=1, ambiguous=0

## `business_impact` — PASS

*if this HSM fails, what breaks — and is the answer evidenced at every hop?* (review item 12)

- **PASS** `the-chain-reaches-a-business-system` — HSM-01 → 2 application(s) → 1 service(s) → 1 critical business system(s) (Card Authorization)
- **PASS** `the-sentence-says-what-breaks` — HSM-01 failure reaches 2 application(s); 1 service(s); 1 critical business system(s) (Card Authorization)
- **PASS** `every-hop-carries-its-evidence` — 1 service hop(s), each with the evidence id of the application→hardware edge and of the service mapping
- **PASS** `an-unmapped-application-is-not-a-zero` — with no service record for the payment applications the answer names them as unmapped rather than reporting that a failure would reach nothing
- **PASS** `a-service-mapping-without-evidence-is-refused` — the hop that reaches a business system needs its own record, so the business view cannot be asserted any more than the hardware edge can
- **PASS** `confidence-is-the-weakest-hop` — the config-proven edge is HIGH and the CMDB service mapping is MEDIUM; the answer reports MEDIUM, because the chain is only as strong as its weakest citation
- **PASS** `no-dependency-is-stated-as-no-dependency` — an appliance nothing proven depends on produces that sentence — not a reassuring zero that hides a missing collector

## `drift_first_class` — PASS

*is a hardware change first class — named, evidenced, versioned and correlated — or just a log line?* (review item 13)

- **PASS** `firmware-8-2-1-to-8-3-0-names-three-things` — the bump produced ['FIRMWARE_CHANGED', 'CRYPTO_CAPABILITY_CHANGED', 'PQC_CAPABILITY_ADDED', 'HSM_CAPABILITY_CHANGED']
- **PASS** `the-change-payloads-carry-no-key-material` — every change payload is firmware versions, algorithm names and evidence ids
- **PASS** `the-change-reaches-the-live-bus` — 4 drift row(s) became live events with evidence ids, through the same controller the estate runs
- **PASS** `the-firmware-change-correlates-with-the-certificate-and-the-application` — the PQC row is CORRELATED with the TLS profile switch and the certificate reissue (verdicts ['SUSPICIOUS', 'CORRELATED', 'CORRELATED', 'CORRELATED'])
- **PASS** `proximity-is-still-not-causation` — the correlation carries its own disclaimer, so a change board cannot read a timestamp as proof
- **PASS** `the-feed-and-the-correlation-agree-about-what-happened` — the feed holds 4 hardware change(s) for the 4 rows the diff produced — no double counting across the seam
- **PASS** `the-twin-versions-the-change` — the HBOM version moved 2 → 3 when the firmware did, and the two documents differ — the drift is a version in the twin, not a row in a log
- **PASS** `the-crypto-delta-is-in-the-change-itself` — the change names what the CBOM gains (ML-DSA-65) and what it loses (nothing), so a CBOM projection after the change has something to say

## `security_qualification` — PASS

*do the collection guards actually refuse — under a hostile path, a moving file and an elevated process?* (review item 15)

- **PASS** `the-file-guards-refuse` — symlink=refused, hardlink=refused, special file=refused, oversized=refused, input mutation=refused — a symlink never reaches an open, a hard link is refused for aliasing, a FIFO is not a file, an oversized input stops at the limit and a file that changes mid-read is refused rather than half-read
- **PASS** `the-secret-guards-refuse` — private key=refused, secret text=refused — the PEM spelling ('BEGIN PRIVATE KEY') is refused as well as the underscore form, which it was not until this drill ran it
- **PASS** `privilege-and-promotion-guards-refuse` — manifest tampering=refused, privilege=refused, expiry=refused, runtime promotion=refused, algorithm promotion=refused, policy promotion=refused — an elevated process is refused, an expired manifest is refused, a tampered manifest no longer matches its digest, a snapshot cannot claim whole-host coverage, a CMDB claim cannot be promoted past MEDIUM and an unknown evidence kind cannot be invented
- **PASS** `the-reader-is-identity-not-assertion` — the same code path reads a real file, so the refusals above are not a reader that refuses everything
- **PASS** `an-allowlisted-binary-still-has-a-fixed-argv` — 3/3 non-allowlisted argument(s) refused (tpm2_getcap properties-variable, tpm2_getcap --tcti=device, opensc-tool --read-certificate) while the one shape each tool is run as still passes — a TPM subcommand or a card-certificate read is not reachable by asking the reader for it
- **PASS** `a-failing-row-degrades-the-rating-that-rested-on-it` — forcing `security_qualification` to FAIL removed green from 1/1 area(s) that rested on it

## What this does not prove

- no bank hardware was touched: the Linux and Windows hosts are recorded facts, the HSM is a synthetic observation, and the application configurations are fixtures shaped like the real files
- the component inventory grades what the readers can see, not what a machine has: a class nobody looked at is UNKNOWN, and UNKNOWN is not an absence
- on Windows, PCI, GPU, RAID, storage-controller and NIC classes have no reader yet; that is a gap in the CIM allowlist and is reported as UNKNOWN rather than as a machine without those parts
- smart cards and crypto accelerators are only as good as the reader that supplies them: this artifact projects a PC/SC or PCI record, it does not open a reader
- the usage graph reads configuration files handed to it; nothing here watches a running process open a PKCS#11 session, so an application that uses the HSM without configuring it is invisible
- a token label shared by two appliances is refused rather than resolved; on a real estate that refusal is a labelling job, not a bug
- the business impact walk depends on service and business-system records a bank maintains; this artifact exercises the chain with CMDB-shaped fixtures and does not connect to a CMDB
- drift here is a single-appliance diff executed in-process; it does not prove what a fleet does when a firmware rollback lands on one unit of a cluster
- the security row executes the collection guards on this runner as an unprivileged or elevated process, whichever it is; Windows traversal guards need a Windows host
- the Windows device tree is projected from `PNPClass`, a Setup Class name and not a PCI class code: a smart-card reader is a reader (whether a card is seated is a separate fact) and a controller Windows calls `SCSIAdapter` is recorded as a storage controller, not as the array behind it
- on Linux the two new readers run as the same unprivileged user as `lspci`, so a host with a policy that denies `/dev/tpm0` or hides the PC/SC socket reports TPM and smart-card as UNKNOWN with that reason rather than as absent

## What is still missing, in the review's own order

Every row is PASS and the platform matrix still has two candidates and two partials. Those are not rows that failed; they are platforms where a reader exists and no production qualification has happened:

1. **Windows production qualification** — the reader is implemented and its allowlist is executed here. What is missing is a Windows host: `Win32_PnPEntity` and `Win32_VideoController` would close the PCI/GPU/NIC `UNKNOWN`s, and both are one allowlist entry plus a projection away.
2. **A smart-card and accelerator reader** — `components.py` projects what a PC/SC or PCI record says; the PC/SC reader itself (`pcsc_scan`/`opensc-tool` behind an argv allowlist) is not built.
3. **Live usage evidence** — the usage graph reads configuration. An `OBSERVED` edge from a running PKCS#11 session would catch an application that uses an HSM it was never configured for, and that needs a session-tracing collector no bank has authorised yet.
4. **CMDB integration** — the business impact chain is exercised against CMDB-shaped fixtures. Pointing it at a bank's actual service register is integration work, and the evidence rule does not change when it happens.
5. **Fleet drift** — a firmware rollback on one unit of a cluster is a cluster-level change, and this artifact diffs one appliance at a time.

