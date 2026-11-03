# Hardware is a view of the estate

`cryptoscan.cbom-hbom-guide/1` · generated 2026-11-03T02:03:11.966030+00:00 · **16 pass · 0 partial · 0 fail** · 72 probes

The HBOM review's sixteen points, answered by putting hardware into the graph the
rest of the estate already lives in. The device is a tree, the HSM has depth, and
capability, operation, use and custody stay four different claims.

```
device → component     HAS_COMPONENT, RUNS_BIOS, HAS_PARTITION
device → capability    SUPPORTS          a datasheet may say this
device → capability    PERFORMS          something ran there, so CONFIGURED or better
application → crypto   USES_CRYPTO       a claim about the application
crypto → device        PROTECTED_BY      the key is held there
device → firmware      RUNS_FIRMWARE     the release, with its own lifecycle
```

26 hardware asset(s) across 22 kind(s) and 35 relationship(s) touching them out of 48 in the estate; 2 device root(s); 244 declared field(s) the collectors did not supply; 1 firmware release(s) tracked

## What the view holds

| kind | rows |
|---|---|
| `BIOS` | 1 |
| `CPU` | 1 |
| `CRYPTO_ACCELERATOR` | 1 |
| `CRYPTO_CAPABILITY` | 3 |
| `FIREWALL` | 1 |
| `FIRMWARE` | 1 |
| `GPU` | 1 |
| `HSM` | 2 |
| `HSM_CLUSTER` | 1 |
| `HSM_PARTITION` | 2 |
| `MEMORY` | 1 |
| `MOTHERBOARD` | 1 |
| `NETWORK_SEGMENT` | 1 |
| `NIC` | 1 |
| `PCI_DEVICE` | 1 |
| `PHYSICAL_SERVER` | 1 |
| `RAID_CONTROLLER` | 1 |
| `STORAGE` | 1 |
| `TPM` | 1 |
| `VENDOR` | 1 |
| `VENDOR_PRODUCT` | 1 |
| `VULNERABILITY` | 1 |

| kind | in the estate |
|---|---|
| `ALGORITHM` | 3 |
| `API_GATEWAY` | 1 |
| `APPLICATION` | 3 |
| `BUSINESS_SYSTEM` | 2 |
| `CRYPTO_ASSET` | 2 |
| `CRYPTO_LIBRARY` | 1 |
| `LOAD_BALANCER` | 1 |
| `NETWORK_ENDPOINT` | 1 |
| `PROCESS` | 1 |
| `WAF` | 1 |

## Field coverage — what the collectors did not supply

| field | declared | missing |
|---|---|---|
| `asset_id` | 20 | 0 |
| `asset_type` | 20 | 0 |
| `bios_version` | 0 | 20 |
| `datacenter` | 3 | 17 |
| `environment` | 20 | 0 |
| `evidence_id` | 20 | 0 |
| `firmware_version` | 6 | 14 |
| `first_seen` | 0 | 20 |
| `hardware_revision` | 0 | 20 |
| `last_seen` | 0 | 20 |
| `location` | 2 | 18 |
| `manufacturer` | 5 | 15 |
| `model` | 13 | 7 |
| `owner` | 1 | 19 |
| `part_number` | 1 | 19 |
| `rack` | 1 | 19 |
| `serial_number` | 2 | 18 |
| `slot` | 2 | 18 |
| `status` | 20 | 0 |

**Blast radius** — HSM-001: 2 application(s), 2 business system(s), 4 cryptographic asset(s), 5 network path(s) affected; 5 reached only through a declared edge

**Coverage** — expected 200, collected 120, unavailable 50, permission denied 20, unknown 10 — coverage PARTIAL (60%)

**Firmware** — PaymentHSM firmware 8.4.2 (8.4.2): EOL, run by HSM-001, 1 advisory(ies)

**Cross-BOM** — HSM-001: HBOM 20, CBOM 6, SBOM 4, TBOM 2, NBOM 4, VBOM 2, VULNERABILITY 1 — one graph, read as separate views

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `components` | is a server a tree of parts, with the field set | **PASS** | 5, 0 failing |
| `hsm` | is an HSM a device with depth, not a vendor string | **PASS** | 5, 0 failing |
| `software` | does hardware meet software through evidence | **PASS** | 6, 0 failing |
| `crypto` | are capability, operation, use and custody distinct | **PASS** | 6, 0 failing |
| `vendor` | does the vendor chain reach the business | **PASS** | 3, 0 failing |
| `network` | is network hardware in the same estate | **PASS** | 4, 0 failing |
| `business` | does an HSM question become a blast radius | **PASS** | 5, 0 failing |
| `firmware` | is firmware first-class, with a lifecycle | **PASS** | 4, 0 failing |
| `drift` | does hardware drift come back typed | **PASS** | 7, 0 failing |
| `identity` | is hardware identity stable under network change | **PASS** | 5, 0 failing |
| `virtual` | do virtual and cloud platforms correlate | **PASS** | 3, 0 failing |
| `containers` | does Kubernetes correlate without pretending | **PASS** | 3, 0 failing |
| `evidence` | does every fact say how it is known | **PASS** | 5, 0 failing |
| `coverage` | does coverage say what was not seen | **PASS** | 4, 0 failing |
| `crossbom` | does the HBOM correlate with the other BOMs | **PASS** | 3, 0 failing |
| `projection` | is the HBOM a view and never a source | **PASS** | 4, 0 failing |

## `components` — PASS

*is a server a tree of parts, with the field set* (review hbom / 1)

- **PASS** `a-server-is-a-tree-of-parts-not-a-row` — 11 component(s): BIOS, CPU, CRYPTO_ACCELERATOR, GPU, MEMORY, MOTHERBOARD, NIC, PCI_DEVICE, RAID_CONTROLLER, STORAGE, TPM
- **PASS** `the-device-field-set-is-declared-and-counted` — 12 of 19 declared field(s) supplied
- **PASS** `what-the-collector-did-not-supply-is-named-not-hidden` — 7 field(s) listed as unknown: part_number, firmware_version, bios_version, hardware_revision, location
- **PASS** `every-component-carries-its-own-evidence-and-identity` — 18 asset(s) carry an identity block
- **PASS** `bios-and-firmware-are-reachable-as-their-own-assets` — RUNS_BIOS plus RUNS_FIRMWARE, not a version string on the server row

## `hsm` — PASS

*is an HSM a device with depth, not a vendor string* (review hbom / 2)

- **PASS** `an-hsm-carries-cluster-ha-peers-and-partitions` — cluster 1, partitions 2, HA mode Active/Active
- **PASS** `an-hsm-lists-what-it-can-do-with-key-types-and-sizes` — HSM-001 ML-KEM-768 ENCAPSULATE → ['ENCAPSULATE']
- **PASS** `the-applications-wired-to-the-device-are-claims-not-attributes` — 4 USES_HSM edge(s)
- **PASS** `a-partition-names-the-application-it-serves` — each partition records the applications it holds keys for
- **PASS** `a-key-material-attribute-is-refused-at-the-door` — private_key → KEY_MATERIAL_REFUSED

## `software` — PASS

*does hardware meet software through evidence* (review hbom / 3)

- **PASS** `a-process-runs-on-the-host-it-was-seen-on` — payments-api reaches ASSET-HW-010788 over RUNS_ON (19 proven node(s))
- **PASS** `an-application-on-a-host-is-a-covered-claim-not-an-assumption` — Payments API RUNS_ON the server, basis config-parse → CONFIGURED
- **PASS** `the-business-system-to-hardware-chain-is-walkable-end-to-end` — system → application → process → host → component, all from claims
- **PASS** `a-process-loads-the-crypto-library-that-uses-the-algorithm` — payments-api LOADS OpenSSL 3.0.13, and the library PROVIDES_ALGORITHM
- **PASS** `the-host-row-carries-the-hardware-it-was-seen-with` — ASSET-HW-010788 is the canonical id, not a hostname
- **PASS** `an-application-cannot-be-a-component-of-a-server` — HAS_COMPONENT ends at a component, never at an application

## `crypto` — PASS

*are capability, operation, use and custody distinct* (review hbom / 4)

- **PASS** `supports-is-a-capability-claim-and-carries-its-own-class` — SUPPORTS → VENDOR_DECLARED from the vendor list
- **PASS** `performs-is-a-statement-that-something-ran-there` — PERFORMS → CONFIGURED from the HSM API poll
- **PASS** `a-datasheet-cannot-carry-a-performs-claim` — vendor-datasheet PERFORMS → CLAIM_WEAKER_THAN_RELATION_REQUIRES
- **PASS** `uses_crypto-is-a-claim-about-the-application-not-the-device` — Payments API USES_CRYPTO → OBSERVED
- **PASS** `protected_by-is-a-claim-about-the-key-and-its-custodian` — RSA-2048 PROTECTED_BY HSM-001 → CONFIGURED
- **PASS** `a-device-relation-can-never-be-written-from-the-application-side` — SUPPORTS starts at a device or a firmware, never at an application

## `vendor` — PASS

*does the vendor chain reach the business* (review hbom / 5)

- **PASS** `vendor-to-product-to-device-is-four-claims` — HSM-001 HAS_MODEL product, product SUPPLIED_BY vendor
- **PASS** `the-firmware-release-is-in-the-vendor-chain` — the release names its vendor, so an advisory can start at either end
- **PASS** `a-vendor-question-reaches-the-systems-that-buy-it` — SyntheticHSM: 2 application(s), 2 business system(s), 4 cryptographic asset(s), 5 network path(s) affected; 23 reached only through a declared edge

## `network` — PASS

*is network hardware in the same estate* (review hbom / 6)

- **PASS** `a-firewall-is-hardware-with-its-own-firmware-and-ha-role` — FIREWALL with firmware 11.1.3 and HA mode Active/Passive
- **PASS** `the-path-is-firewall-then-waf-then-balancer-then-gateway` — 3 FORWARDS_TO hop(s) from the firewall
- **PASS** `a-nic-attaches-to-a-segment-and-the-segment-carries-the-zone` — NIC ATTACHED_TO SEG-VLAN-40, zone PAYMENTS, 10.10.1.0/24
- **PASS** `the-network-and-the-hardware-are-one-graph` — ASSET-HW-946725: 1 application(s), 1 business system(s), 0 cryptographic asset(s), 4 network path(s) affected; 1 reached only through a declared edge

## `business` — PASS

*does an HSM question become a blast radius* (review hbom / 7)

- **PASS** `an-hsm-failure-reported-in-the-units-a-business-owner-uses` — HSM-001: 2 application(s), 2 business system(s), 4 cryptographic asset(s), 5 network path(s) affected; 5 reached only through a declared edge
- **PASS** `business-systems-are-reachable-through-applications-not-by-name-matching` — 2 system(s): Card Services, Payments
- **PASS** `the-cryptographic-assets-behind-the-device-are-counted` — 4 cryptographic asset(s)
- **PASS** `the-network-paths-that-carry-the-traffic-are-counted` — 5 network path(s)
- **PASS** `a-declared-hop-taints-what-sits-above-it` — 5 node(s) reached only through a declared edge

## `firmware` — PASS

*is firmware first-class, with a lifecycle* (review hbom / 8)

- **PASS** `firmware-is-a-release-with-a-date-a-status-and-an-end` — PaymentHSM firmware 8.4.2 8.4.2 → EOL
- **PASS** `the-release-names-the-devices-that-run-it` — run by HSM-001
- **PASS** `a-known-vulnerability-reaches-the-release-through-an-edge` — CVE-2026-1111 → VENDOR_DECLARED, because the vendor said it
- **PASS** `an-unknown-firmware-status-is-refused-rather-than-stored` — PROBABLY-FINE → UNKNOWN_FIRMWARE_STATUS

## `drift` — PASS

*does hardware drift come back typed* (review hbom / 9)

- **PASS** `an-unchanged-estate-produces-no-drift` — no change between two reads of the same estate
- **PASS** `moving-an-address-is-a-network-interface-change-not-a-new-device` — 1 hardware change(s): NETWORK_INTERFACE_CHANGED 1; 1 application(s) sit behind the changed devices
- **PASS** `a-hsm-firmware-change-is-named-as-an-hsm-change` — 8.4.2 → 8.5.0 → HSM_FIRMWARE_CHANGED
- **PASS** `a-bios-change-and-a-firmware-change-are-different-events` — BIOS_CHANGED and FIRMWARE_CHANGED are counted separately
- **PASS** `a-removed-part-is-device-removed-and-a-new-one-is-device-added` — DEVICE_ADDED and DEVICE_REMOVED are both reported
- **PASS** `every-drift-event-carries-the-cryptography-behind-the-device` — an HSM change names the application that depends on it
- **PASS** `the-twelve-review-change-types-are-all-modelled` — 12 typed hardware changes

## `identity` — PASS

*is hardware identity stable under network change* (review hbom / 10)

- **PASS** `a-canonical-id-is-derived-from-manufacturer-model-and-serial` — ASSET-HW-665154 from manufacturer, model, serial_number
- **PASS** `a-renamed-host-and-a-new-address-keep-the-same-id` — the address moved; the device did not
- **PASS** `network-identifiers-are-kept-but-never-used-as-identity` — hostname and MAC recorded as observations only
- **PASS** `a-device-known-only-by-hostname-ip-and-mac-has-no-identity` — IDENTITY_WITHOUT_ANCHOR rather than a hostname-shaped id
- **PASS** `a-manufacturer-and-model-alone-is-provisional-and-says-so` — two units of one model collide, so the id says it is provisional

## `virtual` — PASS

*do virtual and cloud platforms correlate* (review hbom / 11)

- **PASS** `physical-to-hypervisor-to-vm-to-os-to-application-is-one-chain` — esxi-01: 1 application(s), 0 business system(s), 0 cryptographic asset(s), 0 network path(s) affected
- **PASS** `a-cloud-instance-is-in-a-region-which-is-in-an-account` — three claims, no viewer-side inference
- **PASS** `the-platform-rows-are-hardware-adjacent-not-applications` — an application is reached from the platform, not stored as one

## `containers` — PASS

*does Kubernetes correlate without pretending* (review hbom / 12)

- **PASS** `a-pod-is-scheduled-on-a-node-and-never-on-a-processor` — the pod→CPU claim is refused, the pod→node claim is kept
- **PASS** `a-container-reaches-the-crypto-library-through-its-process` — container → process → library → algorithm, without inventing hardware
- **PASS** `a-container-is-not-given-a-hardware-substrate-it-cannot-prove` — the container stays in the software view

## `evidence` — PASS

*does every fact say how it is known* (review hbom / 13)

- **PASS** `every-device-cites-an-evidence-id` — 26 asset(s), each with at least one evidence id
- **PASS** `the-register-keeps-the-eleven-parts-the-review-asks-for` — linux-hardware-collector 1.4.2 at 2026-11-03T08:30:00Z
- **PASS** `an-observation-without-a-hash-is-refused` — evidence that cannot be re-checked is a memory
- **PASS** `a-hardware-asset-without-evidence-is-refused` — how the platform knows the device exists is part of the asset
- **PASS** `key-material-is-refused-and-a-reference-is-kept` — PRIVATE KEY → KEY_MATERIAL_REFUSED; KREF-0007 is kept

## `coverage` — PASS

*does coverage say what was not seen* (review hbom / 14)

- **PASS** `coverage-states-the-denominator-and-every-bucket` — expected 200, collected 120, unavailable 50, permission denied 20, unknown 10 — coverage PARTIAL (60%)
- **PASS** `coverage-that-does-not-add-up-is-refused` — 190 accounted for of 200 expected → COVERAGE_DOES_NOT_RECONCILE
- **PASS** `the-estate-carries-its-own-completeness-with-the-gap-reasons` — PARTIAL: 3 kind(s) complete, 3 short, 2 stated gap(s), 27 unmeasured
- **PASS** `a-kind-with-no-denominator-is-unmeasured-not-complete` — 27 kind(s) unmeasured

## `crossbom` — PASS

*does the HBOM correlate with the other BOMs* (review hbom / 15)

- **PASS** `one-hardware-asset-walks-into-the-other-four-views` — HSM-001: HBOM 20, CBOM 6, SBOM 4, TBOM 2, NBOM 4, VBOM 2, VULNERABILITY 1 — one graph, read as separate views
- **PASS** `the-walk-reaches-the-application-and-the-business-system` — HBOM → CBOM → SBOM → NBOM → VBOM, one graph
- **PASS** `a-link-is-a-reference-pinned-by-digest-not-a-copy` — bom-link:hbom:fb56fc820a1525e5

## `projection` — PASS

*is the HBOM a view and never a source* (review hbom / 16)

- **PASS** `the-hbom-is-the-techbom-restricted-to-hardware` — 26 hardware row(s) out of 42 estate assets
- **PASS** `an-hbom-cannot-be-fed-back-in-as-a-source` — from_document(HBOM) → refused: a projection is not a source
- **PASS** `a-techbom-cannot-produce-an-hbom-either` — from_document(TechBOM) → refused
- **PASS** `the-same-estate-produces-the-same-ids-and-the-same-statement` — 26 hardware asset(s) across 22 kind(s) and 35 relationship(s) touching them out of 48 in the estate; 2 device root(s); 244 declared field(s) the collectors did not supply; 1 firmware release(s) tracked

## What this does not prove

- the fixture is the review's own example estate, not a bank's collector output: the shapes are real, the rows are not
- a collector that cannot see a field leaves it unknown, and this guide counts those gaps instead of filling them
- capability is what a vendor or a firmware list says; nothing here re-probes the device to confirm it
- drift compares two collections: a device nobody re-read shows no change
- coverage is only as honest as the denominator, which comes from a CMDB the platform does not own
