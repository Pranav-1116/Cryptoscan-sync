# The rest of the HBOM review

`cryptoscan.cbom-hbom-gaps-guide/1` · generated 2026-11-03T02:15:12.023398+00:00 · **9 pass · 0 partial · 0 fail** · 43 probes

Guide 167 answered the review at the level of relations. Read back against the
text, nine things were still missing — device metadata, the other direction of
"runs", two evidence classes, product lifecycle, network appliances, the
review's sentence as a number, `DEVICE_REPLACED`, evidence as nodes, and the
certificates an HSM holds.

```
class ladder      OBSERVED = NETWORK_OBSERVED > CONFIGURED > CAPABILITY
                  = IMPORTED = VENDOR_DECLARED > INFERRED > UNKNOWN
device metadata   sku, certifications[{standard, level, expires, evidence_id}]
cpu topology      sockets × cores_per_socket × threads_per_core, reconciled
host              HOST --RUNS--> APPLICATION   (and APP --RUNS_ON--> HOST)
product           VENDOR_PRODUCT{status} --HAS_MODEL-- DEVICE --USES_HSM-- APP
appliance         ip, mac, interface, vlan, zone, subnet, routing, ha_role,
                  firmware, vendor, model, tls, certificate, hsm
evidence          EVIDENCE node + EVIDENCED_BY edge, floor IMPORTED
```

23 hardware asset(s) across 20 kind(s) and 47 relationship(s) touching them out of 55 in the estate; 2 device root(s); 190 declared field(s) the collectors did not supply; 1 firmware release(s) tracked

**The review's sentence** — HSM-001: 2 HSMs affected, 2 applications affected, 2 business systems affected, 3 cryptographic assets affected, 3 network paths affected; 5 node(s) only through a declared edge

**Product lifecycle** — 1 vendor product(s) in the chain, 1 past end of life: SyntheticHSM PaymentHSM-9000 RETIRED → 1 device(s), 2 application(s), 2 system(s)

| kind | rows |
|---|---|
| `BIOS` | 1 |
| `CERTIFICATE` | 2 |
| `CPU` | 1 |
| `CRYPTO_CAPABILITY` | 2 |
| `EVIDENCE` | 1 |
| `FIREWALL` | 1 |
| `FIRMWARE` | 1 |
| `HSM` | 2 |
| `HSM_CLUSTER` | 1 |
| `HSM_PARTITION` | 1 |
| `LOAD_BALANCER` | 1 |
| `MEMORY` | 1 |
| `MOTHERBOARD` | 1 |
| `NIC` | 1 |
| `PHYSICAL_SERVER` | 1 |
| `RAID_CONTROLLER` | 1 |
| `STORAGE` | 1 |
| `TPM` | 1 |
| `VENDOR` | 1 |
| `VENDOR_PRODUCT` | 1 |

| evidence class | rank |
|---|---|
| `OBSERVED` | 5 |
| `NETWORK_OBSERVED` | 5 |
| `CONFIGURED` | 4 |
| `CAPABILITY` | 3 |
| `IMPORTED` | 3 |
| `VENDOR_DECLARED` | 3 |
| `INFERRED` | 2 |
| `UNKNOWN` | 1 |

| Row | Question | Verdict | Probes |
|---|---|---|---|
| `metadata` | does a device carry a SKU, certifications and a CPU topology | **PASS** | 6, 0 failing |
| `host-runs` | can a host say what it runs, as the review draws it | **PASS** | 5, 0 failing |
| `classes` | are CAPABILITY and NETWORK_OBSERVED classes of their own | **PASS** | 5, 0 failing |
| `product-lifecycle` | does a retired model reach the business | **PASS** | 5, 0 failing |
| `network-appliance` | do network appliances carry their fourteen facts | **PASS** | 5, 0 failing |
| `impact-units` | does the review's sentence become a number | **PASS** | 4, 0 failing |
| `device-replaced` | is a swapped device one event, not two | **PASS** | 5, 0 failing |
| `evidence-nodes` | is the evidence walkable, not just listed | **PASS** | 5, 0 failing |
| `hsm-certificates` | does an HSM's certificate graph reach it | **PASS** | 3, 0 failing |

## `metadata` — PASS

*does a device carry a SKU, certifications and a CPU topology* (review hbom / 1 (metadata))

- **PASS** `a-device-carries-a-sku-as-well-as-a-part-number` — SKU PER760-32C on ASSET-HW-010788
- **PASS** `a-certification-names-a-standard-a-level-and-an-expiry` — FIPS 140-3 Level 3 until 2027-06-30
- **PASS** `a-certification-without-a-standard-is-refused` — level without a standard → CERTIFICATION_WITHOUT_STANDARD
- **PASS** `a-certification-with-no-attestation-behind-it-says-so` — kept, but marked unbacked rather than presented as certified
- **PASS** `a-cpu-is-a-topology-whose-arithmetic-reconciles` — 2 socket(s) x 16 core(s) x 2 thread(s) = 64 logical processor(s)
- **PASS** `a-topology-that-does-not-add-up-is-refused` — 2 sockets x 16 cores ≠ 48 claimed → TOPOLOGY_DOES_NOT_RECONCILE

## `host-runs` — PASS

*can a host say what it runs, as the review draws it* (review hbom / 3)

- **PASS** `a-host-runs-the-applications-that-sit-on-it` — 2 RUNS edge(s) out of the host, basis process-trace
- **PASS** `the-reverse-direction-is-kept-as-well` — Payments API RUNS_ON the same host, from configuration
- **PASS** `both-directions-are-claims-with-their-own-basis` — RUNS OBSERVED from a process trace, RUNS_ON CONFIGURED from configuration
- **PASS** `a-host-cannot-run-an-algorithm` — RUNS ends at software, never at an algorithm
- **PASS** `the-business-to-hardware-chain-reads-in-one-direction` — from the host: Payments; from the HSM: both systems, through two apps

## `classes` — PASS

*are CAPABILITY and NETWORK_OBSERVED classes of their own* (review hbom / 4 (evidence classes))

- **PASS** `capability-is-an-evidence-class-of-its-own` — CAPABILITY sits above an import and below anything read from the device
- **PASS** `a-capability-list-claim-carries-capability-and-not-more` — SUPPORTS from a capability list → CAPABILITY
- **PASS** `a-network-observation-is-an-observation` — NETWORK_OBSERVED is proven, because a capture saw it
- **PASS** `a-capability-can-never-be-promoted-into-the-proven-set` — CAPABILITY is walked and reported, never counted as blast radius
- **PASS** `the-eight-classes-the-review-names-are-all-present` — 8 classes, including the two this round added

## `product-lifecycle` — PASS

*does a retired model reach the business* (review hbom / 5)

- **PASS** `a-product-past-end-of-life-is-actionable` — SyntheticHSM PaymentHSM-9000 → RETIRED (EOL 2026-09-30)
- **PASS** `the-lifecycle-walk-names-the-devices-behind-the-product` — device(s): HSM-001
- **PASS** `and-the-applications-and-systems-above-them` — 2 application(s), 2 system(s)
- **PASS** `a-replacement-is-recorded-rather-than-implied` — replacement PaymentHSM-9100
- **PASS** `an-unknown-product-status-is-refused` — PROBABLY-FINE → UNKNOWN_PRODUCT_STATUS

## `network-appliance` — PASS

*do network appliances carry their fourteen facts* (review hbom / 6)

- **PASS** `an-appliance-carries-the-fourteen-facts-the-review-lists` — 14 of 14 facts present on payments-lb
- **PASS** `its-certificate-is-an-edge-not-a-string` — payments-lb PRESENTS cert:payments-edge
- **PASS** `its-hsm-offload-is-an-edge-too` — a load balancer may offload TLS to an HSM, and says so
- **PASS** `the-tls-capability-is-recorded-beside-the-certificate` — TLS1.2 with a hybrid ML-KEM key exchange offered
- **PASS** `a-router-is-not-an-appliance-this-builder-invents` — ROUTER → NOT_A_NETWORK_DEVICE rather than a guessed shape

## `impact-units` — PASS

*does the review's sentence become a number* (review hbom / 7)

- **PASS** `the-review-sentence-is-produced-from-the-graph` — HSM-001: 2 HSMs affected, 2 applications affected, 2 business systems affected, 3 cryptographic assets affected, 3 network paths affected; 5 node(s) only through a declared edge
- **PASS** `the-counts-are-numbers-a-ticket-can-quote` — 2 HSM, 2 applications, 2 systems, 3 crypto assets, 3 paths
- **PASS** `the-path-counts-the-appliances-as-well-as-the-endpoint` — 3 network path(s) including the load balancer
- **PASS** `nothing-is-counted-twice` — a device reached twice is one device, and the counts are sets

## `device-replaced` — PASS

*is a swapped device one event, not two* (review hbom / 9)

- **PASS** `a-swapped-unit-in-the-same-rack-slot-is-one-event` — 1 DEVICE_REPLACED event(s)
- **PASS** `it-is-not-reported-as-an-add-and-a-remove` — change types: DEVICE_REPLACED
- **PASS** `it-names-both-identities-so-the-audit-trail-survives` — HSM-001 → HSM-009 in the same bay
- **PASS** `a-device-in-a-free-bay-is-still-an-addition` — a new serial with no rack placement in common → DEVICE_ADDED
- **PASS** `the-replacement-carries-the-cryptography-behind-the-bay` — every event still carries its impact block

## `evidence-nodes` — PASS

*is the evidence walkable, not just listed* (review hbom / 13)

- **PASS** `every-cited-evidence-record-is-a-node-in-the-graph` — 1 EVIDENCE node(s): EVID-829182
- **PASS** `the-node-carries-the-hash-and-the-collector` — hash, collector, version and timestamp all travel with the node
- **PASS** `each-device-gets-an-evidenced_by-edge-to-it` — 15 EVIDENCED_BY edge(s) from 15 asset(s)
- **PASS** `an-evidence-edge-cannot-be-weaker-than-an-import` — name-match EVIDENCED_BY → CLAIM_WEAKER_THAN_RELATION_REQUIRES
- **PASS** `a-consumer-can-reach-the-evidence-from-the-device` — correlate('HSM-001') reaches EVID-829182

## `hsm-certificates` — PASS

*does an HSM's certificate graph reach it* (review hbom / 2 (certificates))

- **PASS** `a-certificate-an-hsm-holds-is-a-node` — 2 certificate node(s) in the hardware view
- **PASS** `the-holds-edge-runs-from-the-device-to-the-certificate` — HSM-001 HOLDS_CERTIFICATE cert:payments-root
- **PASS** `an-hsm-cannot-hold-a-key-reference-through-that-relation` — HOLDS_CERTIFICATE ends at a certificate, not at a key reference

## What this does not prove

- the fixture is a small bank estate; the shapes are real and the rows are not
- a certification is a record of an attestation, not the attestation itself: the expiry is what the collector read, and nothing here re-checks it
- a replaced device is inferred from the bay it sits in, so two devices swapped between bays are two replacements nobody can see
- product lifecycle status is what was recorded when the row was written
- evidence nodes are synthesised from the records a collector cited: an unrecorded observation has no node
