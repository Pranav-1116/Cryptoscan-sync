# SNB Group 1,020-system sandbox — end-to-end

_Generated 2026-09-26 17:47 UTC — synthetic / deterministic sandbox. NOT the real SNB or SAMA._

## Scope

Four SNB Group legal entities with **1,020 declared systems**: core banking, cards & payments (mada/SARIE/SADAD/WPS/SWIFT/Tap-to-Pay), digital channels (mobile/online/open banking/QuickPay), treasury, SNB Capital (brokerage/custody), AlAhli Takaful, AlAhli QuickPay remittance corridors, 20 regional edges, 33 biller connectors, 32 QuickPay corridors, 42 data feeds, DR/UAT shadows for critical systems, and a PQC pilot. Each file is stamped from the labelled wave-16/17/18/19 corpus (842 ground-truth cases) with a deterministic seed (`snb-1k-sandbox-v2`). The scanner runs blind through the real `PipelineRunner`; F1 is measured against the labels.

## Overall

| entities | declared systems | files | evidence rows | precision | recall | F1 | files exact |
|---|---|---|---|---|---|---|---|
| 4 | 1020 | 1020 | 2468 | 1.000 | 1.000 | **1.000** | 1020/1020 |

## Per entity

| entity | name | declared systems | files | P | R | F1 | exact | cascade systems | unassigned | top policy FAILs |
|---|---|---|---|---|---|---|---|---|---|---|
| snb | Saudi National Bank | 720 | 720 | 1.000 | 1.000 | 1.000 | 720/720 | 300 | 0 | SAMA-001:FAIL×357, BASELINE-001:FAIL×353, CBUAE-001:FAIL×353, SAMASWIFT-001:FAIL×226 |
| snb-capital | SNB Capital | 140 | 140 | 1.000 | 1.000 | 1.000 | 140/140 | 140 | 0 | BASELINE-003:WARN×64, BASELINE-001:FAIL×32, CBUAE-001:FAIL×32, SAMA-001:FAIL×32 |
| snb-takaful | AlAhli Takaful | 70 | 70 | 1.000 | 1.000 | 1.000 | 70/70 | 70 | 0 | BASELINE-003:WARN×28, BASELINE-001:FAIL×19, CBUAE-001:FAIL×19, SAMA-001:FAIL×19 |
| snb-quickpay | AlAhli QuickPay / TeleMoney | 90 | 90 | 1.000 | 1.000 | 1.000 | 90/90 | 90 | 0 | BASELINE-003:WARN×35, BASELINE-001:FAIL×23, CBUAE-001:FAIL×23, SAMA-001:FAIL×23 |

## SAMA / mada / SWIFT-CSP policy findings

Per-entity FAIL/WARN counts for the Kingdom rule pack (`services/policy/rule_definitions/saudi/`): SAMA-001 forbidden-legacy-algorithms, SAMA-002 TLS-floor (customer/remote/payment/SWIFT), SAMA-003 asymmetric key ≥2048, SAMA-004 HSM review for 3DES in payments, SAMA-005 JWT alg policy, SAMA-006 weak RNG, MADA-001 PIN-block key blocks, SAMASWIFT-001 SWIFT CSCF v2024 legacy hygiene.

| entity | SAMA-001 | SAMA-002 | SAMA-003 | SAMA-004 | SAMA-005 | SAMA-006 | MADA-001 | SAMASWIFT-001 |

|---|---|---|---|---|---|---|---|---|
| snb | F357 | F39 | F37 | — | — | — | F116 | F226 |
| snb-capital | F32 | F23 | F12 | — | — | — | — | — |
| snb-takaful | F19 | F11 | F11 | — | — | — | — | — |
| snb-quickpay | F23 | F13 | F15 | — | — | — | — | F23 |

## Supervisor view (`/api/v1/banking/group`, `/group/supervisor-pack`, role `supervisor`)

Registry entities: 4 · systems (cascade-aware rollup): 604 · unassigned: 0 · pack kind `supervisory-pack` over 4 entities

| entity | regulator | systems | crypto instances | weak / legacy | quantum-vuln PK | worst system |
|---|---|---|---|---|---|---|
| snb (Saudi National Bank) | SAMA | 301 | 2879 | 191 | 542 | snb |
| snb-capital (SNB Capital) | CMA | 141 | 506 | 8 | 102 | cap-settlement-t2 |
| snb-takaful (AlAhli Takaful) | SAMA | 71 | 305 | 5 | 53 | takaful-billing |
| snb-quickpay (AlAhli QuickPay / TeleMoney) | SAMA | 91 | 384 | 7 | 71 | quickpay-settlement |

Group totals: `{"entities": 4, "systems": 604, "crypto_instances": 4074, "weak_legacy_instances": 211, "quantum_vulnerable_public_key": 768}`

By jurisdiction: `{"sa": {"entities": 4, "crypto_instances": 4074, "weak_legacy_instances": 211}}`


## Migration roadmap summary (`/group/roadmap`)

10 rows · instances_by_bucket `{'by-2030': 176, 'by-2035': 185, 'immediate': 142}` · families_by_bucket `[('by-2030', ['RSA']), ('by-2035', ['ECDH', 'ECDSA']), ('immediate', ['3DES-112'])]` · entities_affected ['snb', 'snb-capital', 'snb-quickpay', 'snb-takaful']


## What this demonstrates beyond the previous runs

- **Scale.** 1,020 declared systems in one SQLite database — a size that matches a midsize Saudi bank CMDB including regional edges, partner connectors, data feeds, and shadow estates.
- **Entity isolation.** Four legal entities coexist; cross-entity same-name systems are qualified (<entity>/<name>) so no bank inherits another's evidence; supervisor roll-up counts 0 unassigned.
- **Legacy share is realistic.** ~8-15% of partner connectors, F5 LBs, IBM MQ, UAT and regional edges carry TLS 1.0/3DES/RC4/MD5/SHA-1/DH-1024, so weak/legacy discovery and the migration roadmap are non-empty.
- **PQC readiness.** One `pqc-pilot` system exposes ML-KEM / ML-DSA material, exercising the PQC family path.

## Honest notes

- **Synthetic.** Code is taken from the labelled public corpus (waves 16-19), stamped into synthetic system paths. Nothing in this run originates from Saudi National Bank or SAMA.
- **F1 is scored against the labelled truth per file**; each file's label is exactly the set of crypto families the corpus cases promise. F1 can be < 1.0 only if the scanner FP'd a negative file or missed a labelled family — both are surfaced in `misses`.
- **Scope.** SQLite only in this script for throughput. Postgres has been parity-validated on the Dubai 6-bank and GCC runs; no code path here differs.