# SNB Group 1,020-system sandbox — end-to-end

_Generated 2026-09-26 14:04 UTC — synthetic / deterministic sandbox. NOT the real SNB or SAMA._

## Scope

Four SNB Group legal entities with **1,020 declared systems**: core banking, cards & payments (mada/SARIE/SADAD/WPS/SWIFT/Tap-to-Pay), digital channels (mobile/online/open banking/QuickPay), treasury, SNB Capital (brokerage/custody), AlAhli Takaful, AlAhli QuickPay remittance corridors, 20 regional edges, 33 biller connectors, 32 QuickPay corridors, 42 data feeds, DR/UAT shadows for critical systems, and a PQC pilot. Each file is stamped from the labelled wave-16/17/18/19 corpus (842 ground-truth cases) with a deterministic seed (`snb-1k-sandbox-v2`). The scanner runs blind through the real `PipelineRunner`; F1 is measured against the labels.

## Overall

| entities | declared systems | files | evidence rows | precision | recall | F1 | files exact |
|---|---|---|---|---|---|---|---|
| 4 | 1020 | 1020 | 2468 | 1.000 | 1.000 | **1.000** | 1020/1020 |

## Per entity

| entity | name | declared systems | files | P | R | F1 | exact | cascade systems | unassigned |
|---|---|---|---|---|---|---|---|---|---|
| snb | Saudi National Bank | 720 | 720 | 1.000 | 1.000 | 1.000 | 720/720 | 720 | 0 |
| snb-capital | SNB Capital | 140 | 140 | 1.000 | 1.000 | 1.000 | 140/140 | 140 | 0 |
| snb-takaful | AlAhli Takaful | 70 | 70 | 1.000 | 1.000 | 1.000 | 70/70 | 70 | 0 |
| snb-quickpay | AlAhli QuickPay / TeleMoney | 90 | 90 | 1.000 | 1.000 | 1.000 | 90/90 | 90 | 0 |

## Supervisor view (`/api/v1/banking/group`, `/group/supervisor-pack`, role `supervisor`)

Registry entities: 4 · systems total (DB): 1024 · unassigned: 0 · pack kind `supervisory-pack` over 4 entities

| entity | regulator | systems | crypto instances | weak / legacy | quantum-vulnerable PK | worst system |
|---|---|---|---|---|---|---|
| snb | SAMA | 721 | 2879 | 191 | 542 | biller-medgulf |
| snb-capital | CMA | 141 | 506 | 8 | 102 | cap-settlement-t2 |
| snb-takaful | SAMA | 71 | 305 | 5 | 53 | takaful-billing |
| snb-quickpay | SAMA | 91 | 384 | 7 | 71 | quickpay-settlement |

Group totals: `{"entities": 4, "systems": 1024, "crypto_instances": 4074, "weak_legacy_instances": 211, "quantum_vulnerable_public_key": 768}`

By jurisdiction: `{"sa": {"entities": 4, "crypto_instances": 4074, "weak_legacy_instances": 211}}`


## Migration roadmap summary (`/group/roadmap`)

10 rows · instances_by_bucket `{'immediate': 142, 'by-2030': 176, 'by-2035': 185}` · families_by_bucket `[('immediate', 1), ('by-2030', 1), ('by-2035', 2)]` · entities_affected ['snb', 'snb-capital', 'snb-quickpay', 'snb-takaful']


## What this demonstrates beyond the previous runs

- **Scale.** 1,020 declared systems in one SQLite database — a size that matches a midsize Saudi bank CMDB including regional edges, partner connectors, data feeds, and shadow estates.
- **Entity isolation.** Four legal entities coexist; cross-entity same-name systems are qualified (<entity>/<name>) so no bank inherits another's evidence; supervisor roll-up counts 0 unassigned.
- **Legacy share is realistic.** ~8-15% of partner connectors, F5 LBs, IBM MQ, UAT and regional edges carry TLS 1.0/3DES/RC4/MD5/SHA-1/DH-1024, so weak/legacy discovery and the migration roadmap are non-empty.
- **PQC readiness.** One `pqc-pilot` system exposes ML-KEM / ML-DSA material, exercising the PQC family path.


## Product defects found and fixed in this round

- **Cascade truncation hid systems at scale.** `_bounded_cascade()` in `pipeline_runner.py` and `stage_scan.py` capped `systems`, `libraries`, `shared_keys`, `key_references`, `weak_parameters` at 300 entries and `providers` at 500. On a 1,020-system estate the cascade in `Scan.statistics.cascade.systems` was silently truncated to 300, which then caused `_sync_declared_systems` to register only 300/720 SNB systems and the supervisor roll-up to report 604 systems instead of 1,024. Caps raised to 5,000 lists / 20,000 providers (cascade entries are compact per-system counts, so even 5k ≈ a few MB of JSON).
- **Supervisor pack entity summary dropped key fields.** `cbom.supervisor.supervisor_pack()` was writing `{code,name,jurisdiction,lei}` into the pack entities list and omitting `regulator`, `country`, `systems`, `crypto_instances`, `weak_legacy_instances`, `quantum_vulnerable_public_key`, `top_families`, `worst_system`, `generated_for` — even though the entity rollups already computed them. The UI saw blank rows. Fixed to mirror the roll-up fields (matching `/banking/group`).

## Honest notes

- **Synthetic.** Code is taken from the labelled public corpus (waves 16-19), stamped into synthetic system paths. Nothing in this run originates from Saudi National Bank or SAMA.
- **F1 is scored against the labelled truth per file**; each file's label is exactly the set of crypto families the corpus cases promise. F1 can be < 1.0 only if the scanner FP'd a negative file or missed a labelled family — both are surfaced in `misses`.
- **Scope.** SQLite only in this script for throughput. Postgres has been parity-validated on the Dubai 6-bank and GCC runs; no code path here differs.