# Dubai banks — every estate through the whole product, plus the supervisory view

_Generated 2026-09-26T10:03:19.780877+00:00 by `scripts/dubai_banks_e2e.py` on **sqlite**._

**What this is.** Six representative Dubai-headquartered bank estates (conventional, Islamic, digital-forward, a DIFC branch under
the DFSA) composed from the blind-labelled corpus waves, each with its own `cryptoscan-systems.yml` (systems, criticality,
dependencies, compliance scopes, legal entity), run through the full pipeline into one database, scored against the labels,
and read back through the HTTP API as a bank analyst and as a CBUAE supervisor.

**What this is not.** Not the banks' code, configuration or key material — no bank system was accessed. The names fix the
*shape* of each estate. Numbers describe the product on code of that shape.

## Overall

| banks | files | evidence rows | precision | recall | F1 | files exact |
|---|---|---|---|---|---|---|
| 6 | 100 | 540 | 1.000 | 1.000 | **1.000** | 100/100 |

## Per bank (through pipeline + database)

| bank | entity | systems | files | rows | P | R | F1 | exact | failing rules (instances) |
|---|---|---|---|---|---|---|---|---|---|
| enbd | Emirates NBD | 8 | 28 | 146 | 1.000 | 1.000 | 1.000 | 28/28 | CBUAE-001 (14), CBUAE-002 (4), CBUAE-003 (5), CBUAE-004 (1), DIFC-001 (1), PDPL-001 (2), PDPL-002 (2) |
| mashreq | Mashreq | 6 | 19 | 130 | 1.000 | 1.000 | 1.000 | 19/19 | CBUAE-001 (4), CBUAE-003 (2), CBUAE-004 (2), PDPL-001 (2) |
| dib | Dubai Islamic Bank | 6 | 18 | 80 | 1.000 | 1.000 | 1.000 | 18/18 | CBUAE-001 (30), CBUAE-002 (2), CBUAE-003 (5), CBUAE-004 (1), PDPL-001 (5), PDPL-002 (5) |
| cbd | Commercial Bank of Dubai | 5 | 14 | 86 | 1.000 | 1.000 | 1.000 | 14/14 | CBUAE-001 (5), CBUAE-002 (2), CBUAE-003 (1), PDPL-001 (2) |
| ei | Emirates Islamic | 4 | 11 | 67 | 1.000 | 1.000 | 1.000 | 11/11 | CBUAE-001 (6), CBUAE-002 (4), CBUAE-004 (1), PDPL-001 (2) |
| cbi | Commercial Bank International | 4 | 10 | 31 | 1.000 | 1.000 | 1.000 | 10/10 | CBUAE-001 (12), CBUAE-003 (6), PDPL-001 (2), PDPL-002 (2) |

### Files not exact

_none_

### Jurisdiction rules applied per system (PASS/FAIL/WARN — out-of-scope rules are NOT_APPLICABLE and omitted)

- enbd / AANI-IPP: CBUAE-001, CBUAE-004, CBUAE-005
- enbd / BRANCH-INFRA: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- enbd / CARD-SWITCH: CBUAE-001, CBUAE-002
- enbd / CORE-KYC: CBUAE-001, PDPL-001, PDPL-002
- enbd / DIFC-WEALTH: CBUAE-001, DIFC-001, DIFC-002
- enbd / IDENTITY: CBUAE-001, PDPL-001, PDPL-002
- enbd / OPEN-FINANCE: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- enbd / PQC-PILOT: CBUAE-001, CBUAE-004, CBUAE-005
- mashreq / AANI-IPP: CBUAE-001, CBUAE-004, CBUAE-005
- mashreq / CORE: CBUAE-001, PDPL-001, PDPL-002
- mashreq / EDGE-INFRA: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- mashreq / IDENTITY: CBUAE-001, PDPL-002
- mashreq / NEO-MOBILE: CBUAE-001, CBUAE-003, CBUAE-005
- mashreq / OPEN-FINANCE: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- dib / AANI-IPP: CBUAE-001, CBUAE-004, CBUAE-005
- dib / CARD-SWITCH: CBUAE-001, CBUAE-002
- dib / CORE-ISLAMIC: CBUAE-001, PDPL-001, PDPL-002
- dib / INFRA: CBUAE-001, CBUAE-003
- dib / KYC: CBUAE-001, PDPL-001, PDPL-002
- dib / MOBILE: CBUAE-001, CBUAE-003, CBUAE-005
- cbd / CARD-SWITCH: CBUAE-001, CBUAE-002
- cbd / CORE: CBUAE-001, PDPL-001, PDPL-002
- cbd / INFRA: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- cbd / TREASURY: CBUAE-001, CBUAE-004, CBUAE-005
- cbd / WPS-FTA: CBUAE-001, CBUAE-004
- ei / CARDS: CBUAE-001, CBUAE-002
- ei / CORE: CBUAE-001, PDPL-001, PDPL-002
- ei / INFRA: CBUAE-001, CBUAE-003, CBUAE-004, CBUAE-005
- ei / MOBILE: CBUAE-001, CBUAE-003, CBUAE-005
- cbi / CORE: CBUAE-001, PDPL-001, PDPL-002
- cbi / IDENTITY: CBUAE-001, PDPL-001, PDPL-002
- cbi / INFRA: CBUAE-001, CBUAE-003
- cbi / WPS: CBUAE-001

## Through the API

| bank | scan status | findings via API | cascade systems via API |
|---|---|---|---|
| enbd | COMPLETED | 146 | 8 |
| mashreq | COMPLETED | 130 | 6 |
| dib | COMPLETED | 80 | 6 |
| cbd | COMPLETED | 86 | 5 |
| ei | COMPLETED | 67 | 4 |
| cbi | COMPLETED | 31 | 4 |

Readonly session posting a triage → HTTP 403. Field accuracy endpoint → `NO_FIELD_DATA` (no bank has published a review; nothing is invented).

## Supervisor view (`/api/v1/banking/group`, `/group/supervisor-pack`, `/group/roadmap`, role `supervisor`)

Registry entities: 7 · systems total: 39 · unassigned to an entity: 0 · pack: `supervisory-pack` over 7 entities

| entity | regulator | systems | crypto instances | weak / legacy | quantum-vulnerable public-key | worst system | top families |
|---|---|---|---|---|---|---|---|
| enbd | CBUAE | 8 | 116 | 7 | 27 | CARD-SWITCH | X509 12, AES 12, JWT 9, SHA-256-256 6, 3DES-112 6 |
| enbd-difc | DFSA | 1 | 11 | 0 | 0 | DIFC-WEALTH | AES 4, HMAC-SHA-256-256 4, SHA-256-256 1, AES-256 1, UNKNOWN 1 |
| mashreq | CBUAE | 7 | 108 | 0 | 26 | mashreq-estate | AES 12, X509 11, SHA-256-256 10, JWT 10, ECDSA 8 |
| dib | CBUAE | 7 | 69 | 18 | 5 | dib/CARD-SWITCH | 3DES-112 14, AES 8, X509 7, UNKNOWN 5, AES-256 5 |
| cbd | CBUAE | 6 | 70 | 4 | 14 | cbd/CARD-SWITCH | AES 13, HMAC-SHA-256-256 6, SHA-256-256 6, RSA 6, SHA-384-384 5 |
| ei | CBUAE | 5 | 62 | 6 | 13 | CARDS | AES 14, 3DES-112 6, ECDSA 5, X509 4, UNKNOWN 4 |
| cbi | CBUAE | 5 | 29 | 4 | 1 | cbi/INFRA | AES 5, X509 4, SHA-256-256 3, RC4 3, UNKNOWN 2 |

Group totals: `{"entities": 7, "systems": 39, "crypto_instances": 465, "weak_legacy_instances": 39, "quantum_vulnerable_public_key": 86}` · by jurisdiction: `{"ae": {"entities": 6, "crypto_instances": 454, "weak_legacy_instances": 39}, "difc": {"entities": 1, "crypto_instances": 11, "weak_legacy_instances": 0}}` · roadmap: `{"rows": 18, "instances_by_bucket": {"immediate": 37, "by-2030": 15, "by-2035": 32}, "families_by_bucket": {"immediate": 2, "by-2030": 1, "by-2035": 4}, "entities_affected": ["cbd", "cbi", "dib", "ei", "enbd", "mashreq"]}`

## How to read this

- Accuracy is scored per file × algorithm family on the evidence rows the pipeline persisted — after dedup, normalisation and the database round-trip — against labels written before any scan.
- Each system's `legal_entity` in `cryptoscan-systems.yml` is what puts it under a bank in the supervisor view; `compliance_scopes` is what selects the CBUAE / DFSA (DIFC) / PDPL rules. Both are declarations a bank makes, not inferences.
- The supervisor sees posture per legal entity and the group; a bank analyst sees its scans and findings. Publishing a triage review needs an analyst/CISO/auditor role.
- Regenerate: `python scripts/dubai_banks_e2e.py --md docs/accuracy/DUBAI-BANKS-E2E.md --json docs/accuracy/dubai-banks-e2e.json [--backend postgresql]`.
