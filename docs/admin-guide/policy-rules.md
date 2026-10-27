# Policy rules

Rules live in `services/policy/rule_definitions/baseline/` as versioned YAML.

| ID | Condition | Meaning |
|---|---|---|
| BASELINE-001 | ALGORITHM_IN_LIST | DES, 3DES, RC4, MD5, SHA-1 are forbidden |
| BASELINE-002 | KEY_SIZE_MINIMUM | RSA must be ≥ 2048 bits |
| BASELINE-003 | ALGORITHM_MODE_WHITELIST | AES may use GCM/CCM/CTR; ECB/CBC fail |
| BASELINE-004 | BOOLEAN_FLAG | Hardcoded keys fail |

The engine evaluates every enabled rule against each evidence record. `overall_status` is the worst result (`FAIL` > `WARN` > `PASS`). AI never writes this field.

## Key-inventory pack (`key_inventory/`)

Rules over HSM / KMS / keystore / certificate **export metadata** (findings with `source.type = KEY_INVENTORY`,
produced when a key-export drop is scanned with `CRYPTOSCAN_KEY_INVENTORY=1`). They use the
`KEY_INVENTORY_ATTRIBUTE` condition and are `NOT_APPLICABLE` to code findings, so enabling them never changes a
source-scan gate.

| ID | Attribute · operator | Result | Meaning |
|---|---|---|---|
| KEYINV-001 | `exportability in [sensitive…, exportable under trusted key, …]` | FAIL | TR-31 / ICSF key marked exportable |
| KEYINV-002 | `key_block_version contains "TR-31 A"` | FAIL | key-variant binding (PCI PIN phase-out) |
| KEYINV-003 | `not_after date_before_today` | FAIL | expired key/certificate still listed |
| KEYINV-004 | `not_after date_within_days 90` | WARN | expiring within 90 days |
| KEYINV-005 | `last_used older_than_days 365` (needs `last_used`) | WARN | stale key — check reconciliation, retire |
| KEYINV-006 | `state in [Disabled, ARCHIVED, PendingDeletion, NOTRUST, …]` | WARN | non-active key still present |
| KEYINV-007 | `weak_binding is_true` | FAIL | payment key on variant LMK |
| KEYINV-008 | `extractable is_true` | FAIL | PKCS#11 `CKA_EXTRACTABLE` |
| KEYINV-009 | `exportable is_true` | FAIL | cloud KMS / Key Vault exportable key |

Operators: `equals`, `in`, `contains`, `is_true`, `date_before_today`, `date_within_days`, `older_than_days`, `missing`;
`result` is `FAIL` or `WARN`; `require_attributes` keeps a rule silent for exports that lack the field.
Write your own in the same shape — e.g. `attribute: rotation_enabled, operator: equals, value: "false"` for KMS keys
without automatic rotation.
