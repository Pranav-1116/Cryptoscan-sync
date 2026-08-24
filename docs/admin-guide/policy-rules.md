# Policy rules

Rules live in `services/policy/rule_definitions/baseline/` as versioned YAML.

| ID | Condition | Meaning |
|---|---|---|
| BASELINE-001 | ALGORITHM_IN_LIST | DES, 3DES, RC4, MD5, SHA-1 are forbidden |
| BASELINE-002 | KEY_SIZE_MINIMUM | RSA must be ≥ 2048 bits |
| BASELINE-003 | ALGORITHM_MODE_WHITELIST | AES may use GCM/CCM/CTR; ECB/CBC fail |
| BASELINE-004 | BOOLEAN_FLAG | Hardcoded keys fail |

The engine evaluates every enabled rule against each evidence record. `overall_status` is the worst result (`FAIL` > `WARN` > `PASS`). AI never writes this field.
