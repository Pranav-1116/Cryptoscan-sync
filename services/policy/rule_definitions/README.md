# Policy rules

YAML files in `baseline/` are loaded at engine start. They are the source of
truth for compliance — not the AI layer.

| Rule | Meaning |
|------|---------|
| BASELINE-001 | Forbidden algorithms (DES, 3DES, RC4, MD5, SHA-1) |
| BASELINE-002 | RSA key size ≥ 2048 |
| BASELINE-003 | AES modes: GCM/CCM/CTR only |
| BASELINE-004 | No hardcoded keys |

Add a new file, open a PR, and the next worker restart picks it up.
