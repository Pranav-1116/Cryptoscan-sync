# Compliance rule authoring

Rules are versioned YAML under `services/policy/rule_definitions/`.
The engine loads every `*.yaml` at start. Validate a pack before shipping it by
loading it with the real engine, then running the rule suite:

```bash
.venv/bin/python -c "from policy.engine import PolicyEngine; \
print(len(PolicyEngine('services/policy/rule_definitions').rules), 'rules loaded')"
pytest services/policy/tests -q
```

Nothing is written to the database by either command: rules are code, and the
engine reads them from the pack on every start.

## File layout

```
rule_definitions/
  baseline/BASELINE-001-forbidden-legacy.yaml
  pci_dss/PCIDSS-006-pan-aead.yaml
  nist/NIST131A-006-hash-transition.yaml
  cnsa/CNSA-004-hybrid-mode.yaml
```

## Minimum fields

```yaml
id: PCIDSS-006
standard: PCI-DSS
version: "4.0"
title: PAN must use AEAD
enabled: true
severity: HIGH
condition:
  type: ALGORITHM_MODE_WHITELIST
  field: mode
  allowed: [GCM, CCM]
applies_when:
  purpose: ENCRYPTION
```

Allowed condition types: `ALGORITHM_IN_LIST`, `KEY_SIZE_MINIMUM`,
`ALGORITHM_MODE_WHITELIST`, `BOOLEAN_FLAG`, `TLS_VERSION_MINIMUM`,
`COMPLEX`. Scoped rules only fire when the owning system lists that
standard in `compliance_scopes`.

Never let a model write `overall_status`; the evaluator owns that field.
