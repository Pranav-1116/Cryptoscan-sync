"""Built-in policy rules and pack loading.

Modules:
- rule_loader: Rule Loader - Loads policy rules from YAML files
- rule_registry: Rule Registry - In-memory registry of loaded policy rules
- rule_validator: Rule Validator - Validates policy rules for correctness
- rule_conflicts: Cross-rule conflict detection - duplicate/shadowed/
  contradictory/overlapping rules across the loaded pack (audit 65)
"""
