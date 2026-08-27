#!/usr/bin/env python3
"""Load and validate every policy YAML rule in the pack."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RULES = ROOT / "services" / "policy" / "rule_definitions"


def main() -> None:
    from policy.rules.rule_loader import RuleLoader

    rules = RuleLoader(RULES).load_all_rules()
    if not rules:
        raise SystemExit(f"no rules loaded from {RULES}")
    by_standard: dict[str, int] = {}
    for rule in rules:
        key = getattr(rule, "standard_reference", None) or getattr(rule, "standard", None) or "unknown"
        by_standard[str(key)] = by_standard.get(str(key), 0) + 1
        rule_id = getattr(rule, "rule_id", None) or getattr(rule, "id", None)
        print(f"ok {rule_id} enabled={getattr(rule, 'enabled', True)}")
    print(f"loaded={len(rules)} groups={by_standard}")


if __name__ == "__main__":
    main()
