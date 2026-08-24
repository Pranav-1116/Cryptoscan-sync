"""Load normalization rules from YAML (single-doc or multi-doc)."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from normalization.models.normalization_rule import NormalizationRule

logger = logging.getLogger(__name__)


class RuleLoader:
    def __init__(self, rules_directory: str | Path | None = None):
        self.rules_directory = Path(rules_directory) if rules_directory else None

    def load_from_directory(self, directory: str | Path) -> list[NormalizationRule]:
        self.rules_directory = Path(directory)
        return self.load_all_rules()

    def load_all_rules(self) -> list[NormalizationRule]:
        if self.rules_directory is None:
            raise ValueError("Rules directory not set")
        if not self.rules_directory.exists():
            raise ValueError(f"Rules directory not found: {self.rules_directory}")
        all_rules: list[NormalizationRule] = []
        for yaml_file in self.rules_directory.rglob("*.yaml"):
            if yaml_file.name.startswith("_") or yaml_file.name.lower() == "readme.yaml":
                continue
            all_rules.extend(self._load_rules_from_file(yaml_file))
        logger.info("normalization_rules_loaded", extra={"count": len(all_rules)})
        return all_rules

    def _load_rules_from_file(self, yaml_file: Path) -> list[NormalizationRule]:
        text = yaml_file.read_text(encoding="utf-8")
        documents = list(yaml.safe_load_all(text))
        rules: list[NormalizationRule] = []
        for data in documents:
            if not data:
                continue
            if isinstance(data, dict) and "rules" in data:
                for rule_data in data["rules"]:
                    rules.extend(self._from_entry(rule_data, yaml_file))
                continue
            if isinstance(data, dict):
                rules.extend(self._from_entry(data, yaml_file))
        return rules

    def _from_entry(self, data: dict, yaml_file: Path) -> list[NormalizationRule]:
        output = data.get("normalized_output") or data.get("output") or {}
        patterns = list(data.get("raw_patterns") or [])
        if data.get("pattern") and data["pattern"] not in patterns:
            patterns.insert(0, data["pattern"])
        if not patterns or not output.get("algorithm"):
            return []
        return [
            NormalizationRule(
                rule_id=data.get("rule_id", ""),
                version=str(data.get("version") or "1.0"),
                description=data.get("description", ""),
                source_file=yaml_file.name,
                raw_patterns=[str(p) for p in patterns],
                normalized_output=dict(output),
                pattern=str(patterns[0]),
                output=dict(output),
            )
        ]

    def validate_rules(self, rules: list[NormalizationRule]) -> bool:
        for rule in rules:
            if not rule.raw_patterns or "algorithm" not in (rule.normalized_output or rule.output):
                raise ValueError(f"Invalid rule: {rule}")
        return True
