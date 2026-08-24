"""
Rule validator — validates YAML normalization rules against schema
before loading into the registry.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from normalization.models.normalization_rule import NormalizationRule

logger = logging.getLogger(__name__)

# Required top-level keys in every rule file
_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"rule_id", "version", "raw_patterns", "normalized_output"}
)

# Required keys inside normalized_output
_REQUIRED_OUTPUT_KEYS: frozenset[str] = frozenset(
    {"algorithm", "algorithm_family", "standard_name"}
)


class RuleValidationError(Exception):
    """Raised when a normalization rule fails schema validation."""

    def __init__(self, rule_file: Path, message: str) -> None:
        self.rule_file = rule_file
        super().__init__(f"Rule validation failed for '{rule_file.name}': {message}")


class RuleValidator:
    """
    Validates normalization rule YAML files before they are loaded.

    Validation steps:
      1. YAML is parseable (no syntax errors)
      2. Required top-level keys are present
      3. raw_patterns is a non-empty list of strings
      4. normalized_output contains required fields
      5. Pydantic NormalizationRule model validates successfully
    """

    def validate_file(self, rule_file: Path) -> NormalizationRule:
        """
        Parse and validate a single YAML rule file.

        Args:
            rule_file: Path to the YAML rule file.

        Returns:
            Validated NormalizationRule instance.

        Raises:
            RuleValidationError: If validation fails for any reason.
        """
        if not rule_file.exists():
            raise RuleValidationError(rule_file, "File does not exist")

        if rule_file.suffix not in {".yaml", ".yml"}:
            raise RuleValidationError(rule_file, f"Unexpected file extension '{rule_file.suffix}'")

        # Step 1: Parse YAML
        try:
            raw_data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleValidationError(rule_file, f"YAML parse error: {exc}") from exc

        if not isinstance(raw_data, dict):
            raise RuleValidationError(rule_file, "YAML root must be a mapping (dict)")

        # Step 2: Required top-level keys
        self._check_required_keys(rule_file, raw_data, _REQUIRED_KEYS)

        # Step 3: raw_patterns validation
        self._validate_raw_patterns(rule_file, raw_data.get("raw_patterns"))

        # Step 4: normalized_output validation
        self._validate_normalized_output(rule_file, raw_data.get("normalized_output"))

        # Step 5: Pydantic model validation
        try:
            rule = NormalizationRule.model_validate(raw_data)
        except ValidationError as exc:
            raise RuleValidationError(
                rule_file,
                f"Pydantic validation failed:\n{exc}",
            ) from exc

        logger.debug(
            "Rule validated successfully",
            extra={"rule_id": rule.rule_id, "file": rule_file.name},
        )
        return rule

    def validate_directory(self, rules_dir: Path) -> list[NormalizationRule]:
        """
        Validate all YAML files in a directory tree.

        Args:
            rules_dir: Root directory to scan for YAML rule files.

        Returns:
            List of validated NormalizationRule instances.

        Raises:
            RuleValidationError: On first validation failure encountered.
        """
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        yaml_files = sorted(rules_dir.rglob("*.yaml")) + sorted(rules_dir.rglob("*.yml"))
        # Exclude schema/meta files
        yaml_files = [f for f in yaml_files if not f.name.startswith("_")]

        if not yaml_files:
            logger.warning("No YAML rule files found in '%s'", rules_dir)
            return []

        rules: list[NormalizationRule] = []
        errors: list[str] = []

        for rule_file in yaml_files:
            try:
                rule = self.validate_file(rule_file)
                rules.append(rule)
            except RuleValidationError as exc:
                errors.append(str(exc))
                logger.error("Rule validation failed: %s", exc)

        if errors:
            summary = "\n".join(errors)
            raise RuleValidationError(
                rules_dir,
                f"{len(errors)} rule(s) failed validation:\n{summary}",
            )

        logger.info(
            "All rules validated",
            extra={"count": len(rules), "directory": str(rules_dir)},
        )
        return rules

    # ── Private helpers ───────────────────────────────────────────────

    @staticmethod
    def _check_required_keys(
        rule_file: Path,
        data: dict[str, Any],
        required: frozenset[str],
    ) -> None:
        missing = required - set(data.keys())
        if missing:
            raise RuleValidationError(
                rule_file,
                f"Missing required keys: {sorted(missing)}",
            )

    @staticmethod
    def _validate_raw_patterns(rule_file: Path, raw_patterns: Any) -> None:
        if not isinstance(raw_patterns, list):
            raise RuleValidationError(
                rule_file,
                f"'raw_patterns' must be a list, got {type(raw_patterns).__name__}",
            )
        if len(raw_patterns) == 0:
            raise RuleValidationError(rule_file, "'raw_patterns' must not be empty")
        for i, pattern in enumerate(raw_patterns):
            if not isinstance(pattern, str):
                raise RuleValidationError(
                    rule_file,
                    f"'raw_patterns[{i}]' must be a string, got {type(pattern).__name__}",
                )
            if not pattern.strip():
                raise RuleValidationError(
                    rule_file,
                    f"'raw_patterns[{i}]' must not be blank",
                )

    @staticmethod
    def _validate_normalized_output(rule_file: Path, output: Any) -> None:
        if not isinstance(output, dict):
            raise RuleValidationError(
                rule_file,
                f"'normalized_output' must be a mapping, got {type(output).__name__}",
            )
        missing = _REQUIRED_OUTPUT_KEYS - set(output.keys())
        if missing:
            raise RuleValidationError(
                rule_file,
                f"'normalized_output' missing required keys: {sorted(missing)}",
            )