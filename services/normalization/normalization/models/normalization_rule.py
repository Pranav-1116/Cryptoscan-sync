"""
Normalization rule data model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class NormalizationRule:
    """
    Represents a single normalization rule from YAML.

    Accepts both loader-style (pattern/output) and registry-style
    (raw_patterns/normalized_output) constructors.
    """

    pattern: str = ""
    output: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    source_file: str = ""
    rule_id: str = ""
    version: str = "1.0"
    raw_patterns: List[str] = field(default_factory=list)
    normalized_output: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.raw_patterns and not self.pattern:
            self.pattern = self.raw_patterns[0]
        if self.pattern and not self.raw_patterns:
            self.raw_patterns = [self.pattern]

        if self.normalized_output and not self.output:
            self.output = dict(self.normalized_output)
        if self.output and not self.normalized_output:
            self.normalized_output = dict(self.output)

        if not self.pattern and not self.raw_patterns:
            raise ValueError("Rule pattern cannot be empty")

        if not self.output and not self.normalized_output:
            raise ValueError("Rule output cannot be empty")

        if "algorithm" not in self.output:
            raise ValueError(f"Rule {self.pattern} missing 'algorithm' in output")

        if not self.rule_id:
            self.rule_id = f"NORM-{self.pattern}"
