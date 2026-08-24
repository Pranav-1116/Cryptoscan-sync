"""
Rule Loader - Loads policy rules from YAML files.

Scans a directory for YAML rule files and loads them into PolicyRule objects.
"""

from typing import List, Dict, Any
import logging
from pathlib import Path
import yaml

from policy.models.policy_rule import PolicyRule

logger = logging.getLogger(__name__)


class RuleLoader:
    """Loads policy rules from YAML files."""

    RULE_FILE_EXTENSION = ".yaml"

    def __init__(self, rules_directory: Path):
        """
        Initialize loader.
        
        Args:
            rules_directory: Path to directory containing rule YAML files
        """
        self.rules_directory = Path(rules_directory)
        if not self.rules_directory.exists():
            raise FileNotFoundError(
                f"Rules directory not found: {rules_directory}"
            )

    def load_all_rules(self) -> List[PolicyRule]:
        """
        Load all YAML rule files from the rules directory.
        
        Returns:
            List of loaded PolicyRule objects
        """
        rules = []
        
        # Find all YAML files
        yaml_files = list(
            self.rules_directory.glob(f"**/*{self.RULE_FILE_EXTENSION}")
        )
        
        logger.info(f"Found {len(yaml_files)} rule files")
        
        for yaml_file in yaml_files:
            try:
                rule = self.load_rule_from_file(yaml_file)
                rules.append(rule)
                logger.debug(f"Loaded rule: {rule.rule_id}")
            except Exception as e:
                logger.error(
                    f"Failed to load rule file {yaml_file}",
                    extra={"error": str(e)},
                    exc_info=True
                )
        
        return rules

    def load_rule_from_file(self, file_path: Path) -> PolicyRule:
        """
        Load a single rule from a YAML file.
        
        Args:
            file_path: Path to YAML rule file
        
        Returns:
            Loaded PolicyRule object
        
        Raises:
            FileNotFoundError: If file doesn't exist
            yaml.YAMLError: If YAML is invalid
            ValueError: If rule is invalid
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Rule file not found: {file_path}")
        
        logger.debug(f"Loading rule from: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {file_path}: {str(e)}")
        
        if not data:
            raise ValueError(f"Empty YAML file: {file_path}")
        
        # Parse into PolicyRule (Pydantic will validate)
        rule = PolicyRule(**data)
        
        return rule

    def load_rule_from_dict(self, rule_dict: Dict[str, Any]) -> PolicyRule:
        """
        Load a rule from a dictionary.
        
        Args:
            rule_dict: Dictionary containing rule data
        
        Returns:
            Loaded PolicyRule object
        """
        return PolicyRule(**rule_dict)