"""
Rule loader - loads normalization rules from YAML files.
"""
import logging
from pathlib import Path
from typing import List, Dict, Any
import yaml
from ..models.normalization_rule import NormalizationRule

logger = logging.getLogger(__name__)


class RuleLoader:
    """
    Loads normalization rules from YAML files.
    
    Rules are organized by algorithm family in separate files:
    - symmetric/aes.yaml
    - asymmetric/rsa.yaml
    - hashing/sha2.yaml
    etc.
    """
    
    def __init__(self, rules_directory: str):
        """
        Initialize rule loader.
        
        Args:
            rules_directory: Path to rule_definitions directory
        """
        self.rules_directory = Path(rules_directory)
        
        if not self.rules_directory.exists():
            raise ValueError(f"Rules directory not found: {self.rules_directory}")
    
    def load_all_rules(self) -> List[NormalizationRule]:
        """
        Load all normalization rules from YAML files.
        
        Returns:
            List of normalization rules
        """
        all_rules = []
        
        # Walk through all YAML files
        for yaml_file in self.rules_directory.rglob("*.yaml"):
            logger.info(f"Loading rules from {yaml_file}")
            
            try:
                rules = self._load_rules_from_file(yaml_file)
                all_rules.extend(rules)
            except Exception as e:
                logger.error(f"Failed to load {yaml_file}: {e}")
                raise
        
        logger.info(f"Loaded {len(all_rules)} total normalization rules")
        return all_rules
    
    def _load_rules_from_file(self, yaml_file: Path) -> List[NormalizationRule]:
        """
        Load rules from a single YAML file.
        
        Args:
            yaml_file: Path to YAML file
            
        Returns:
            List of rules from this file
        """
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
        
        if not isinstance(data, dict):
            raise ValueError(f"Invalid YAML structure in {yaml_file}")
        
        rules = []
        
        # YAML format:
        # rules:
        #   - pattern: "DES"
        #     output:
        #       algorithm: "DES"
        #       key_size: 56
        #       ...
        
        for rule_data in data.get('rules', []):
            rule = NormalizationRule(
                pattern=rule_data['pattern'],
                output=rule_data['output'],
                description=rule_data.get('description', ''),
                source_file=str(yaml_file.name),
            )
            rules.append(rule)
        
        return rules
    
    def validate_rules(self, rules: List[NormalizationRule]) -> bool:
        """
        Validate that rules are well-formed.
        
        Args:
            rules: List of rules to validate
            
        Returns:
            True if all rules are valid
            
        Raises:
            ValueError: If any rule is invalid
        """
        for rule in rules:
            # Check required fields
            if not rule.pattern:
                raise ValueError("Rule missing pattern field")
            
            if not rule.output:
                raise ValueError(f"Rule {rule.pattern} missing output field")
            
            # Check output has required algorithm field
            if 'algorithm' not in rule.output:
                raise ValueError(f"Rule {rule.pattern} output missing 'algorithm' field")
        
        return True