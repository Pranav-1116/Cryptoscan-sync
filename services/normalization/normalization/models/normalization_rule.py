"""
Normalization rule data model.
"""
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class NormalizationRule:
    """
    Represents a single normalization rule from YAML.
    
    Example:
        pattern: "DES"
        output:
            algorithm: "DES"
            key_size: 56
            mode: "ECB"
            algorithm_family: "symmetric"
    """
    
    pattern: str  # Input pattern to match (e.g., "DES", "AES/GCM/NoPadding")
    output: Dict[str, Any]  # Normalized output structure
    description: str = ""  # Human-readable description
    source_file: str = ""  # YAML file this rule came from
    
    def __post_init__(self):
        """Validate rule after initialization."""
        if not self.pattern:
            raise ValueError("Rule pattern cannot be empty")
        
        if not self.output:
            raise ValueError("Rule output cannot be empty")
        
        if 'algorithm' not in self.output:
            raise ValueError(f"Rule {self.pattern} missing 'algorithm' in output")