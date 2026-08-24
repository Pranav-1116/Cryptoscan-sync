"""
Environment File Loader
Loads .env files with validation
"""
import os
from pathlib import Path
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


def load_env_file(env_file: Optional[str] = None) -> Dict[str, str]:
    """
    Load environment variables from .env file
    
    Args:
        env_file: Path to .env file (default: .env in current dir)
    
    Returns:
        Dictionary of environment variables
    """
    if env_file is None:
        env_file = ".env"
    
    env_path = Path(env_file)
    
    if not env_path.exists():
        logger.warning(f"Environment file not found: {env_path}")
        return {}
    
    env_vars = {}
    
    with open(env_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Parse KEY=VALUE
            if '=' not in line:
                logger.warning(f"Invalid line {line_num} in {env_file}: {line}")
                continue
            
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            
            # Remove quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            
            env_vars[key] = value
            
            # Set in os.environ (for Pydantic to pick up)
            os.environ[key] = value
    
    logger.info(f"Loaded {len(env_vars)} environment variables from {env_file}")
    return env_vars


def validate_required_vars(required_vars: list):
    """
    Validate that required environment variables are set
    
    Raises:
        ValueError: If any required variable is missing
    """
    missing = []
    
    for var in required_vars:
        if var not in os.environ:
            missing.append(var)
    
    if missing:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing)}"
        )