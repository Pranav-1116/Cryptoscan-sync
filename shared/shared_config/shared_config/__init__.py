"""Shared configuration: enterprise settings base and .env loading."""

from shared_config.base_settings import (
    KNOWN_WEAK_SECRETS,
    SENSITIVE_FIELD_MARKERS,
    VALID_ENVIRONMENTS,
    VALID_LOG_LEVELS,
    BaseSettings,
    ConfigurationError,
)
from shared_config.env_loader import find_env_file, load_env, repo_root

__all__ = [
    "BaseSettings",
    "ConfigurationError",
    "KNOWN_WEAK_SECRETS",
    "SENSITIVE_FIELD_MARKERS",
    "VALID_ENVIRONMENTS",
    "VALID_LOG_LEVELS",
    "find_env_file",
    "load_env",
    "repo_root",
]
