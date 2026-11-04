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
from shared_config.environment import (
    ENVIRONMENT_ALIASES,
    detect,
    describe,
    environment_name,
    is_development,
    is_production,
    is_staging,
    is_test,
    normalise,
)

__all__ = [
    "BaseSettings",
    "ENVIRONMENT_ALIASES",
    "ConfigurationError",
    "KNOWN_WEAK_SECRETS",
    "SENSITIVE_FIELD_MARKERS",
    "VALID_ENVIRONMENTS",
    "VALID_LOG_LEVELS",
    "describe",
    "detect",
    "environment_name",
    "find_env_file",
    "is_development",
    "is_production",
    "is_staging",
    "is_test",
    "load_env",
    "normalise",
    "repo_root",
]
