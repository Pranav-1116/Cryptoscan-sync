"""Enterprise settings base used by every CryptoScan service.

Provides the cross-cutting configuration contract so individual services do
not each reinvent it:

- environment validation (development / staging / test / production),
- log-level validation,
- secret redaction (``redacted()`` / masked ``repr`` — secrets must never
  leak into logs or error reports),
- a fail-closed production gate (``validate_for_production()``) backed by a
  canonical weak-secret registry,
- an extensible ``production_violations()`` hook for service-specific checks.

Subclasses keep their own fields; behaviour added here applies everywhere.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from pydantic import field_validator
from pydantic_settings import BaseSettings as PydanticBaseSettings, SettingsConfigDict

#: Canonical registry of secrets that must never reach a production deployment.
KNOWN_WEAK_SECRETS: frozenset[str] = frozenset(
    {
        "dev-cryptoscan-secret-key-change-in-production-32",
        "change-me-to-a-random-64-character-secret-key-please",
        "change-this-secret-in-production-32chars",
    }
)

#: Substrings that mark a settings field as sensitive (case-insensitive).
SENSITIVE_FIELD_MARKERS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "token",
        "key",  # SECRET_KEY, API_KEY, ACCESS_KEY ... but not "key_size"
    }
)

VALID_ENVIRONMENTS: frozenset[str] = frozenset(
    {"development", "staging", "test", "production"}
)

VALID_LOG_LEVELS: frozenset[str] = frozenset(
    {"CRITICAL", "FATAL", "ERROR", "WARNING", "WARN", "INFO", "DEBUG", "NOTSET"}
)

MIN_SECRET_KEY_LENGTH = 32


class ConfigurationError(RuntimeError):
    """Raised when configuration is invalid or unsafe for the target environment."""


def _is_sensitive_field(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith("_size") or lowered in {"keys", "key_sizes"}:
        return False
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


class BaseSettings(PydanticBaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow",
        case_sensitive=False,
    )

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"

    _NORMALIZED_ENVIRONMENTS: ClassVar[dict[str, str]] = {
        "dev": "development",
        "local": "development",
        "testing": "test",
        "prod": "production",
    }

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def _normalize_environment(cls, value: Any) -> str:
        env = str(value or "development").strip().lower()
        env = cls._NORMALIZED_ENVIRONMENTS.get(env, env)
        if env not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"ENVIRONMENT must be one of {sorted(VALID_ENVIRONMENTS)}, got {value!r}"
            )
        return env

    @field_validator("LOG_LEVEL", mode="before")
    @classmethod
    def _validate_log_level(cls, value: Any) -> str:
        level = str(value or "INFO").strip().upper()
        if level not in VALID_LOG_LEVELS:
            raise ValueError(
                f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}, got {value!r}"
            )
        return level

    # ------------------------------------------------------------------ #
    # Environment predicates
    # ------------------------------------------------------------------ #

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_staging(self) -> bool:
        return self.ENVIRONMENT.lower() == "staging"

    @property
    def is_test(self) -> bool:
        return self.ENVIRONMENT.lower() == "test"

    @property
    def is_development(self) -> bool:
        return not (self.is_production or self.is_staging)

    @property
    def numeric_log_level(self) -> int:
        return getattr(logging, self.LOG_LEVEL.upper(), logging.INFO)

    # ------------------------------------------------------------------ #
    # Secret hygiene
    # ------------------------------------------------------------------ #

    def sensitive_fields(self) -> list[str]:
        """Names of fields whose values must never be printed."""
        return sorted(
            name for name in type(self).model_fields if _is_sensitive_field(name)
        )

    def redacted(self) -> dict[str, Any]:
        """Model dump with every sensitive value replaced by ``[REDACTED]``."""
        dump = self.model_dump()
        for field in self.sensitive_fields():
            if field in dump and dump[field]:
                dump[field] = "[REDACTED]"
        return dump

    def __repr__(self) -> str:  # noqa: D105 — keep pydantic-style body
        sensitive = set(self.sensitive_fields())
        fields = ", ".join(
            f"{name}={'[REDACTED]' if name in sensitive and value else value!r}"
            for name, value in (
                (name, getattr(self, name)) for name in type(self).model_fields
            )
        )
        return f"{type(self).__name__}({fields})"

    # ------------------------------------------------------------------ #
    # Production gate
    # ------------------------------------------------------------------ #

    def production_violations(self) -> list[str]:
        """Human-readable configuration violations for a production run.

        Extend (do not replace) in subclasses::

            def production_violations(self):
                violations = super().production_violations()
                if not self.MY_REQUIRED_URL:
                    violations.append("MY_REQUIRED_URL is required")
                return violations
        """
        violations: list[str] = []
        secret = (getattr(self, "SECRET_KEY", "") or "").strip()
        if len(secret) < MIN_SECRET_KEY_LENGTH or secret in KNOWN_WEAK_SECRETS:
            violations.append(
                f"SECRET_KEY must be a unique value of at least {MIN_SECRET_KEY_LENGTH} characters"
            )
        return violations

    def validate_for_production(self) -> None:
        """Fail closed: raise :class:`ConfigurationError` in production with
        any demo/insecure defaults still configured."""
        if not self.is_production:
            return
        violations = self.production_violations()
        if violations:
            raise ConfigurationError(
                "production configuration rejected: " + "; ".join(violations)
            )
