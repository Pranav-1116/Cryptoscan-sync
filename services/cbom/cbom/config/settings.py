"""CBOM generator / signing settings (enterprise)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _flag(*names: str) -> bool:
    for name in names:
        if os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def parse_retired_secrets(raw: str) -> dict[str, str]:
    """Parse ``kid:secret`` pairs (comma/semicolon separated).

    Example::

        CRYPTOSCAN_CBOM_RETIRED_SECRETS="k2025:aaaa,k2024:bbbb"
    """
    retired: dict[str, str] = {}
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        kid, _, secret = chunk.partition(":")
        kid, secret = kid.strip(), secret.strip()
        if kid and secret:
            retired[kid] = secret
    return retired


@dataclass(frozen=True)
class Settings:
    spec_version: str = "1.5"
    sign: bool = False
    secret: str = ""
    key_id: str = ""  # JWS "kid" — enables rotation-aware verification
    retired_secrets: dict[str, str] = field(default_factory=dict)
    tool_version: str = "1.0.0"
    environment: str = "development"

    def validate_for_production(self) -> None:
        """Fail closed when signing is requested in production without a
        configured key (an ephemeral key would make signatures unverifiable
        after restart)."""
        from shared_config.base_settings import ConfigurationError

        if self.environment.lower() != "production":
            return
        problems: list[str] = []
        if self.sign and not self.secret:
            problems.append(
                "CBOM signing is enabled but CRYPTOSCAN_CBOM_SECRET is not set — "
                "refusing to sign with an ephemeral key in production"
            )
        if self.sign and self.secret and not self.key_id:
            problems.append(
                "CRYPTOSCAN_CBOM_KEY_ID must be set in production so signatures "
                "are rotation-aware (kid header)"
            )
        if problems:
            raise ConfigurationError("production configuration rejected: " + "; ".join(problems))


def load_settings() -> Settings:
    return Settings(
        spec_version=os.environ.get("CRYPTOSCAN_CBOM_SPEC", "1.5") or "1.5",
        sign=_flag("CRYPTOSCAN_CBOM_SIGN"),
        secret=os.environ.get("CRYPTOSCAN_CBOM_SECRET", ""),
        key_id=os.environ.get("CRYPTOSCAN_CBOM_KEY_ID", ""),
        retired_secrets=parse_retired_secrets(
            os.environ.get("CRYPTOSCAN_CBOM_RETIRED_SECRETS", "")
        ),
        tool_version=os.environ.get("CRYPTOSCAN_CBOM_TOOL_VERSION", "1.0.0") or "1.0.0",
        environment=os.environ.get("ENVIRONMENT", "development") or "development",
    )


CbomSettings = Settings
