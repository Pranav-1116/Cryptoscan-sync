"""Cloud / IaC scanner settings from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _flag(*names: str) -> bool:
    for name in names:
        if os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


@dataclass(frozen=True)
class Settings:
    live: bool = False
    api_url: str | None = None
    submit_results: bool = False
    regions: tuple[str, ...] = ()
    max_resources_per_service: int = 500
    environment: str = "development"

    def validate_for_production(self) -> None:
        """Fail closed: live cloud scanning in production requires explicit
        region pinning and at least one provider credential hint — a
        silently-empty live scan must never be possible."""
        from shared_config.base_settings import ConfigurationError

        if self.environment.lower() != "production" or not self.live:
            return
        problems: list[str] = []
        credential_hints = [
            "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN", "CRYPTOSCAN_AWS_ROLE_ARN",
            "AZURE_SUBSCRIPTION_ID", "CRYPTOSCAN_AZURE_SUBSCRIPTION",
            "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT",
        ]
        if not any(os.environ.get(name) for name in credential_hints):
            problems.append(
                "CRYPTOSCAN_CLOUD_LIVE is enabled in production but no cloud "
                "credential is configured (AWS_*/AZURE_*/GOOGLE_* environment)"
            )
        if problems:
            raise ConfigurationError("production configuration rejected: " + "; ".join(problems))


def load_settings() -> Settings:
    regions = tuple(
        item.strip()
        for item in (os.environ.get("CRYPTOSCAN_CLOUD_REGIONS") or "").split(",")
        if item.strip()
    )
    try:
        max_resources = max(1, int(os.environ.get("CRYPTOSCAN_CLOUD_MAX_RESOURCES") or 500))
    except ValueError:
        max_resources = 500
    return Settings(
        live=_flag("CRYPTOSCAN_CLOUD_LIVE"),
        api_url=os.environ.get("CRYPTOSCAN_API_URL") or None,
        submit_results=_flag("CRYPTOSCAN_CLOUD_SUBMIT"),
        regions=regions,
        max_resources_per_service=max_resources,
        environment=os.environ.get("ENVIRONMENT", "development") or "development",
    )


CloudScannerSettings = Settings
