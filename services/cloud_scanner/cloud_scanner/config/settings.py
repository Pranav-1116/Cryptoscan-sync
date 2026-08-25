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


def load_settings() -> Settings:
    regions = tuple(
        item.strip()
        for item in (os.environ.get("CRYPTOSCAN_CLOUD_REGIONS") or "").split(",")
        if item.strip()
    )
    return Settings(
        live=_flag("CRYPTOSCAN_CLOUD_LIVE"),
        api_url=os.environ.get("CRYPTOSCAN_API_URL") or None,
        submit_results=_flag("CRYPTOSCAN_CLOUD_SUBMIT"),
        regions=regions,
    )


CloudScannerSettings = Settings
