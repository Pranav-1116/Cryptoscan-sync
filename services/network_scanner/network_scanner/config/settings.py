"""Network TLS scanner settings from the environment."""

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
    timeout: float = 5.0
    expiry_days: int = 30


def load_settings() -> Settings:
    try:
        timeout = float(os.environ.get("CRYPTOSCAN_TLS_TIMEOUT", "5"))
    except ValueError:
        timeout = 5.0
    try:
        expiry_days = int(os.environ.get("CRYPTOSCAN_TLS_EXPIRY_DAYS", "30"))
    except ValueError:
        expiry_days = 30
    return Settings(
        live=_flag("CRYPTOSCAN_TLS_LIVE"),
        timeout=timeout,
        expiry_days=expiry_days,
    )


NetworkScannerSettings = Settings
