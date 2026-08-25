"""Business-context enrichment settings from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    smtp_host: str | None = None
    executive_revenue_threshold: float = 1_000_000
    alert_on_p0: bool = True


def load_settings() -> Settings:
    raw = os.environ.get("CRYPTOSCAN_EXEC_REVENUE_THRESHOLD", "1000000")
    try:
        threshold = float(raw)
    except ValueError:
        threshold = 1_000_000
    return Settings(
        smtp_host=os.environ.get("CRYPTOSCAN_SMTP_HOST") or None,
        executive_revenue_threshold=threshold,
        alert_on_p0=os.environ.get("CRYPTOSCAN_ALERT_P0", "1").strip().lower() not in {"0", "false", "no", "off"},
    )


BusinessContextSettings = Settings
