"""Deduplication engine settings."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    location_window: int = 3
    merge_cross_scanner: bool = True


def load_settings() -> Settings:
    raw = os.environ.get("CRYPTOSCAN_DEDUP_WINDOW", "3")
    try:
        window = int(raw)
    except ValueError:
        window = 3
    merge = os.environ.get("CRYPTOSCAN_DEDUP_CROSS_SCANNER", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    return Settings(location_window=window, merge_cross_scanner=merge)


DedupSettings = Settings
