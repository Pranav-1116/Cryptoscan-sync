"""CBOM generator / signing settings."""

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
    spec_version: str = "1.5"
    sign: bool = False
    secret: str = ""
    tool_version: str = "1.0.0"


def load_settings() -> Settings:
    return Settings(
        spec_version=os.environ.get("CRYPTOSCAN_CBOM_SPEC", "1.5") or "1.5",
        sign=_flag("CRYPTOSCAN_CBOM_SIGN"),
        secret=os.environ.get("CRYPTOSCAN_CBOM_SECRET", ""),
        tool_version=os.environ.get("CRYPTOSCAN_CBOM_TOOL_VERSION", "1.0.0") or "1.0.0",
    )


CbomSettings = Settings
