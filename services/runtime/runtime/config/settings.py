"""Runtime agent settings from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_url: str | None = None
    api_token: str | None = None
    session_jsonl: str | None = None
    proc_base: str = "/proc"


def load_settings() -> Settings:
    return Settings(
        api_url=os.environ.get("CRYPTOSCAN_API_URL") or None,
        api_token=os.environ.get("CRYPTOSCAN_API_TOKEN") or None,
        session_jsonl=os.environ.get("CRYPTOSCAN_RUNTIME_SESSION_JSONL") or None,
        proc_base=os.environ.get("CRYPTOSCAN_RUNTIME_PROC_BASE") or "/proc",
    )
