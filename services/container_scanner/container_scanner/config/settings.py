"""Container scanner settings from the environment."""

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
    live_cve: bool = False
    github_advisory: bool = False
    nvd_api_key: str = ""
    github_token: str = ""
    workspace_dir: str | None = None
    cve_timeout: float = 8.0


def load_settings() -> Settings:
    timeout_raw = os.environ.get("CRYPTOSCAN_CVE_TIMEOUT", "8")
    try:
        timeout = float(timeout_raw)
    except ValueError:
        timeout = 8.0
    return Settings(
        live_cve=_flag("CRYPTOSCAN_CVE_LIVE", "CRYPTOSCAN_LIVE_CVE"),
        github_advisory=_flag("CRYPTOSCAN_GITHUB_ADVISORY"),
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", ""),
        workspace_dir=os.environ.get("CRYPTOSCAN_CONTAINER_WORKSPACE") or None,
        cve_timeout=timeout,
    )


ContainerScannerSettings = Settings
