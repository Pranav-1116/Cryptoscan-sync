"""Scanner configuration with safe defaults when env/shared_config is missing."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    from pydantic import Field
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class ScannerConfig(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="SCANNER_", extra="allow")

        java_home: Optional[str] = None
        temp_dir: Path = Path("/tmp/cryptoscan")
        exclude_dirs: set[str] = {
            "test",
            "tests",
            "build",
            "dist",
            "target",
            ".git",
            "node_modules",
            "venv",
            ".venv",
        }
        max_file_size_bytes: int = 10 * 1024 * 1024
        scan_timeout_seconds: int = 600
        supported_languages: set[str] = {"java"}
        git_shallow_clone: bool = True

except Exception:  # pragma: no cover

    class ScannerConfig:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            self.exclude_dirs = kwargs.get(
                "exclude_dirs",
                {"test", "tests", "build", "dist", "target", ".git", "node_modules"},
            )
            self.temp_dir = Path(kwargs.get("temp_dir", "/tmp/cryptoscan"))
