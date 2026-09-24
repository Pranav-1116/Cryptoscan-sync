"""Scanner configuration with safe defaults when env/shared_config is missing."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class ScannerConfig(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="SCANNER_", extra="allow")

        java_home: Optional[str] = None
        temp_dir: Path = Path("/tmp/cryptoscan")
        # Extra directory names to skip, merged with FileDiscovery.DEFAULT_EXCLUDED_DIRS.
        # Test directories are NOT excluded by default: hard-coded keys, test keystores and
        # weak-cipher fixtures in src/test are inventory too (use --exclude-tests to drop them).
        exclude_dirs: set[str] = set()
        max_file_size_bytes: int = 10 * 1024 * 1024
        scan_timeout_seconds: int = 600
        supported_languages: set[str] = {"java"}
        git_shallow_clone: bool = True

except Exception:  # pragma: no cover

    class ScannerConfig:  # type: ignore[no-redef]
        def __init__(self, **kwargs):
            self.exclude_dirs = kwargs.get("exclude_dirs", set())
            self.temp_dir = Path(kwargs.get("temp_dir", "/tmp/cryptoscan"))
