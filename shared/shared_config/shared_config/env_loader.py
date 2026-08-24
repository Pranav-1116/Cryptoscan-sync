"""Load .env files from the repo root or the current working directory."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def find_env_file() -> Path | None:
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[3] / ".env",
        Path("/app/.env"),
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def load_env() -> Path | None:
    env_file = find_env_file()
    if env_file:
        load_dotenv(env_file, override=False)
        os.environ.setdefault("CRYPTOSCAN_ROOT", str(env_file.parent))
    return env_file


def repo_root() -> Path:
    env = os.environ.get("CRYPTOSCAN_ROOT")
    if env:
        return Path(env)
    # shared/shared_config/shared_config/env_loader.py → repo root is parents[3]
    return Path(__file__).resolve().parents[3]
