#!/usr/bin/env python3
"""Print a PBKDF2 hash for ADMIN_PASSWORD_HASH."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "api"))

from api.security.passwords import hash_password  # noqa: E402


def main() -> int:
    secret = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Admin password: ")
    if not secret:
        print("password is required", file=sys.stderr)
        return 2
    print(hash_password(secret))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
