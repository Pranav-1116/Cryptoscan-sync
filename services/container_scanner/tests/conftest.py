"""Isolate this service's tests package.

test_registry_and_hash.py imports the sibling helper test_image_archive.py as a
top-level module. The repo-wide pytest.ini uses --import-mode=importlib (so
identical basenames across services can't collide), which no longer inserts the
tests directory on sys.path — do it here.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
