"""Isolate this service's tests package.

Test helpers in this directory (zelix_fixtures, zelix_live_fixtures) are
imported by sibling test modules as top-level modules. The repo-wide pytest.ini
uses --import-mode=importlib (so identical basenames across services can't
collide), which no longer inserts the tests directory on sys.path — do it here.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
