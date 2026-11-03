"""Siem collectors — one type, one contract, several dialects.

``SiemCollector`` is the type's normalization; ``vendors.py`` is the dialect table. Nothing here
writes to a device: the capability surface is read-only by construction.
"""

from __future__ import annotations

from .base import COLLECTS, CONTROL, MUST_NOT, SiemCollector, collector
from .vendors import SPECS, dialects, spec_for

__all__ = ["COLLECTS", "CONTROL", "MUST_NOT", "SPECS", "SiemCollector", "collector", "dialects",
           "spec_for"]
