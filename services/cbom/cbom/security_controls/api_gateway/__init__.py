"""Api Gateway collectors — one type, one contract, several dialects.

``ApiGatewayCollector`` is the type's normalization; ``vendors.py`` is the dialect table. Nothing here
writes to a device: the capability surface is read-only by construction.
"""

from __future__ import annotations

from .base import COLLECTS, CONTROL, MUST_NOT, ApiGatewayCollector, collector
from .vendors import SPECS, dialects, spec_for

__all__ = ["COLLECTS", "CONTROL", "MUST_NOT", "SPECS", "ApiGatewayCollector", "collector", "dialects",
           "spec_for"]
