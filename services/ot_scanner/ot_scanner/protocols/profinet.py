"""PROFINET IO (EtherType 0x8892): layer-2 realtime, no native security.

PROFINET Security Classes exist (V2.4+) but are rarely enabled; the bus is
trusted by design.
"""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": "PROFINET",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_PROFINET",
        "confidence": "MEDIUM",
        "note": "PROFINET RT/IRT cycles are unauthenticated at layer 2; security class or segmentation required.",
    }
