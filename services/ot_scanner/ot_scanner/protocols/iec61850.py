"""IEC 61850 MMS — treat missing TLS as unencrypted station bus traffic."""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = str(record.get("tls") or "").lower() in {"1", "true", "yes", "on"}
    if tls:
        return {
            "protocol": "IEC-61850",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {"encryption": record.get("cipher") or "TLS"},
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "IEC-61850",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_IEC61850",
        "confidence": "MEDIUM",
    }
