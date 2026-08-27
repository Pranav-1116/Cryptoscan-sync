"""IEC 60870-5-104 (TCP/2404): plaintext APDUs by default.

Secure variants wrapping the link in TLS are defined by IEC 62351; base
deployments carry unscaled telecontrol traffic in the clear.
"""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = str(record.get("tls") or record.get("tls_encrypted") or "").lower() in {"1", "true", "yes", "on"}
    if tls:
        return {
            "protocol": "IEC-104",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {"encryption": record.get("cipher") or "TLS (IEC 62351)"},
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "IEC-104",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_IEC104",
        "confidence": "MEDIUM",
        "note": "IEC 60870-5-104 carries telecontrol frames in plaintext; IEC 62351 TLS or a conduit is required.",
    }
