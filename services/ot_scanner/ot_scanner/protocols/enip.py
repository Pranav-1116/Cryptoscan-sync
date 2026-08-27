"""EtherNet/IP (Rockwell CIP, TCP/44818 UDP/2222): no security by default.

CIP Security (TLS) exists as an option on newer firmware; without it the
protocol is unauthenticated plaintext.
"""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = str(record.get("tls") or record.get("tls_encrypted") or "").lower() in {"1", "true", "yes", "on"}
    if tls:
        return {
            "protocol": "EtherNet/IP",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {"encryption": record.get("cipher") or "CIP Security (TLS)"},
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "EtherNet/IP",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_ETHERNETIP",
        "confidence": "MEDIUM",
        "note": "EtherNet/IP is unauthenticated plaintext unless CIP Security (TLS) is enabled; restrict with conduits.",
    }
