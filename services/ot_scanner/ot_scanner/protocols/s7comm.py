"""S7comm (Siemens, ISO-on-TCP port 102): no native protocol cryptography."""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = str(record.get("tls") or record.get("tls_encrypted") or "").lower() in {"1", "true", "yes", "on"}
    if tls:
        # routed through a TLS gateway (e.g. an industrial firewall)
        return {
            "protocol": "S7comm-over-TLS",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {"encryption": record.get("cipher") or "TLS"},
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "S7comm",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_S7",
        "confidence": "MEDIUM",
        "note": "S7comm has no native encryption or authentication; put PLC access behind a TLS gateway or VPN.",
    }
