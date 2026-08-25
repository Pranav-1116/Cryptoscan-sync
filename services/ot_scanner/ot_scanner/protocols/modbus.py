"""Modbus TCP has no native crypto. Flag plaintext vs TLS tunnel."""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = record.get("tls") or record.get("is_tls_encrypted") or record.get("tls_encrypted")
    if str(tls).lower() in {"1", "true", "yes", "on"}:
        return {
            "protocol": "Modbus-over-TLS",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {
                "encryption": record.get("cipher") or "TLS",
                "tls_version": record.get("tls_version"),
            },
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "Modbus TCP",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_MODBUS",
        "confidence": "MEDIUM",
        "note": "Modbus has no native encryption. Consider a TLS tunnel.",
    }
