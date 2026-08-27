"""MQTT at the OT/IIoT edge: 1883 is plaintext, 8883 is MQTT-over-TLS."""

from __future__ import annotations

from typing import Any


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    tls = str(record.get("tls") or record.get("tls_encrypted") or "").lower() in {"1", "true", "yes", "on"}
    port = str(record.get("port") or "")
    if not tls and port == "8883":
        tls = True  # the well-known MQTT-over-TLS port implies TLS
    if tls:
        return {
            "protocol": "MQTT",
            "security_level": "ENCRYPT",
            "has_crypto": True,
            "crypto": {"encryption": record.get("cipher") or "TLS"},
            "crypto_config": {"encryption": record.get("cipher") or "TLS"},
            "compliance_issue": None,
            "confidence": "MEDIUM",
        }
    return {
        "protocol": "MQTT",
        "security_level": "NONE",
        "has_crypto": False,
        "crypto": {"encryption": "NONE", "signing": "NONE"},
        "crypto_config": {"encryption": "NONE"},
        "compliance_issue": "OT_UNENCRYPTED_MQTT",
        "confidence": "MEDIUM",
        "note": "MQTT on 1883 sends telemetry and credentials in plaintext; move publishers to 8883 (TLS).",
    }
