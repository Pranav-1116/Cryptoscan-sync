"""DNP3 Secure Authentication (optional)."""

from __future__ import annotations

from typing import Any

AUTH = {
    "0": "NONE",
    "0X00": "NONE",
    "1": "HMAC-SHA1",
    "0X01": "HMAC-SHA1",
    "2": "HMAC-SHA256",
    "0X02": "HMAC-SHA256",
    "3": "AES-GMAC",
    "0X03": "AES-GMAC",
    "HMAC-SHA1": "HMAC-SHA1",
    "HMAC-SHA256": "HMAC-SHA256",
    "AES-GMAC": "AES-GMAC",
}


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    sa = record.get("sa") or record.get("secure_authentication") or record.get("has_secure_authentication")
    auth = str(record.get("auth") or record.get("auth_algorithm") or "")
    mapped = AUTH.get(auth.upper()) if auth else None
    enabled = str(sa).lower() in {"1", "true", "yes", "on"} or bool(mapped and mapped != "NONE")
    if not enabled:
        return {
            "protocol": "DNP3",
            "security_level": "NONE",
            "has_crypto": False,
            "crypto": {"authentication": "NONE"},
            "crypto_config": {"authentication": "NONE"},
            "compliance_issue": "OT_NO_AUTHENTICATION",
            "confidence": "MEDIUM",
        }
    algo = mapped or "HMAC-SHA256"
    return {
        "protocol": "DNP3-SA",
        "security_level": "SIGN" if "HMAC" in algo else "ENCRYPT",
        "has_crypto": True,
        "crypto": {"authentication": algo, "purpose": "MESSAGE_AUTHENTICATION"},
        "crypto_config": {"authentication": algo},
        "compliance_issue": "OT_WEAK_AUTHENTICATION" if algo == "HMAC-SHA1" else None,
        "confidence": "MEDIUM",
    }
