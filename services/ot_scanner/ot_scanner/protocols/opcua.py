"""Parse OPC-UA security mode / policy from passive observations."""

from __future__ import annotations

from typing import Any

POLICIES = {
    "BASIC256SHA256": {"encryption": "AES-256-CBC", "signing": "HMAC-SHA256", "key_derivation": "P-SHA256"},
    "BASIC256": {"encryption": "AES-256-CBC", "signing": "HMAC-SHA1", "key_exchange": "RSA-2048"},
    "BASIC128RSA15": {"encryption": "AES-128-CBC", "signing": "HMAC-SHA1", "key_exchange": "RSA-1024"},
    "AES256-SHA256-RSAPSS": {"encryption": "AES-256-CBC", "signing": "RSA-PSS-SHA256"},
    "NONE": {"encryption": "NONE", "signing": "NONE"},
}


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    mode = str(record.get("security_mode") or record.get("mode") or "None")
    policy = str(record.get("security_policy") or record.get("policy") or "")
    key = policy.upper().replace("#", "").split("/")[-1]
    if "BASIC256SHA256" in key:
        crypto = dict(POLICIES["BASIC256SHA256"])
    elif "BASIC128RSA15" in key:
        crypto = dict(POLICIES["BASIC128RSA15"])
    elif "BASIC256" in key:
        crypto = dict(POLICIES["BASIC256"])
    elif "NONE" in key or not policy:
        crypto = dict(POLICIES["NONE"])
    else:
        crypto = {"encryption": "UNKNOWN", "signing": "UNKNOWN", "policy": policy}
    mode_u = mode.upper().replace(" ", "")
    weak_policy = "BASIC128RSA15" in key or ("BASIC256" in key and "SHA256" not in key)
    if mode_u in {"0", "0X00", "NONE"}:
        level, issue = "NONE", "OT_UNENCRYPTED_TRAFFIC"
        crypto = dict(POLICIES["NONE"])
    elif weak_policy:
        # Basic128RSA15: RSA-1024 + HMAC-SHA1; Basic256: HMAC-SHA1 — deprecated
        # since OPC-UA part 7 (2015), still accepted by many PLCs
        level, issue = ("SIGN" if mode_u in {"1", "0X01", "SIGN"} else "ENCRYPT"), "OT_WEAK_CRYPTO_POLICY"
    elif mode_u in {"1", "0X01", "SIGN"}:
        level, issue = "SIGN", None
    else:
        level, issue = "ENCRYPT", None
    return {
        "protocol": "OPC-UA",
        "security_level": level,
        "has_crypto": level != "NONE",
        "crypto": crypto,
        "crypto_config": crypto,
        "compliance_issue": issue,
        "confidence": "MEDIUM",
        "note": "Passive OPC-UA observation. Verify with the OT vendor before acting.",
    }
