"""IEC 61850 MMS — treat missing TLS as unencrypted station bus traffic."""

from __future__ import annotations

from typing import Any


def _multicast_note(record: dict[str, Any]) -> dict[str, Any]:
    """IEC 61850 assigns dedicated multicast MACs: 01:0C:CD:01 (GOOSE), 01:0C:CD:04 (SV)."""
    mac = str(record.get("dst_mac") or record.get("dstmac") or "").upper()
    if mac.startswith("01:0C:CD"):
        return {"multicast": True, "multicast_mac": mac}
    return {}


def analyze(record: dict[str, Any]) -> dict[str, Any]:
    proto = str(record.get("protocol") or "").lower()
    if "goose" in proto:
        # GOOSE runs on raw Ethernet (IEEE 802.1Q) with no security at all —
        # by design, for speed. That fact is the finding.
        return {
            "protocol": "IEC-61850-GOOSE",
            "security_level": "NONE",
            "has_crypto": False,
            "crypto": {"encryption": "NONE", "signing": "NONE"},
            "crypto_config": {"encryption": "NONE"},
            "compliance_issue": "OT_UNENCRYPTED_GOOSE",
            "confidence": "MEDIUM",
            "note": "GOOSE tripping frames carry no native security; segmentation is the only control.",
            **_multicast_note(record),
        }
    if proto in {"sv", "sampled-values", "sampledvalues"} or "sampled" in proto:
        return {
            "protocol": "IEC-61850-SV",
            "security_level": "NONE",
            "has_crypto": False,
            "crypto": {"encryption": "NONE", "signing": "NONE"},
            "crypto_config": {"encryption": "NONE"},
            "compliance_issue": "OT_UNENCRYPTED_SV",
            "confidence": "MEDIUM",
            "note": "Sampled Values streams are unauthenticated by design; network segmentation required.",
            **_multicast_note(record),
        }
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
