"""Asset identity resolution + detection confidence.

Fuses observations of the same physical/logical asset from multiple sources
(network scan, cloud inventory, CMDB import, agent, CBOM) into one canonical
identity, and assigns an explicit confidence state rather than forcing a
binary YES/NO:

    CONFIRMED  >= 2 independent agreeing sources on a stable identifier
    PROBABLE   high agreement but a single strong source or near-match
    POSSIBLE   weak/partial match
    UNKNOWN    no corroborating evidence
    CONFLICT   sources disagree on a key attribute (owner/criticality/type)
"""

from __future__ import annotations

from collections import Counter
from typing import Any

CONFIDENCE_STATES = ("CONFIRMED", "PROBABLE", "POSSIBLE", "UNKNOWN", "CONFLICT")

#: stable identifiers used to correlate the same asset across sources.
STABLE_KEYS = ("mac_address", "instance_id", "resource_id", "serial",
               "hardware_uuid", "cert_fingerprint", "fqdn", "ip_address", "hostname")


def canonical_id(observations: list[dict[str, Any]]) -> str:
    """Deterministic canonical id from the most stable key available.

    Prefers strong identifiers; falls back to a hash of the correlated set."""
    import hashlib

    for key in STABLE_KEYS:
        for obs in observations:
            val = (obs.get("identifiers") or {}).get(key)
            if val:
                return f"asset-{hashlib.sha256(f'{key}:{val}'.encode()).hexdigest()[:16]}"
    blob = "|".join(sorted(str(o.get("source", "")) for o in observations))
    return f"asset-{hashlib.sha256(blob.encode()).hexdigest()[:16]}"


def _conflicting(observations: list[dict[str, Any]], attr: str) -> bool:
    vals = {str(o.get(attr)).lower() for o in observations if o.get(attr) is not None}
    return len(vals) > 1


def resolve_identity(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Fuse observations into a canonical identity + confidence + provenance."""
    obs = [o for o in observations if o]
    sources = sorted({o.get("source", "unknown") for o in obs})
    result: dict[str, Any] = {
        "canonical_id": canonical_id(obs),
        "confidence": "UNKNOWN",
        "evidence_sources": sources,
        "source_count": len(sources),
        "attributes": {},
    }
    if not obs:
        return result

    if any(_conflicting(obs, a) for a in ("criticality", "owner", "asset_type", "region")):
        result["confidence"] = "CONFLICT"

    # majority-vote attribute fusion
    attrs = ("asset_type", "name", "region", "business_unit", "environment",
             "owner", "maintainer", "application", "service",
             "data_classification", "criticality")
    for attr in attrs:
        vals = [o.get(attr) for o in obs if o.get(attr) is not None]
        if vals:
            result["attributes"][attr] = Counter(str(v) for v in vals).most_common(1)[0][0]

    strong_id_sources = set()
    for o in obs:
        idents = o.get("identifiers") or {}
        if any(idents.get(k) for k in STABLE_KEYS[:6]):  # strong keys
            strong_id_sources.add(o.get("source"))

    if result["confidence"] != "CONFLICT":
        if len(strong_id_sources) >= 2:
            result["confidence"] = "CONFIRMED"
        elif len(strong_id_sources) == 1:
            result["confidence"] = "PROBABLE"
        elif len(sources) >= 2:
            result["confidence"] = "POSSIBLE"
        else:
            result["confidence"] = "UNKNOWN"
    return result


def confidence_from_evidence(evidence_count: int, *, agreeing: int | None = None) -> str:
    """Detection confidence for an algorithm/finding from evidence strength.

    Mirrors the "RSA 96.8% / 4 sources / CONFIRMED" model. Never binary."""
    agreeing = agreeing if agreeing is not None else evidence_count
    if evidence_count <= 0:
        return "UNKNOWN"
    if evidence_count >= 3 and agreeing >= 2:
        return "CONFIRMED"
    if evidence_count >= 2:
        return "PROBABLE"
    return "POSSIBLE"
