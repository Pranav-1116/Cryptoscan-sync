"""Normalization — vendor raw data → UniversalObservation → CryptoObservation.

Spec §1 ("vendor-specific data → … → canonical asset") and §20 ("keep
vendor-specific fields separately, do not lose information"). Algorithm
names are canonicalized through the shared registry when it is available;
registry-unrecognized names stay verbatim with family "unknown" rather than
being guessed.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.models import CryptoObservation, UniversalObservation

try:  # shared registry, guarded import
    from shared_models.algorithm_registry import parse_algorithm
except Exception:  # pragma: no cover - registry unavailable
    parse_algorithm = None  # type: ignore[assignment]


_FAMILY_MAP = {
    "block-cipher": "symmetric",
    "stream-cipher": "symmetric",
    "aead": "symmetric",
    "pke": "asymmetric",
    "kex": "asymmetric",
    "hash": "hash",
    "mac": "mac",
    "signature": "signature",
    "kdf": "kdf",
}


def _family(family: Optional[str]) -> Optional[str]:
    if not family:
        return None
    return _FAMILY_MAP.get(family.lower(), family.lower())


def _algorithm_facts(algorithm: Optional[str]) -> dict[str, Any]:
    """Canonical name / family / nist status / pqc flags via shared registry."""
    if not algorithm or parse_algorithm is None:
        return {}
    info = parse_algorithm(str(algorithm))
    if not getattr(info, "recognized", False):
        return {}
    return {
        "algorithm": info.canonical or str(algorithm),
        "algorithm_family": _family(info.family),
        "nist_status": getattr(info, "status", None),
        "quantum_vulnerable": getattr(info, "quantum_vulnerable", None),
        "pqc_replacement": getattr(info, "pqc_replacement", None),
    }


def normalize_to_crypto(observation: UniversalObservation) -> CryptoObservation:
    facts = _algorithm_facts(observation.algorithm)
    return CryptoObservation(
        asset_id=observation.asset_id,
        vendor=observation.vendor,
        product=observation.product,
        product_version=observation.product_version,
        algorithm=facts.get("algorithm") or observation.algorithm,
        algorithm_family=facts.get("algorithm_family"),
        algorithm_parameters=dict(observation.algorithm_parameters),
        protocol=observation.protocol,
        protocol_version=observation.protocol_version,
        implementation=observation.implementation,
        implementation_version=observation.implementation_version,
        library=observation.library,
        library_version=observation.library_version,
        key_id=observation.key_id,
        key_role=observation.key_role,
        key_type=observation.key_type,
        key_size=observation.key_size,
        curve=observation.curve,
        public_material_present=observation.public_material_present,
        private_material_present=observation.private_material_present,
        initialization_vector=observation.initialization_vector,
        salt=observation.salt,
        material_type=observation.material_type,
        material_metadata=observation.material_metadata,
        certificate=observation.certificate,
        certificate_chain=list(observation.certificate_chain),
        observed_usage=observation.observed_usage,
        purpose=None,
        nist_status=facts.get("nist_status"),
        quantum_vulnerable=facts.get("quantum_vulnerable"),
        pqc_replacement=facts.get("pqc_replacement"),
        source=observation.source,
        confidence=observation.confidence,
        visibility=observation.visibility,
        vendor_specific=dict(observation.vendor_specific),
    )


def normalize_all(raw_items: list[dict[str, Any]], plugin) -> list[UniversalObservation]:
    return [plugin.normalize(item) for item in raw_items]
