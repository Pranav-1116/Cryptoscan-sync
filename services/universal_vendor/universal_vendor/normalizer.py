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


def _string_list(values: Any) -> list[str]:
    if values is None:
        return []
    items = values if isinstance(values, (list, tuple, set)) else [values]
    output: list[str] = []
    for item in items:
        if isinstance(item, dict):
            item = (item.get("name") or item.get("cipher_suite")
                    or item.get("cipher") or item.get("id"))
        if item not in (None, ""):
            output.append(str(item))
    return output


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
        algorithm_type=observation.algorithm_type,
        algorithm_mode=observation.algorithm_mode,
        padding_scheme=observation.padding_scheme,
        algorithm_oid=observation.algorithm_oid,
        algorithm_parameters=dict(observation.algorithm_parameters),
        quantum_safe_status=observation.quantum_safe_status,
        protocol=observation.protocol,
        protocol_version=observation.protocol_version,
        cipher_suites=_string_list(observation.cipher_suites),
        protocol_configuration=dict(observation.protocol_configuration),
        configuration=dict(observation.configuration) if observation.configuration else None,
        implementation=observation.implementation,
        implementation_version=observation.implementation_version,
        library=observation.library,
        library_version=observation.library_version,
        library_dependencies=list(observation.library_dependencies),
        fips_certification=observation.fips_certification,
        key_id=observation.key_id,
        key_role=observation.key_role,
        key_storage_location=observation.key_storage_location,
        key_lifecycle_state=observation.key_lifecycle_state,
        key_type=observation.key_type,
        key_size=observation.key_size,
        curve=observation.curve,
        public_material_present=observation.public_material_present,
        private_material_present=observation.private_material_present,
        initialization_vector=observation.initialization_vector,
        salt=observation.salt,
        material_type=observation.material_type,
        material_metadata=observation.material_metadata,
        secret_type=observation.secret_type,
        secret_storage_location=observation.secret_storage_location,
        certificate=observation.certificate,
        certificate_serial_number=observation.certificate_serial_number,
        certificate_issuer=observation.certificate_issuer,
        certificate_subject=observation.certificate_subject,
        certificate_valid_from=observation.certificate_valid_from,
        certificate_valid_to=observation.certificate_valid_to,
        certificate_public_key_type=observation.certificate_public_key_type,
        certificate_public_key_size=observation.certificate_public_key_size,
        certificate_public_key_curve=observation.certificate_public_key_curve,
        certificate_signature_algorithm=observation.certificate_signature_algorithm,
        certificate_chain=list(observation.certificate_chain),
        observed_usage=observation.observed_usage,
        rng_name=observation.rng_name,
        rng_type=observation.rng_type,
        rng_source=observation.rng_source,
        component_usage=dict(observation.component_usage),
        related_vulnerabilities=list(observation.related_vulnerabilities),
        compliance=list(observation.compliance),
        authenticated_encryption=observation.authenticated_encryption,
        forward_secrecy=observation.forward_secrecy,
        side_channel_resistance=observation.side_channel_resistance,
        crypto_service_type=observation.crypto_service_type,
        crypto_service_provider=observation.crypto_service_provider,
        crypto_service_name=observation.crypto_service_name,
        crypto_service_version=observation.crypto_service_version,
        quantum_vulnerability=observation.quantum_vulnerability,
        migration_priority=observation.migration_priority,
        pqc_alternatives=_string_list(observation.pqc_alternatives),
        migration_status=observation.migration_status,
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
