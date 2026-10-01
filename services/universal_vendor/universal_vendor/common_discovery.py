"""Artifact-driven discovery for crypto fields shared by vendor plugins.

Vendor plugins remain responsible for vendor-specific parsing. This module
covers the common structured shapes that appear in API responses, CBOMs,
configuration exports, and operator-supplied metadata. It never copies key,
IV, salt, PEM, or private material into an observation; only presence and
non-sensitive metadata are retained.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


_CRYPTO_TYPE_KEYS = {
    "algorithms", "cryptographic_algorithms", "ciphers", "cipher_suites",
    "protocols", "crypto_protocols", "tls_versions", "ssh_versions",
    "ipsec", "quic", "protocol_versions", "negotiated_protocols",
    "libraries", "crypto_libraries", "cryptographic_libraries",
    "implementations", "crypto_implementations", "dependencies",
    "cryptographic_dependencies", "keys", "key_metadata",
    "cryptographic_keys", "key_pairs", "public_keys", "private_keys",
    "certificates", "certificate_chain", "tls_certificate", "certificate",
    "initialization_vectors", "ivs", "salts", "key_material",
}

_CERTIFICATE_FIELDS = {
    "subject", "issuer", "serial", "serial_number", "cn", "san", "dns_names",
    "not_before", "not_after", "valid_from", "valid_to", "signature_algorithm",
    "key_algorithm", "key_type", "key_size", "curve", "fingerprint", "path",
    "reference", "status", "revoked", "chain_length", "name", "id", "arn", "type", "expires",
}


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, dict):
        # A single record has crypto-shaped keys. Otherwise treat a mapping as
        # a name -> record map, retaining the map key as a stable identifier.
        if set(value).intersection(_CRYPTO_TYPE_KEYS | {
            "name", "id", "key_id", "keyId", "algorithm", "algorithmType",
            "protocol", "protocolVersion", "library", "version", "type",
            "key_type", "public_key", "publicKey", "private_key", "privateKey",
            "initialization_vector", "initializationVector", "iv", "salt",
            "subject", "issuer", "provider", "serviceName", "rngName",
        }):
            return [value]
        return [{"name": key, **(item if isinstance(item, dict) else {"value": item})}
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [value]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", []):
            return value
    wanted = {_normalized_key(key) for key in keys}
    for actual, value in record.items():
        if _normalized_key(actual) in wanted and value not in (None, "", []):
            return value
    return None


def _int(value: Any) -> int | None:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else None
    except (TypeError, ValueError):
        return None


def _infer_algorithm_metadata(algorithm: Any, details: dict[str, Any]) -> dict[str, Any]:
    """Extract explicit parameters embedded in a reported algorithm token.

    This is parsing of the source token, not a risk guess: only values with a
    recognizable textual delimiter/pattern are returned. OIDs and quantum
    status still require source evidence or a trusted registry projection.
    """
    text = _text(algorithm)
    upper = text.upper()
    inferred: dict[str, Any] = {}
    if details.get("key_size") is None:
        match = re.search(r"(?:AES|RSA|DSA|DH|EC)[-_]?(128|192|224|256|384|512|1024|2048|3072|4096)", upper)
        if match:
            inferred["key_size"] = int(match.group(1))
    if details.get("mode") in (None, ""):
        match = re.search(r"(?:-|/)(GCM|CBC|CCM|CTR|XTS|OCB|CFB|OFB|ECB)(?:$|[-_/])", upper)
        if match:
            inferred["mode"] = match.group(1)
    if details.get("padding") in (None, ""):
        match = re.search(r"(?:-|/)(OAEP|PSS|PKCS(?:1|7)?)(?:$|[-_/])", upper)
        if match:
            inferred["padding"] = match.group(1)
    curve = details.get("curve")
    if curve in (None, ""):
        match = re.search(r"(?:P-[0-9]{3}|SECP[0-9]+R[0-9]+|BRAINPOOLP[0-9]+R[0-9]+|CURVE(?:19|448)[0-9]+)", upper)
        if match:
            inferred["curve"] = match.group(0)
    return inferred


def _presence(record: dict[str, Any], *keys: str) -> bool | None:
    wanted = {_normalized_key(key) for key in keys}
    for actual, value in record.items():
        if _normalized_key(actual) in wanted:
            if isinstance(value, bool):
                return value
            return value not in (None, "", [], {})
    return None


def _material_metadata(record: dict[str, Any], *keys: str) -> dict[str, Any] | None:
    for key in keys:
        if key not in record:
            continue
        value = record[key]
        result: dict[str, Any] = {"present": value not in (None, "", [], {})}
        if isinstance(value, dict):
            result["length"] = _int(_first(value, "length", "size", "bytes"))
            result["encoding"] = _first(value, "encoding", "format")
        elif isinstance(value, (str, bytes)):
            # Length is metadata only; the value itself is intentionally not
            # returned. A PEM/base64 payload is never placed in the report.
            result["length"] = len(value)
        return result
    return None


_SENSITIVE_METADATA_KEYS = {
    "secret", "secrets", "password", "passwd", "token", "access_token",
    "authorization", "credential", "credentials", "private_key", "private_key_pem",
    "private_material", "key_material", "plaintext", "ciphertext", "raw_value",
}


def _safe_mapping(value: Any) -> Any:
    if isinstance(value, dict):
        def safe_key(key: Any) -> bool:
            normalized = _normalized_key(key)
            sensitive = {_normalized_key(item) for item in _SENSITIVE_METADATA_KEYS}
            return normalized not in sensitive and not any(
                token in normalized for token in ("password", "secret", "privatekey", "token", "apikey")
            )

        return {
            str(key): _safe_mapping(item)
            for key, item in value.items()
            if safe_key(key)
        }
    if isinstance(value, list):
        return [_safe_mapping(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_mapping(item) for item in value]
    return value


def _certificate_metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        text = value.strip()
        if "BEGIN " in text or len(text) > 256:
            return {"present": bool(text), "opaque_material": True, "length": len(value)}
        return {"reference": text, "present": bool(text)}
    if not isinstance(value, dict):
        return {"present": value not in (None, "", [], {})}
    result: dict[str, Any] = {}
    for key in sorted(_CERTIFICATE_FIELDS):
        candidate = _first(value, key)
        if candidate not in (None, ""):
            result[key] = candidate
    public_key = _first(value, "public_key", "public_key_details")
    if isinstance(public_key, dict):
        result["public_key"] = {
            key: _first(public_key, key)
            for key in ("type", "algorithm", "key_type", "size", "key_size", "curve", "named_curve")
            if _first(public_key, key) not in (None, "")
        }
    result["present"] = True
    return result


def _safe_list(value: Any) -> list[Any]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    safe: list[Any] = []
    for item in values:
        if isinstance(item, dict):
            safe.append({
                key: item[key]
                for key in ("id", "cve", "name", "severity", "score", "summary", "description", "source")
                if item.get(key) not in (None, "")
            })
        elif _text(item):
            safe.append(_text(item))
    return safe


def _common_metadata(record: dict[str, Any]) -> dict[str, Any]:
    """Project whitelisted non-secret metadata shared by all asset kinds."""
    values: dict[str, Any] = {}
    text_fields = {
        "rng_name": ("rng_name", "rng", "random_source"),
        "rng_type": ("rng_type", "random_type"),
        "rng_source": ("rng_source", "random_source_type"),
        "side_channel_resistance": ("side_channel_resistance", "side_channel"),
        "crypto_service_type": ("crypto_service_type", "service_type"),
        "crypto_service_provider": ("crypto_service_provider", "service_provider", "provider"),
        "crypto_service_name": ("crypto_service_name", "service_name"),
        "crypto_service_version": ("crypto_service_version", "service_version"),
        "quantum_vulnerability": ("quantum_vulnerability", "quantum_risk", "quantum_risk_level"),
        "migration_priority": ("migration_priority", "pqc_priority"),
        "migration_status": ("migration_status", "pqc_migration_status"),
        "secret_type": ("secret_type", "secret_kind"),
        "secret_storage_location": ("secret_storage_location", "secret_store", "vault_reference"),
    }
    for output, keys in text_fields.items():
        value = _first(record, *keys)
        if isinstance(value, dict):
            value = _first(value, "name", "type", "kind", "provider", "id", "reference")
        if value not in (None, ""):
            values[output] = _text(value)
    bool_fields = {
        "authenticated_encryption": ("authenticated_encryption", "aead"),
        "forward_secrecy": ("forward_secrecy", "pfs"),
    }
    for output, keys in bool_fields.items():
        value = _first(record, *keys)
        if isinstance(value, bool):
            values[output] = value
    usage = _first(record, "component_usage", "usage", "purposes", "purpose", "operations")
    if usage not in (None, "", [], {}):
        values["component_usage"] = _safe_mapping(usage if isinstance(usage, dict) else {"value": usage})
    vulnerabilities = _first(record, "related_vulnerabilities", "vulnerabilities", "vulnerability")
    if vulnerabilities not in (None, "", [], {}):
        values["related_vulnerabilities"] = _safe_list(vulnerabilities)
    compliance = _first(record, "compliance", "compliance_status", "standards", "controls")
    if compliance not in (None, "", [], {}):
        values["compliance"] = _safe_list(compliance)
    alternatives = _first(record, "pqc_alternatives", "pqc_replacements", "migration_alternatives")
    if alternatives not in (None, "", [], {}):
        values["pqc_alternatives"] = [_text(item) for item in (
            alternatives if isinstance(alternatives, (list, tuple, set)) else [alternatives]
        ) if _text(item)]
    return values


def _base(plugin: Any, context: dict[str, Any], *, crypto_type: str,
          field: str, asset_id: str | None = None, **values: Any) -> dict[str, Any]:
    source = "api_metadata" if _normalized_key(field.split(".", 1)[0]) == "apimetadata" else "artifact"
    visibility = "API_VISIBLE" if source == "api_metadata" else "OBSERVED"
    source_evidence_reference = _first(
        context, "evidence_reference", "evidenceReference",
        "source_evidence_reference", "sourceEvidenceReference",
    )
    if source_evidence_reference in (None, ""):
        for _root_name, root in _metadata_roots(context):
            source_evidence_reference = _first(
                root, "evidence_reference", "evidenceReference",
                "source_evidence_reference", "sourceEvidenceReference",
            )
            if source_evidence_reference not in (None, ""):
                break
    record = {
        "vendor": plugin.vendor,
        "product": plugin.product,
        "product_version": _first(context, "version", "product_version", "productVersion"),
        "asset_id": asset_id or _first(context, "asset_id", "assetId") or f"{plugin.vendor}:{plugin.product}",
        "crypto_type": crypto_type,
        "source": f"{plugin.plugin_id}:common",
        "evidence_field": field,
        "discovery_method": "structured_metadata" if source == "api_metadata" else "artifact",
        "confidence": 0.85 if source == "api_metadata" else 0.75,
        "visibility": visibility,
        "source_evidence_reference": source_evidence_reference,
    }
    # Source-level risk, compliance, RNG, service, and migration metadata can
    # sit beside an algorithms/protocols list rather than inside each item.
    # Carry only the same whitelisted metadata onto each observation; never
    # copy an entire source document into a crypto record.
    context_metadata = _common_metadata(context)
    for _root_name, root in _metadata_roots(context):
        if isinstance(root, dict):
            context_metadata.update(_common_metadata(root))
    record.update({key: value for key, value in context_metadata.items()
                   if value is not None})
    record.update({key: value for key, value in values.items() if value is not None})
    return record


def _metadata_roots(context: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    wanted = {_normalized_key(key) for key in
              ("api_metadata", "metadata", "crypto_metadata", "cbom", "sbom")}
    for actual, raw_value in context.items():
        if _normalized_key(actual) not in wanted:
            continue
        value = raw_value
        if isinstance(value, str):
            # JSON parsing is deliberately limited to explicit metadata blobs.
            try:
                import json
                value = json.loads(value)
            except (TypeError, ValueError):
                continue
        if isinstance(value, dict):
            yield str(actual), value


def _field_values(context: dict[str, Any], names: Iterable[str]) -> Iterable[tuple[str, Any]]:
    """Yield configured fields with snake_case/camelCase equivalence."""
    wanted = {_normalized_key(name) for name in names}
    for actual, value in context.items():
        if (_normalized_key(actual) in wanted
                and value not in (None, "", [], {})):
            yield str(actual), value
    for root_name, root in _metadata_roots(context):
        for actual, value in root.items():
            if (_normalized_key(actual) in wanted
                    and value not in (None, "", [], {})):
                yield f"{root_name}.{actual}", value


def discover_common_crypto(plugin: Any, context: dict[str, Any]) -> list[dict[str, Any]]:
    """Return safe observations for common algorithms, protocols, libraries,
    keys, key-material presence, and certificates in structured artifacts.
    """
    records: list[dict[str, Any]] = []

    # CycloneDX CBOM/SBOM components are a common structured source. Only
    # explicit algorithm properties or recognized algorithm tokens are used;
    # a generic component name never becomes an invented algorithm.
    for root_name, root in _metadata_roots(context):
        for index, component in enumerate(_items(root.get("components"))):
            if not isinstance(component, dict):
                continue
            properties = component.get("cryptoProperties") or {}
            algorithm_properties = properties.get("algorithmProperties") or {}
            algorithm = _first(
                algorithm_properties, "algorithm", "name", "algorithmName",
            ) or _first(component, "algorithm")
            if not algorithm:
                primitive = _text(algorithm_properties.get("primitive")).lower()
                parameter = algorithm_properties.get("parameterSetIdentifier")
                if primitive in {"ae", "block-cipher", "enc"} and str(parameter).isdigit():
                    algorithm = f"AES-{parameter}"
                else:
                    try:
                        from universal_vendor.plugins._helpers import extract_algorithms
                        tokens = extract_algorithms(_text(component.get("name")))
                    except (ImportError, TypeError, ValueError):
                        tokens = []
                    algorithm = tokens[0] if tokens else None
            if algorithm:
                records.append(_base(
                    plugin, context, crypto_type="algorithm",
                    field=f"{root_name}.components[{index}]",
                    asset_id=_text(_first(component, "bom-ref", "ref", "name")) or None,
                    algorithm=_text(algorithm),
                    algorithm_type=_text(algorithm_properties.get("primitive")) or None,
                    algorithm_mode=_text(algorithm_properties.get("mode")) or None,
                    padding_scheme=_text(algorithm_properties.get("padding")) or None,
                    algorithm_oid=_text(properties.get("oid")) or None,
                    key_size=_int(algorithm_properties.get("parameterSetIdentifier")),
                    curve=_text(algorithm_properties.get("curve")) or None,
                    quantum_safe_status=("QUANTUM_VULNERABLE"
                                         if properties.get("quantumVulnerable") is True
                                         else "QUANTUM_SAFE"
                                         if properties.get("quantumVulnerable") is False else None),
                    algorithm_parameters={
                        key: algorithm_properties.get(key)
                        for key in ("primitive", "parameterSetIdentifier", "mode", "padding", "curve")
                        if algorithm_properties.get(key) is not None
                    },
                    **_common_metadata(component),
                ))
            library = _first(component, "library", "implementation", "provider")
            if library:
                records.append(_base(
                    plugin, context, crypto_type="library",
                    field=f"{root_name}.components[{index}]",
                    asset_id=_text(_first(component, "bom-ref", "ref", "name")) or None,
                    library=_text(library),
                    library_version=_text(_first(component, "version", "release")) or None,
                    **_common_metadata(component),
                ))

    algorithm_names = (
        "algorithms", "cryptographic_algorithms", "ciphers", "cipher_suites",
    )
    for field, value in _field_values(context, algorithm_names):
        for index, item in enumerate(_items(value)):
            if isinstance(item, dict):
                algorithm = _first(item, "algorithm", "name", "cipher", "suite", "value")
                details = {"mode": _first(item, "mode", "algorithm_mode"),
                           "key_size": _int(_first(item, "key_size", "key_bits", "bits")),
                           "padding": _first(item, "padding_scheme", "padding"),
                           "curve": _first(item, "curve", "named_curve")}
                inferred = _infer_algorithm_metadata(algorithm, details)
                details.update({key: value for key, value in inferred.items()
                                if details.get(key) in (None, "")})
                asset_id = _text(_first(item, "asset_id", "id", "name")) or None
                algorithm_type = _text(_first(item, "algorithm_type", "type", "primitive")) or None
                padding_scheme = _text(details.get("padding")) or None
                algorithm_oid = _text(_first(item, "algorithm_oid", "oid")) or None
                quantum_value = _first(
                    item, "quantum_safe_status", "quantum_status", "pqc_status", "quantum_safe",
                )
                if isinstance(quantum_value, bool):
                    quantum_safe_status = "QUANTUM_SAFE" if quantum_value else "QUANTUM_VULNERABLE"
                else:
                    quantum_safe_status = _text(quantum_value) or None
                mode = _text(details.get("mode")) or None
                key_size = details.get("key_size")
                algorithm_parameters = {
                    **details,
                    "parameters": _first(item, "parameters", "parameter_set", "parameterSetIdentifier"),
                }
            else:
                algorithm, details, asset_id = item, {}, None
                algorithm_type = padding_scheme = algorithm_oid = quantum_safe_status = None
                mode = None
                key_size = None
                algorithm_parameters = details
            algorithm_text = _text(algorithm)
            if not algorithm_text or algorithm_text.upper() in {"UNKNOWN", "NONE"}:
                continue
            records.append(_base(
                plugin, context, crypto_type="algorithm", field=field,
                asset_id=asset_id or f"{context.get('asset_id') or plugin.plugin_id}:algorithm:{index}",
                algorithm=algorithm_text, algorithm_type=algorithm_type,
                algorithm_mode=mode, padding_scheme=padding_scheme,
                algorithm_oid=algorithm_oid, quantum_safe_status=quantum_safe_status,
                key_size=key_size, curve=_text(details.get("curve")) or None,
                algorithm_parameters=algorithm_parameters,
                configuration=details,
                **_common_metadata(item if isinstance(item, dict) else {}),
            ))

    protocol_names = (
        "protocols", "crypto_protocols", "tls_versions", "ssh_versions",
        "ipsec", "quic", "protocol_versions", "negotiated_protocols",
    )
    for field, value in _field_values(context, protocol_names):
        for index, item in enumerate(_items(value)):
            if isinstance(item, dict):
                protocol = _first(item, "protocol", "name", "type")
                versions = _first(item, "versions", "version")
                algorithm = _first(item, "algorithm", "cipher", "cipher_suite")
                observed = _presence(item, "observed", "negotiated")
                asset_id = _text(_first(item, "asset_id", "id", "name")) or None
                cipher_suites = _first(item, "cipher_suites", "ciphers", "supported_ciphers")
                protocol_configuration = _first(item, "protocol_configuration", "configuration", "config", "extensions")
            else:
                protocol, versions, algorithm, observed, asset_id = item, None, None, None, None
                cipher_suites, protocol_configuration = None, None
            protocol_text = _text(protocol)
            # A scalar TLS 1.3 / SSH-2 value is a protocol plus version.
            scalar_match = re.match(
                r"^(TLS|SSL|SSH|IPsec|IKE|QUIC)\s*[v_-]?\s*([0-9][0-9._]*)?\s*$",
                protocol_text, re.IGNORECASE,
            )
            if scalar_match and not isinstance(item, dict):
                protocol_text, versions = scalar_match.group(1), scalar_match.group(2)
            elif not isinstance(item, dict) and re.fullmatch(r"[0-9]+(?:[._][0-9]+)*", protocol_text):
                field_name = field.rsplit(".", 1)[-1].lower()
                if "ssh" in field_name:
                    protocol_text, versions = "SSH", protocol_text
                elif "quic" in field_name:
                    protocol_text, versions = "QUIC", protocol_text
                elif "ipsec" in field_name or "ike" in field_name:
                    protocol_text, versions = "IPsec", protocol_text
                else:
                    protocol_text, versions = "TLS", protocol_text
            if not protocol_text:
                continue
            version_text = _text(versions) or None
            records.append(_base(
                plugin, context, crypto_type="protocol", field=field,
                asset_id=asset_id or f"{context.get('asset_id') or plugin.plugin_id}:protocol:{index}",
                protocol=protocol_text, protocol_version=version_text,
                cipher_suites=[
                    (_text(_first(cipher, "name", "cipher_suite", "cipher", "id"))
                     if isinstance(cipher, dict) else _text(cipher))
                    for cipher in (cipher_suites if isinstance(cipher_suites, (list, tuple))
                                   else ([cipher_suites] if cipher_suites else []))
                    if ((isinstance(cipher, dict)
                         and _text(_first(cipher, "name", "cipher_suite", "cipher", "id")))
                        or (not isinstance(cipher, dict) and _text(cipher)))
                ],
                protocol_configuration=_safe_mapping(
                    protocol_configuration if isinstance(protocol_configuration, dict)
                    else ({"value": protocol_configuration}
                          if protocol_configuration is not None else {})
                ),
                algorithm=_text(algorithm) or None,
                observed_usage=observed,
                **_common_metadata(item if isinstance(item, dict) else {}),
            ))

    library_names = (
        "libraries", "crypto_libraries", "cryptographic_libraries",
        "implementations", "crypto_implementations", "crypto_library", "library",
    )
    for field, value in _field_values(context, library_names):
        for index, item in enumerate(_items(value)):
            if isinstance(item, dict):
                name = _first(item, "library", "implementation", "name", "id")
                version = _first(item, "library_version", "version", "release")
                implementation = _first(item, "implementation", "provider", "engine")
                asset_id = _text(_first(item, "asset_id", "id", "name")) or None
                fips_certification = _text(_first(
                    item, "fips_certification", "fips_validation", "fips_certificate",
                )) or None
                library_dependencies = _first(item, "library_dependencies", "dependencies")
            else:
                name, version, implementation, asset_id = item, None, None, None
                fips_certification, library_dependencies = None, None
            name_text = _text(name)
            if not name_text:
                continue
            records.append(_base(
                plugin, context, crypto_type="library", field=field,
                asset_id=asset_id or f"{context.get('asset_id') or plugin.plugin_id}:library:{index}",
                library=name_text, library_version=_text(version) or None,
                implementation=_text(implementation) or None,
                fips_certification=fips_certification,
                library_dependencies=_safe_mapping(
                    library_dependencies if isinstance(library_dependencies, list)
                    else ([library_dependencies] if library_dependencies else [])
                ),
                **_common_metadata(item if isinstance(item, dict) else {}),
            ))

    version_library_fields = (
        ("openssl_version", "OpenSSL"), ("libressl_version", "LibreSSL"),
        ("boringssl_version", "BoringSSL"), ("wolfssl_version", "wolfSSL"),
        ("mbedtls_version", "mbedTLS"),
        ("java_crypto_extension_version", "Java Cryptography Extension"),
    )
    for field, library_name in version_library_fields:
        if context.get(field) not in (None, ""):
            records.append(_base(
                plugin, context, crypto_type="library", field=field,
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:library:{library_name}",
                library=library_name, library_version=_text(context[field]),
            ))

    service_names = (
        "crypto_services", "cryptographic_services", "services", "hsm", "hsm_services",
        "kms", "kms_services", "vaults", "certificate_authorities", "pki_services",
        "crypto_providers",
    )
    for field, value in _field_values(context, service_names):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                item = {"name": item}
            service_name = _text(_first(item, "crypto_service_name", "service_name", "name", "id"))
            if not service_name:
                continue
            records.append(_base(
                plugin, context, crypto_type="service", field=field,
                asset_id=_text(_first(item, "asset_id", "id", "name"))
                         or f"{context.get('asset_id') or plugin.plugin_id}:service:{index}",
                crypto_service_type=_text(_first(item, "crypto_service_type", "service_type", "type")) or None,
                crypto_service_provider=_text(_first(item, "crypto_service_provider", "provider", "vendor")) or None,
                crypto_service_name=service_name,
                crypto_service_version=_text(_first(item, "crypto_service_version", "version")) or None,
                configuration=_safe_mapping({
                    key: item[key] for key in ("endpoint", "region", "partition", "mode", "status")
                    if item.get(key) not in (None, "")
                }),
                **{key: value for key, value in _common_metadata(item).items()
                   if key not in {"crypto_service_type", "crypto_service_provider",
                                  "crypto_service_name", "crypto_service_version"}},
            ))

    rng_names = ("rngs", "random_number_generators", "random_sources", "rng")
    for field, value in _field_values(context, rng_names):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                item = {"name": item}
            rng_name = _text(_first(item, "rng_name", "name", "id", "generator"))
            if not rng_name:
                continue
            records.append(_base(
                plugin, context, crypto_type="rng", field=field,
                asset_id=_text(_first(item, "asset_id", "id", "name"))
                         or f"{context.get('asset_id') or plugin.plugin_id}:rng:{index}",
                rng_name=rng_name,
                rng_type=_text(_first(item, "rng_type", "type", "kind")) or None,
                rng_source=_text(_first(item, "rng_source", "source", "provider")) or None,
                **{key: value for key, value in _common_metadata(item).items()
                   if key not in {"rng_name", "rng_type", "rng_source"}},
            ))

    dependency_names = ("dependencies", "cryptographic_dependencies")
    for field, value in _field_values(context, dependency_names):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                continue
            library = _first(item, "library", "implementation", "package", "name")
            if not library:
                continue
            records.append(_base(
                plugin, context, crypto_type="library", field=field,
                asset_id=_text(_first(item, "repo", "asset_id", "component", "name"))
                         or f"{plugin.plugin_id}:dependency:{index}",
                library=_text(library), library_version=_text(_first(item, "version", "release")) or None,
                implementation=_text(_first(item, "implementation", "provider")) or None,
                **_common_metadata(item),
            ))

    key_names = (
        "keys", "key_metadata", "cryptographic_keys", "key_pairs",
        "public_keys", "private_keys", "key_material", "secrets", "secret_metadata",
        "secret_material", "credentials",
    )
    for field, value in _field_values(context, key_names):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                item = {"value": item}
            key_id = _text(_first(item, "key_id", "id", "alias", "name", "reference")) or None
            role = _text(_first(item, "key_role", "role", "type")) or None
            key_storage_location = _text(_first(
                item, "key_storage_location", "storage_location", "storage", "location",
            )) or None
            key_lifecycle_state = _text(_first(
                item, "key_lifecycle_state", "lifecycle_state", "state", "status",
            )) or None
            public_present = _presence(item, "public_key", "public_key_present",
                                       "public_material_present", "public")
            private_present = _presence(item, "private_key", "private_key_present",
                                        "private_material_present", "private")
            if field.endswith("public_keys"):
                public_present = True
                role = role or "public"
            if field.endswith("private_keys"):
                private_present = True
                role = role or "private"
            is_secret = any(token in field.lower() for token in ("secret", "credential"))
            records.append(_base(
                plugin, context, crypto_type="secret" if is_secret else "key", field=field,
                asset_id=key_id or f"{context.get('asset_id') or plugin.plugin_id}:{'secret' if is_secret else 'key'}:{index}",
                key_id=key_id, key_role=role,
                key_type=_text(_first(item, "key_type", "algorithm", "key_algorithm")) or None,
                key_size=_int(_first(item, "key_size", "key_bits", "bits", "size")),
                curve=_text(_first(item, "curve", "named_curve")) or None,
                key_storage_location=key_storage_location,
                key_lifecycle_state=key_lifecycle_state,
                public_material_present=public_present, private_material_present=private_present,
                initialization_vector=_material_metadata(item, "initialization_vector", "iv", "ivs"),
                salt=_material_metadata(item, "salt", "salts"),
                configuration={"state": _first(item, "state", "status"),
                               "usage": _first(item, "usage", "purposes", "purpose"),
                               "extractable": _first(item, "extractable", "exportable")},
                **_common_metadata(item),
            ))

    for field, value in _field_values(context, ("initialization_vectors", "ivs", "salts")):
        material_type = "salt" if "salt" in field.lower() else "initialization_vector"
        for index, item in enumerate(_items(value)):
            metadata = _material_metadata({material_type: item}, material_type)
            records.append(_base(
                plugin, context, crypto_type="key_material", field=field,
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:{material_type}:{index}",
                material_type=material_type, material_metadata=metadata,
            ))

    certificate_names = ("certificates", "certificate_chain", "tls_certificate", "certificate")
    for field, value in _field_values(context, certificate_names):
        entries = _items(value)
        if field.endswith("certificate_chain") and entries:
            chain = [_certificate_metadata(entry) for entry in entries]
            primary = chain[0]
            primary_key = primary.get("public_key") if isinstance(primary.get("public_key"), dict) else {}
            records.append(_base(
                plugin, context, crypto_type="certificate", field=field,
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:certificate-chain",
                certificate=primary, certificate_chain=chain,
                certificate_serial_number=_text(primary.get("serial_number") or primary.get("serial")) or None,
                certificate_issuer=_text(primary.get("issuer")) or None,
                certificate_subject=_text(primary.get("subject") or primary.get("cn")) or None,
                certificate_valid_from=_text(primary.get("not_before") or primary.get("valid_from")) or None,
                certificate_valid_to=_text(primary.get("not_after") or primary.get("valid_to") or primary.get("expires")) or None,
                certificate_public_key_type=_text(primary_key.get("type") or primary_key.get("algorithm")
                                                  or primary.get("key_type") or primary.get("key_algorithm")) or None,
                certificate_public_key_size=_int(primary_key.get("size") or primary_key.get("key_size")
                                                 or primary.get("key_size")),
                certificate_public_key_curve=_text(primary_key.get("curve") or primary_key.get("named_curve")
                                                   or primary.get("curve")) or None,
                certificate_signature_algorithm=_text(primary.get("signature_algorithm")) or None,
                **_common_metadata(entries[0] if isinstance(entries[0], dict) else {}),
            ))
            continue
        for index, item in enumerate(entries):
            certificate = _certificate_metadata(item)
            if isinstance(item, dict):
                chain_value = item.get("chain") or item.get("certificate_chain")
            else:
                chain_value = None
            chain = ([_certificate_metadata(entry) for entry in _items(chain_value)]
                     if chain_value else [])
            cert_id = _text(certificate.get("fingerprint") or certificate.get("serial_number")
                            or certificate.get("serial") or certificate.get("reference")
                            or certificate.get("name") or certificate.get("id")
                            or certificate.get("arn")) or None
            public_key = certificate.get("public_key") if isinstance(certificate.get("public_key"), dict) else {}
            records.append(_base(
                plugin, context, crypto_type="certificate", field=field,
                asset_id=cert_id or f"{context.get('asset_id') or plugin.plugin_id}:certificate:{index}",
                certificate=certificate, certificate_chain=chain,
                certificate_serial_number=_text(certificate.get("serial_number") or certificate.get("serial")) or None,
                certificate_issuer=_text(certificate.get("issuer")) or None,
                certificate_subject=_text(certificate.get("subject") or certificate.get("cn")) or None,
                certificate_valid_from=_text(certificate.get("not_before") or certificate.get("valid_from")) or None,
                certificate_valid_to=_text(certificate.get("not_after") or certificate.get("valid_to")
                                          or certificate.get("expires")) or None,
                certificate_public_key_type=_text(public_key.get("type") or public_key.get("algorithm")
                                                  or certificate.get("key_type") or certificate.get("key_algorithm")) or None,
                certificate_public_key_size=_int(public_key.get("size") or public_key.get("key_size")
                                                 or certificate.get("key_size")),
                certificate_public_key_curve=_text(public_key.get("curve") or public_key.get("named_curve")
                                                   or certificate.get("curve")) or None,
                certificate_signature_algorithm=_text(certificate.get("signature_algorithm")) or None,
                **_common_metadata(item if isinstance(item, dict) else {}),
            ))

    # Algorithms stated in an explicit configuration artifact are useful even
    # for a plugin that does not implement a vendor-specific crypto parser.
    config = context.get("config")
    if isinstance(config, str):
        try:
            from universal_vendor.plugins._helpers import extract_algorithms
            algorithms = extract_algorithms(config)
        except (ImportError, TypeError, ValueError):
            algorithms = []
        for index, algorithm in enumerate(algorithms):
            records.append(_base(
                plugin, context, crypto_type="algorithm", field="config",
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:config-algorithm:{index}",
                algorithm=algorithm,
            ))

        # Protocols stated in an explicit configuration artifact are still useful
        # when a vendor API does not expose a structured protocol list.
        for index, match in enumerate(re.finditer(
            r"\b(TLS|SSL|SSH|IPsec|IKE|QUIC)\s*[v]?\s*([0-9]+(?:[._][0-9]+)*)?",
            config, re.IGNORECASE,
        )):
            protocol, version = match.group(1), match.group(2)
            records.append(_base(
                plugin, context, crypto_type="protocol", field="config",
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:config-protocol:{index}",
                protocol=protocol, protocol_version=version,
            ))

    return records


def discover_common_dependencies(plugin: Any, context: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert explicit dependency metadata into graph edges."""
    out: list[dict[str, Any]] = []
    for field, value in _field_values(context, ("dependencies", "cryptographic_dependencies")):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                continue
            source = _text(_first(item, "source_asset", "repo", "asset_id", "component"))
            target = _text(_first(item, "target_asset", "library", "package", "name"))
            if not source or not target:
                continue
            out.append({
                "asset_id": source,
                "target_asset": target,
                "relationship": _text(_first(item, "relationship")) or "DEPENDS_ON",
                "detail": {"field": field, "version": _first(item, "version", "release")},
                "source_vendor": plugin.vendor,
                "source_product": plugin.product,
            })
    for root_name, root in _metadata_roots(context):
        for index, component in enumerate(_items(root.get("components"))):
            if not isinstance(component, dict):
                continue
            source = _text(_first(component, "bom-ref", "ref", "name"))
            for target in _items(component.get("dependsOn")):
                target_text = _text(target)
                if source and target_text:
                    out.append({
                        "asset_id": source,
                        "target_asset": target_text,
                        "relationship": "DEPENDS_ON",
                        "detail": {"field": f"{root_name}.components[{index}].dependsOn"},
                        "source_vendor": plugin.vendor,
                        "source_product": plugin.product,
                    })
    return out
