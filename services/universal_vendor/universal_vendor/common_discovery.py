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
            "name", "id", "key_id", "algorithm", "protocol", "library",
            "version", "type", "key_type", "public_key", "private_key",
            "initialization_vector", "iv", "salt", "subject", "issuer",
        }):
            return [value]
        return [{"name": key, **(item if isinstance(item, dict) else {"value": item})}
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [value]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _first(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", []):
            return value
    return None


def _int(value: Any) -> int | None:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else None
    except (TypeError, ValueError):
        return None


def _presence(record: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in record:
            value = record[key]
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
        if key in value and value[key] not in (None, ""):
            result[key] = value[key]
    result["present"] = True
    return result


def _base(plugin: Any, context: dict[str, Any], *, crypto_type: str,
          field: str, asset_id: str | None = None, **values: Any) -> dict[str, Any]:
    source = "api_metadata" if field.startswith("api_metadata") else "artifact"
    visibility = "API_VISIBLE" if source == "api_metadata" else "OBSERVED"
    record = {
        "vendor": plugin.vendor,
        "product": plugin.product,
        "product_version": context.get("version"),
        "asset_id": asset_id or context.get("asset_id") or f"{plugin.vendor}:{plugin.product}",
        "crypto_type": crypto_type,
        "source": f"{plugin.plugin_id}:common",
        "evidence_field": field,
        "discovery_method": "structured_metadata" if source == "api_metadata" else "artifact",
        "confidence": 0.85 if source == "api_metadata" else 0.75,
        "visibility": visibility,
    }
    record.update({key: value for key, value in values.items() if value is not None})
    return record


def _metadata_roots(context: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    for key in ("api_metadata", "metadata", "crypto_metadata", "cbom", "sbom"):
        value = context.get(key)
        if isinstance(value, str):
            # JSON parsing is deliberately limited to explicit metadata blobs.
            try:
                import json
                value = json.loads(value)
            except (TypeError, ValueError):
                continue
        if isinstance(value, dict):
            yield key, value


def _field_values(context: dict[str, Any], names: Iterable[str]) -> Iterable[tuple[str, Any]]:
    for name in names:
        if name in context and context[name] not in (None, "", [], {}):
            yield name, context[name]
    for root_name, root in _metadata_roots(context):
        for name in names:
            if name in root and root[name] not in (None, "", [], {}):
                yield f"{root_name}.{name}", root[name]


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
                    algorithm_parameters={
                        key: algorithm_properties.get(key)
                        for key in ("primitive", "parameterSetIdentifier", "mode")
                        if algorithm_properties.get(key) is not None
                    },
                ))
            library = _first(component, "library", "implementation", "provider")
            if library:
                records.append(_base(
                    plugin, context, crypto_type="library",
                    field=f"{root_name}.components[{index}]",
                    asset_id=_text(_first(component, "bom-ref", "ref", "name")) or None,
                    library=_text(library),
                    library_version=_text(_first(component, "version", "release")) or None,
                ))

    algorithm_names = (
        "algorithms", "cryptographic_algorithms", "ciphers", "cipher_suites",
    )
    for field, value in _field_values(context, algorithm_names):
        for index, item in enumerate(_items(value)):
            if isinstance(item, dict):
                algorithm = _first(item, "algorithm", "name", "cipher", "suite", "value")
                details = {"mode": _first(item, "mode"),
                           "key_size": _int(_first(item, "key_size", "key_bits", "bits"))}
                asset_id = _text(_first(item, "asset_id", "id", "name")) or None
            else:
                algorithm, details, asset_id = item, {}, None
            algorithm_text = _text(algorithm)
            if not algorithm_text or algorithm_text.upper() in {"UNKNOWN", "NONE"}:
                continue
            records.append(_base(
                plugin, context, crypto_type="algorithm", field=field,
                asset_id=asset_id or f"{context.get('asset_id') or plugin.plugin_id}:algorithm:{index}",
                algorithm=algorithm_text, algorithm_parameters=details,
                configuration=details,
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
            else:
                protocol, versions, algorithm, observed, asset_id = item, None, None, None, None
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
                algorithm=_text(algorithm) or None,
                observed_usage=observed,
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
            else:
                name, version, implementation, asset_id = item, None, None, None
            name_text = _text(name)
            if not name_text:
                continue
            records.append(_base(
                plugin, context, crypto_type="library", field=field,
                asset_id=asset_id or f"{context.get('asset_id') or plugin.plugin_id}:library:{index}",
                library=name_text, library_version=_text(version) or None,
                implementation=_text(implementation) or None,
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
            ))

    key_names = (
        "keys", "key_metadata", "cryptographic_keys", "key_pairs",
        "public_keys", "private_keys", "key_material",
    )
    for field, value in _field_values(context, key_names):
        for index, item in enumerate(_items(value)):
            if not isinstance(item, dict):
                item = {"value": item}
            key_id = _text(_first(item, "key_id", "id", "alias", "name", "reference")) or None
            role = _text(_first(item, "key_role", "role", "type")) or None
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
            records.append(_base(
                plugin, context, crypto_type="key", field=field,
                asset_id=key_id or f"{context.get('asset_id') or plugin.plugin_id}:key:{index}",
                key_id=key_id, key_role=role,
                key_type=_text(_first(item, "key_type", "algorithm", "key_algorithm")) or None,
                key_size=_int(_first(item, "key_size", "key_bits", "bits", "size")),
                curve=_text(_first(item, "curve", "named_curve")) or None,
                public_material_present=public_present, private_material_present=private_present,
                initialization_vector=_material_metadata(item, "initialization_vector", "iv", "ivs"),
                salt=_material_metadata(item, "salt", "salts"),
                configuration={"state": _first(item, "state", "status"),
                               "usage": _first(item, "usage", "purposes", "purpose"),
                               "extractable": _first(item, "extractable", "exportable")},
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
            records.append(_base(
                plugin, context, crypto_type="certificate", field=field,
                asset_id=f"{context.get('asset_id') or plugin.plugin_id}:certificate-chain",
                certificate=chain[0], certificate_chain=chain,
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
            records.append(_base(
                plugin, context, crypto_type="certificate", field=field,
                asset_id=cert_id or f"{context.get('asset_id') or plugin.plugin_id}:certificate:{index}",
                certificate=certificate, certificate_chain=chain,
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
