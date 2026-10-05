"""Live Vendor CBOM (24/7 spec §26).

Vendor Event → Event Log → State Transition → CBOM Materializer → LIVE
VENDOR CBOM. Every event (VENDOR_DISCOVERED, ASSET_DISCOVERED,
CONFIG_CHANGED, FIRMWARE_CHANGED, CERTIFICATE_CHANGED, CRYPTO_CHANGED,
VPN_CHANGED, KEY_CHANGED, …) is materialized into the canonical CBOM
component set, and each materialization is versioned.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

from universal_vendor.live.events import UniversalVendorEvent

try:  # guard: cbom service may not be importable in minimal deployments
    from cbom.generator import CbomGenerator

    _HAS_CBOM = True
except Exception:  # pragma: no cover
    CbomGenerator = None  # type: ignore[assignment]
    _HAS_CBOM = False


# The model is intentionally explicit so realtime CBOM output remains useful
# to consumers that do not understand the full vendor-specific payload. Values
# are metadata/classifications only; secret material is never a CBOM property.
# Event types that identify a concrete cryptographic surface even when the
# source did not provide its algorithm parameters. These are observations of
# the changed surface, not inferred algorithms; all detailed properties remain
# absent until evidence supplies them.
_EVENT_SURFACE_TYPES = {
    "TLS_CHANGED": "protocol",
    "IPSEC_CHANGED": "protocol",
    "IKE_CHANGED": "protocol",
    "VPN_CHANGED": "protocol",
    "SSH_CHANGED": "protocol",
    "CERTIFICATE_CREATED": "certificate",
    "CERTIFICATE_RENEWED": "certificate",
    "CERTIFICATE_REVOKED": "certificate",
    "CERTIFICATE_REPLACED": "certificate",
    "CERTIFICATE_EXPIRED": "certificate",
    "CA_CHANGED": "certificate",
    "TRUST_CHAIN_CHANGED": "certificate",
    "SIGNATURE_ALGORITHM_CHANGED": "algorithm",
    "KEY_CHANGED": "key",
}


_OBSERVATION_FIELDS = (
    "crypto_type", "algorithm_type", "algorithm_mode", "padding_scheme",
    "algorithm_oid", "algorithm_parameters", "quantum_safe_status", "protocol", "protocol_version",
    "cipher_suites", "protocol_configuration", "implementation",
    "implementation_version", "library", "library_version",
    "library_dependencies", "fips_certification", "key_id", "key_role",
    "key_type", "key_size", "curve", "key_storage_location",
    "key_lifecycle_state", "public_material_present", "private_material_present",
    "initialization_vector", "salt", "material_type", "material_metadata",
    "secret_type", "secret_storage_location", "certificate", "certificate_chain",
    "certificate_serial_number", "certificate_issuer", "certificate_subject",
    "certificate_valid_from", "certificate_valid_to", "certificate_public_key_type",
    "certificate_public_key_size", "certificate_public_key_curve",
    "certificate_signature_algorithm", "configuration", "observed_usage",
    "rng_name", "rng_type", "rng_source",
    "component_usage", "related_vulnerabilities", "compliance",
    "authenticated_encryption", "forward_secrecy", "side_channel_resistance",
    "crypto_service_type", "crypto_service_provider", "crypto_service_name",
    "crypto_service_version", "quantum_vulnerability", "migration_priority",
    "pqc_alternatives", "migration_status", "visibility", "discovery_method",
)


def _safe_property(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if any(token in str(key).lower().replace("_", "")
                                          for token in ("password", "secret", "token", "privatekey", "keymaterial"))
            else _safe_property(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_safe_property(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_property(item) for item in value]
    if isinstance(value, str) and "BEGIN " in value and "PRIVATE KEY" in value:
        return "<redacted-private-key>"
    return value


def _property_value(value: Any) -> str:
    value = _safe_property(value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


def _crypto_properties(event: UniversalVendorEvent,
                        observation: dict[str, Any],
                        algorithm: str | None = None) -> dict[str, Any]:
    quantum_status = (
        observation.get("quantum_safe_status")
        or observation.get("quantum_vulnerability")
    )
    quantum_vulnerable: bool | None = None
    if isinstance(quantum_status, bool):
        quantum_vulnerable = quantum_status
    elif quantum_status is not None:
        lowered = str(quantum_status).lower()
        if any(token in lowered for token in ("vulnerable", "unsafe", "at_risk", "classical")):
            quantum_vulnerable = True
        elif any(token in lowered for token in ("safe", "supported", "hybrid", "pqc")):
            quantum_vulnerable = False
    algorithm_properties = {
        "algorithm": observation.get("algorithm") or algorithm or event.vendor_metadata.get("algorithm"),
        "primitive": observation.get("algorithm_type"),
        "mode": observation.get("algorithm_mode"),
        "padding": observation.get("padding_scheme"),
        "keySize": observation.get("key_size"),
        "curve": observation.get("curve"),
        "parameters": observation.get("algorithm_parameters"),
    }
    def present(values: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in values.items()
                if value not in (None, "", [], {})}

    certificate = observation.get("certificate")
    certificate = certificate if isinstance(certificate, dict) else {}
    certificate_public_key = certificate.get("public_key")
    certificate_public_key = certificate_public_key if isinstance(certificate_public_key, dict) else {}
    certificate_properties = present({
        "serialNumber": observation.get("certificate_serial_number")
                       or certificate.get("serial_number") or certificate.get("serial"),
        "issuer": observation.get("certificate_issuer") or certificate.get("issuer"),
        "subject": observation.get("certificate_subject") or certificate.get("subject"),
        "validFrom": observation.get("certificate_valid_from")
                     or certificate.get("not_before") or certificate.get("valid_from"),
        "validTo": observation.get("certificate_valid_to")
                   or certificate.get("not_after") or certificate.get("valid_to"),
        "publicKeyType": observation.get("certificate_public_key_type")
                         or certificate_public_key.get("type") or certificate.get("key_type"),
        "publicKeySize": observation.get("certificate_public_key_size")
                         or certificate_public_key.get("size") or certificate.get("key_size"),
        "publicKeyCurve": observation.get("certificate_public_key_curve")
                          or certificate_public_key.get("curve") or certificate.get("curve"),
        "signatureAlgorithm": observation.get("certificate_signature_algorithm")
                              or certificate.get("signature_algorithm"),
        "chain": observation.get("certificate_chain") or certificate.get("chain")
                 or certificate.get("certificate_chain"),
    })

    return _safe_property({
        "assetType": observation.get("crypto_type") or "algorithm",
        "oid": observation.get("algorithm_oid"),
        "algorithmProperties": present(algorithm_properties),
        "nistDesignation": observation.get("quantum_safe_status"),
        "quantumVulnerable": quantum_vulnerable,
        "protocol": observation.get("protocol"),
        "protocolVersion": observation.get("protocol_version"),
        "cipherSuites": observation.get("cipher_suites") or [],
        "protocolProperties": present({
            "name": observation.get("protocol"),
            "version": observation.get("protocol_version"),
            "cipherSuites": observation.get("cipher_suites"),
            "configuration": observation.get("protocol_configuration"),
        }),
        "certificateProperties": certificate_properties,
        "keyProperties": present({
            "id": observation.get("key_id"),
            "role": observation.get("key_role"),
            "type": observation.get("key_type"),
            "size": observation.get("key_size"),
            "curve": observation.get("curve"),
            "storage": observation.get("key_storage_location"),
            "lifecycle": observation.get("key_lifecycle_state"),
            "publicMaterialPresent": observation.get("public_material_present"),
            "privateMaterialPresent": observation.get("private_material_present"),
        }),
        "implementationProperties": present({
            "name": observation.get("implementation"),
            "version": observation.get("implementation_version"),
            "usage": observation.get("component_usage"),
            "authenticatedEncryption": observation.get("authenticated_encryption"),
            "forwardSecrecy": observation.get("forward_secrecy"),
            "sideChannelResistance": observation.get("side_channel_resistance"),
        }),
        "libraryProperties": present({
            "name": observation.get("library"),
            "version": observation.get("library_version"),
            "dependencies": observation.get("library_dependencies"),
            "fipsCertification": observation.get("fips_certification"),
        }),
        "serviceProperties": present({
            "type": observation.get("crypto_service_type"),
            "provider": observation.get("crypto_service_provider"),
            "name": observation.get("crypto_service_name"),
            "version": observation.get("crypto_service_version"),
        }),
        "riskProperties": present({
            "vulnerabilities": observation.get("related_vulnerabilities"),
            "compliance": observation.get("compliance"),
            "rng": observation.get("rng_name"),
            "rngType": observation.get("rng_type"),
        }),
        "migrationProperties": present({
            "quantumRisk": observation.get("quantum_vulnerability"),
            "priority": observation.get("migration_priority"),
            "alternatives": observation.get("pqc_alternatives"),
            "status": observation.get("migration_status"),
        }),
        "evidenceReference": event.evidence_reference,
    })


class LiveCbom:
    """Event-sourced vendor CBOM materializer.

    Component key = (asset_id, crypto_type, component_identity, event_type)
    so repeated source observations update rather than duplicate while distinct
    crypto-surface records stay distinct; each materialization is versioned.
    """

    def __init__(self) -> None:
        # Include crypto type in the identity. A single vendor asset can have
        # an algorithm, protocol, certificate, key, library, service, and RNG
        # observation with no algorithm name; collapsing those to "unknown"
        # loses real scanner evidence.
        self._components: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._event_log: list[dict[str, Any]] = []
        self._version = 1
        # Liveness, kept separately from the event log and the version.
        # See observe_liveness().
        self._observations = 0
        self._last_observed_at: str | None = None

    def materialize(self, event: UniversalVendorEvent) -> dict[str, Any]:
        """Apply one vendor event to the CBOM state. Returns the event record."""
        record = event.to_dict()
        self._event_log.append(record)
        if event.event_type == "ASSET_REMOVED":
            self._remove_asset(event)
        else:
            self._upsert_components(event)
        self._version += 1
        self._observations += 1
        self._last_observed_at = _utc_now_iso()
        return record

    def observe_liveness(self, *, event_count: int) -> None:
        """Record that a quiet poll re-saw `event_count` known events.

        The engine used to express this by calling materialize() again for
        every known event on every quiet tick. That kept components
        idempotent, but each call appended to the event log and bumped the
        version -- so with K known events and T quiet ticks the log grew by
        K*T rows and the version counted ticks rather than changes. On a
        two-second loop that is roughly 43k rows a day for an estate that
        never changed, and a CBOM consumer diffing on `version` saw constant
        churn against identical content.

        It also contradicted the engine's own contract: the comment above
        the processing step promises "no repeated CBOM version bumps".

        Liveness is a different fact from change, so it gets its own
        fields. This is O(1) per tick, bounded in memory, and leaves
        `version` meaning "the content changed this many times".
        """
        if event_count <= 0:
            return
        self._observations += 1
        self._last_observed_at = _utc_now_iso()

    def _upsert_components(self, event: UniversalVendorEvent) -> None:
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        metadata = event.vendor_metadata or {}
        observation = metadata.get("observation")
        observation = observation if isinstance(observation, dict) else {}
        event_type = event.event_type.value if hasattr(event.event_type, "value") \
            else str(event.event_type)

        # Only materialize an asset when the event contains an explicit crypto
        # observation. A health/config/asset event with only labels or an
        # unreadable artifact must not become a fabricated "unknown" algorithm.
        def identity(value: Any) -> str:
            if isinstance(value, dict):
                value = (value.get("algorithm") or value.get("name")
                         or value.get("protocol") or value.get("id")
                         or value.get("type"))
            return str(value) if value not in (None, "") else ""

        algorithms = metadata.get("algorithms") or []
        if isinstance(algorithms, str):
            algorithms = [algorithms]
        elif not isinstance(algorithms, (list, tuple, set)):
            algorithms = [algorithms]
        algorithms = [identity(value) for value in algorithms if value not in (None, "")]
        explicit_algorithm = metadata.get("algorithm")
        if explicit_algorithm not in (None, "") and not algorithms:
            algorithms = [identity(explicit_algorithm)]
        if not algorithms and observation:
            observed_identity = (observation.get("algorithm")
                                 or observation.get("name")
                                 or observation.get("protocol")
                                 or observation.get("library")
                                 or observation.get("key_id")
                                 or observation.get("crypto_service_name")
                                 or observation.get("rng_name")
                                 or observation.get("certificate_serial_number"))
            if observed_identity not in (None, ""):
                algorithms = [identity(observed_identity)]
        if not algorithms:
            safe_event_fields = {
                field: metadata[field] for field in _OBSERVATION_FIELDS
                if field in metadata and metadata[field] not in (None, "", [], {})
            }
            if safe_event_fields:
                identity_value = (
                    safe_event_fields.get("algorithm")
                    or safe_event_fields.get("protocol")
                    or safe_event_fields.get("library")
                    or safe_event_fields.get("key_id")
                    or safe_event_fields.get("crypto_service_name")
                    or safe_event_fields.get("rng_name")
                    or safe_event_fields.get("certificate_serial_number")
                    or safe_event_fields.get("crypto_type")
                )
                inferred_type = safe_event_fields.get("crypto_type") or (
                    "protocol" if safe_event_fields.get("protocol") else
                    "library" if safe_event_fields.get("library") else
                    "key" if safe_event_fields.get("key_id") else
                    "service" if safe_event_fields.get("crypto_service_name") else
                    "rng" if safe_event_fields.get("rng_name") else
                    "certificate" if safe_event_fields.get("certificate_serial_number") else
                    "algorithm"
                )
                safe_event_fields["crypto_type"] = inferred_type
                if identity_value in (None, "", inferred_type) and not any(
                    key != "crypto_type" for key in safe_event_fields
                ):
                    return
                algorithms = [identity(identity_value)]
                observation = {**safe_event_fields, **observation}

        # The event type itself is evidence of a concrete surface transition
        # (for example TLS or certificate replacement), but it is not evidence
        # of an algorithm. Preserve that honest observation without creating an
        # ``unknown`` algorithm/component for config or health-only events.
        surface_type = _EVENT_SURFACE_TYPES.get(event_type)
        if not algorithms and surface_type:
            algorithms = [event_type]
            observation = {"crypto_type": surface_type, **observation}

        algorithms = [value for value in algorithms if value]
        if not algorithms:
            return

        crypto_type = str(observation.get("crypto_type") or
                          ("algorithm" if metadata.get("algorithms") or
                           metadata.get("algorithm") else algorithms[0]))
        base_properties = [
            {"name": "vendor", "value": event.vendor},
            {"name": "product", "value": event.product},
            {"name": "source", "value": event.source},
            {"name": "evidence_reference",
             "value": event.evidence_reference or ""},
        ]
        observation_properties: list[dict[str, str]] = []
        for field_name in _OBSERVATION_FIELDS:
            value = observation.get(field_name)
            if value not in (None, "", [], {}):
                observation_properties.append({
                    "name": f"cryptoscan:{field_name}",
                    "value": _property_value(value),
                })
        for component_identity in algorithms:
            key = (asset_id, crypto_type, component_identity, event_type)
            effective_observation = {"crypto_type": crypto_type, **observation}
            algorithm_for_properties = (
                component_identity if crypto_type == "algorithm" else None
            )
            properties = list(base_properties) + observation_properties
            if crypto_type == "algorithm" or observation.get("algorithm"):
                properties.append({"name": "algorithm", "value": component_identity})
            else:
                properties.append({"name": "asset_reference", "value": component_identity})
            component = {
                "type": "crypto-asset",
                "group": event.asset_type or "other",
                "name": asset_id,
                "version": event.product_version or "unknown",
                "purl": f"pkg:vendor/{event.vendor.lower()}/{event.product.lower()}",
                "cryptoProperties": _crypto_properties(
                    event, effective_observation, algorithm_for_properties,
                ),
                "properties": properties,
                "bom-ref": f"{asset_id}:{crypto_type}:{component_identity}",
            }
            self._components[key] = component

    def _remove_asset(self, event: UniversalVendorEvent) -> None:
        asset_id = event.asset_id or f"{event.vendor}:{event.product}"
        for key in [k for k in self._components if k[0] == asset_id]:
            del self._components[key]

    # ── output ────────────────────────────────────────────────────────

    def components(self) -> list[dict[str, Any]]:
        return list(self._components.values())

    def export_state(self) -> dict[str, Any]:
        """Return the safe materializer state for durable realtime replay."""
        return {
            "version": self._version,
            # Liveness travels with the state so a replayed engine does not
            # look like it has never observed anything.
            "observations": self._observations,
            "last_observed_at": self._last_observed_at,
            "components": [
                {
                    "asset_id": key[0],
                    "crypto_type": key[1],
                    "identity": key[2],
                    "event_type": key[3],
                    "component": component,
                }
                for key, component in self._components.items()
            ],
        }

    def restore_state(self, state: dict[str, Any] | None) -> None:
        """Restore only a previously exported, safe CBOM state."""
        if not isinstance(state, dict):
            return
        restored: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in state.get("components") or []:
            if not isinstance(item, dict) or not isinstance(item.get("component"), dict):
                continue
            key = tuple(str(item.get(name) or "") for name in
                       ("asset_id", "crypto_type", "identity", "event_type"))
            if all(key):
                restored[key] = dict(item["component"])
        self._components = restored
        try:
            self._version = max(1, int(state.get("version") or 1))
        except (TypeError, ValueError):
            self._version = 1
        try:
            self._observations = max(0, int(state.get("observations") or 0))
        except (TypeError, ValueError):
            self._observations = 0
        last_seen = state.get("last_observed_at")
        self._last_observed_at = last_seen if isinstance(last_seen, str) else None

    def event_log(self) -> list[dict[str, Any]]:
        return list(self._event_log)

    def liveness(self) -> dict[str, Any]:
        """How recently the estate was confirmed, independent of change.

        `observations` counts polls that saw the estate (changed or not);
        `version` counts only content changes. A monitor that has gone
        quiet is the difference between the two moving and neither moving.
        """
        return {
            "observations": self._observations,
            "last_observed_at": self._last_observed_at,
            "version": self._version,
        }

    def version(self) -> int:
        return self._version

    def generate_document(self, *, name: str = "live-vendor-cbom",
                          tool_version: str = "universal-vendor-live") -> dict[str, Any]:
        """Serialize to CycloneDX via the shared CbomGenerator when present."""
        if not _HAS_CBOM:
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": self._version,
                "name": name,
                "components": self.components(),
                "note": "cbom service unavailable; emitted canonical components",
            }
        components = self.components()
        records = [self._component_as_record(c) for c in components]
        document = CbomGenerator().from_records(
            records,
            name=name,
            version=f"v{self._version}",
            tool_version=tool_version,
        )
        # The shared generator supplies CycloneDX metadata/dependency structure,
        # while this materializer owns the realtime crypto properties. Reattach
        # the complete safe projection after conversion so a generic record
        # adapter cannot silently discard vendor fields.
        generated = document.get("components") or []
        for index, component in enumerate(components):
            if index >= len(generated):
                break
            generated[index].update({
                "type": component.get("type", "cryptographic-asset"),
                "group": component.get("group"),
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "cryptoProperties": component.get("cryptoProperties") or {},
                "properties": component.get("properties") or [],
                "bom-ref": component.get("bom-ref"),
            })
        return document

    @staticmethod
    def _component_as_record(component: dict[str, Any]) -> dict[str, Any]:
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        prefixed = {
            name.removeprefix("cryptoscan:"): value
            for name, value in props.items() if name.startswith("cryptoscan:")
        }
        crypto = component.get("cryptoProperties") or {}
        algorithm_properties = crypto.get("algorithmProperties") or {}
        observation = {
            "algorithm": props.get("algorithm"),
            "algorithm_type": algorithm_properties.get("primitive"),
            "algorithm_mode": algorithm_properties.get("mode"),
            "padding_scheme": algorithm_properties.get("padding"),
            "algorithm_oid": crypto.get("oid"),
            "key_size": algorithm_properties.get("keySize"),
            "curve": algorithm_properties.get("curve"),
            "protocol": crypto.get("protocol"),
            "protocol_version": crypto.get("protocolVersion"),
            "cipher_suites": crypto.get("cipherSuites") or [],
            **prefixed,
        }
        finding_data = {
            key: value for key, value in observation.items()
            if value not in (None, "", [], {})
        }
        return {
            "vendor": props.get("vendor", "unknown"),
            "product": props.get("product", "unknown"),
            "algorithm": props.get("algorithm", "unknown"),
            "algorithm_family": props.get("cryptoscan:algorithm_type"),
            "mode": props.get("cryptoscan:algorithm_mode"),
            "padding": props.get("cryptoscan:padding_scheme"),
            "key_size": props.get("cryptoscan:key_size"),
            "source": props.get("source", "unknown"),
            "asset_id": component["name"],
            "product_version": component.get("version"),
            "purpose": "vendor-crypto",
            "file_path": "",
            "line_number": None,
            "nist_status": crypto.get("nistDesignation"),
            "quantum_vulnerable": crypto.get("quantumVulnerable"),
            "pqc_replacement": props.get("cryptoscan:pqc_alternatives"),
            "finding_data": finding_data,
            "evidence_id": props.get("evidence_reference"),
        }
