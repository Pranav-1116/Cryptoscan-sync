"""Normalize raw runtime observations into crypto operation events (spec 92 §7–§13).

An event states exactly what the adapter saw:

    {algorithm: AES, key_size: 256, mode: GCM, operation: ENCRYPT, nonce_length: 96}

and nothing more. A parameter the adapter did not report is ``UNKNOWN`` — never
``128`` because AES tags usually are, never ``PKCS#1`` because that used to be
the default. Guessing here would turn an observation into a fabricated fact,
which is exactly what a bank audit cannot tolerate.

The event also carries its **attribution level** and the identity chain
(host → process → container → image → deployment → application) so a crypto
operation can be traced back to a deployable artifact.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from runtime.engine.adapters import EVENT_FIELDS, get_adapter
from runtime.engine.levels import evidence_type_for_level, level_for_evidence

SCHEMA = "cryptoscan.runtime-crypto-event/1"

#: §8 operation taxonomy — "crypto found" is not an operation
OPERATIONS = (
    "ENCRYPT",
    "DECRYPT",
    "SIGN",
    "VERIFY",
    "HASH",
    "MAC",
    "KEY_AGREEMENT",
    "KEY_DERIVATION",
    "KEY_GENERATION",
    "KEY_WRAP",
    "KEY_UNWRAP",
    "TLS_HANDSHAKE",
    "UNKNOWN",
)

#: raw operation spellings adapters emit, folded onto the taxonomy
_OPERATION_ALIASES = {
    "ENCRYPT": "ENCRYPT",
    "ENCRYPTION": "ENCRYPT",
    "EVP_ENCRYPT": "ENCRYPT",
    "DECRYPT": "DECRYPT",
    "DECRYPTION": "DECRYPT",
    "SIGN": "SIGN",
    "SIGNATURE": "SIGN",
    "VERIFY": "VERIFY",
    "HASH": "HASH",
    "DIGEST": "HASH",
    "MAC": "MAC",
    "HMAC": "MAC",
    "KDF": "KEY_DERIVATION",
    "DERIVE": "KEY_AGREEMENT",
    "KEY_AGREEMENT": "KEY_AGREEMENT",
    "ECDH": "KEY_AGREEMENT",
    "KEY_DERIVATION": "KEY_DERIVATION",
    "KEY_GENERATION": "KEY_GENERATION",
    "KEYGEN": "KEY_GENERATION",
    "KEY_WRAP": "KEY_WRAP",
    "WRAP": "KEY_WRAP",
    "KEY_UNWRAP": "KEY_UNWRAP",
    "UNWRAP": "KEY_UNWRAP",
    "TLS_HANDSHAKE": "TLS_HANDSHAKE",
    "HANDSHAKE": "TLS_HANDSHAKE",
}

#: parameters whose values are *metadata* and are safe to keep as numbers
_LENGTH_FIELDS = ("nonce_length", "tag_length", "iv_length", "digest_length", "output_length", "key_size")

#: field-name fragments that mean the observation carried content, not metadata
_FORBIDDEN_FRAGMENTS = (
    "plaintext",
    "cleartext",
    "ciphertext",
    "key_bytes",
    "key_material",
    "raw_key",
    "secret",
    "password",
    "passwd",
    "iv_value",
    "nonce_value",
    "salt_value",
    "private_key",
    "key_pem",
    "payload",
    "customer",
    "pan",
    "card_number",
    "cvv",
)


class CryptoObservationRejected(ValueError):
    """Raised when an observation carries content, credentials or key material."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "_").replace(" ", "_")


def _int_or_unknown(value: Any) -> int | str:
    if value is None or value == "":
        return "UNKNOWN"
    try:
        return int(value)
    except (TypeError, ValueError):
        return "UNKNOWN"


def _reject_forbidden(observation: Any, path: str = "") -> None:
    stack: list[tuple[str, Any]] = [(path, observation)]
    while stack:
        where, node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                field_path = f"{where}.{key}" if where else str(key)
                lowered = str(key).lower()
                if any(fragment in lowered for fragment in _FORBIDDEN_FRAGMENTS):
                    raise CryptoObservationRejected(
                        f"field '{field_path}' looks like content or key material; runtime events carry "
                        "algorithm parameters only"
                    )
                stack.append((field_path, value))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                stack.append((f"{where}[{index}]", value))


def assert_metadata_only(observation: Any) -> None:
    """Reject an observation that carries content, credentials or key material.

    Called before any other validation so the caller is told the real problem
    ("this field is content") rather than "this field is unknown".
    """
    _reject_forbidden(observation)


def normalize_operation(value: Any) -> str:
    """Fold an adapter's spelling onto the command taxonomy."""
    return _OPERATION_ALIASES.get(_norm(value), "UNKNOWN")


def build_runtime_event(
    observation: dict[str, Any],
    *,
    authorization: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """One raw adapter observation → one normalized runtime crypto event."""
    if not isinstance(observation, dict):
        raise CryptoObservationRejected("a runtime observation must be an object")
    _reject_forbidden(observation)

    adapter = get_adapter(observation.get("adapter") or observation.get("source"))
    source = str(observation.get("source") or (adapter.source if adapter else "BINARY_TRACE")).upper()
    level = level_for_evidence(source)
    if adapter is None:
        level = 6

    operation = normalize_operation(observation.get("operation"))
    attributes = {key: value for key, value in (observation.get("attributes") or {}).items() if value is not None}
    _reject_forbidden(attributes)

    decomposition = {
        "mode": observation.get("mode"),
        "padding": observation.get("padding"),
        "hash": observation.get("hash"),
        "curve": observation.get("curve"),
        "kdf": observation.get("kdf"),
    }
    lengths = {field: _int_or_unknown(observation.get(field)) for field in _LENGTH_FIELDS}
    # a length that was not reported is UNKNOWN; it is never defaulted
    observed_fields = sorted(
        field
        for field, value in {**decomposition, **lengths}.items()
        if value not in (None, "", "UNKNOWN")
    )

    event: dict[str, Any] = {
        "schema": SCHEMA,
        "event_type": "CRYPTO_OPERATION",
        "event_id": observation.get("event_id") or f"rte-{uuid.uuid4().hex}",
        "evidence_type": evidence_type_for_level(level),
        "attribution_level": level,
        "source": source,
        "adapter": adapter.id if adapter else None,
        "crypto_provider": observation.get("crypto_provider"),
        "provider_version": observation.get("provider_version"),
        "library": observation.get("library"),
        "function": observation.get("function"),
        # identity chain (spec §22–§23): event → process → container → image → deployment → app
        "identity": {
            "host": observation.get("host"),
            "application": observation.get("application"),
            "process": observation.get("process"),
            "pid": _int_or_unknown(observation.get("pid")),
            "executable": observation.get("executable"),
            "executable_digest": observation.get("executable_digest"),
            "container_id": observation.get("container_id"),
            "container_digest": observation.get("container_digest"),
            "image": observation.get("image"),
            "cluster": observation.get("cluster"),
            "namespace": observation.get("namespace"),
            "pod": observation.get("pod"),
            "deployment": observation.get("deployment"),
        },
        "operation": operation,
        "algorithm": observation.get("algorithm"),
        "key_size": lengths["key_size"],
        "decomposition": decomposition,
        "parameters": {
            "nonce_length": lengths["nonce_length"],
            "tag_length": lengths["tag_length"],
            "iv_length": lengths["iv_length"],
            "digest_length": lengths["digest_length"],
            "output_length": lengths["output_length"],
            "salt_present": observation.get("salt_present"),
            "info_present": observation.get("info_present"),
        },
        "observed_fields": observed_fields,
        "unobserved_fields": sorted(
            field
            for field, value in {**decomposition, **lengths}.items()
            if value in (None, "", "UNKNOWN")
        ),
        "transport": {
            "tls_version": observation.get("tls_version"),
            "cipher_suite": observation.get("cipher_suite"),
            "mutual_tls": observation.get("mutual_tls"),
        },
        "key_reference": observation.get("key_reference"),
        "device": observation.get("device"),
        "caller_identity": observation.get("caller_identity"),
        "observation_count": max(1, int(observation.get("observation_count") or 1)),
        "attributes": attributes,
        "observed_at": observed_at or observation.get("timestamp") or _now(),
        "authorization": authorization,
        "limitations": [],
        "boundary": (
            "runtime observation of one operation on one process identity — it is not a statement "
            "about the application's whole crypto inventory"
        ),
    }

    if event["algorithm"] is None:
        event["limitations"].append("the adapter did not report an algorithm: this operation stays UNKNOWN")
    if "key_size" in event["unobserved_fields"] and event["algorithm"]:
        event["limitations"].append(
            "key size was not reported by the instrumentation and is NOT inferred from the algorithm name"
        )
    if adapter is not None and adapter.cannot_report:
        event["limitations"].append(f"{adapter.id} cannot report: {'; '.join(adapter.cannot_report[:2])}")
    if level == 6:
        event["limitations"].append(
            "no approved observation covers this code path (custom crypto or an unsupported runtime) — "
            "the operation is UNKNOWN, not absent"
        )
    if level == 4:
        event["limitations"].append(
            "a negotiated session proves transport crypto only; application crypto is a separate layer"
        )
    return event


def build_runtime_events(
    observations: Iterable[dict[str, Any]],
    *,
    authorization: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize a batch, rejecting the whole batch on a forbidden field."""
    events: list[dict[str, Any]] = []
    for observation in observations:
        events.append(build_runtime_event(observation, authorization=authorization, observed_at=observed_at))
    return events


def event_fields() -> tuple[str, ...]:
    """The accepted input field set (exposed for documentation/tests)."""
    return EVENT_FIELDS
