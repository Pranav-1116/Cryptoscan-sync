"""CryptoLog event contract v1 (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 1).

The event taxonomy, the canonical event schema, event identity and
deduplication, provenance and evidence requirements, privacy classification
and the event versioning strategy.

CryptoLog is an event intelligence domain: it references the authoritative
evidence records and Digital Twin assets; it never becomes a second evidence
database. The contract's honesty rules, each enforced at construction:

- the three logging kinds keep their own trust semantics: ACTIVITY
  (observed cryptographic activity), CHANGE (configuration and asset
  changes) and AUDIT (what CryptoScan discovered and did);
- every event carries evidence ids: an observed event without evidence is
  a rumor;
- every relationship carries its relationship evidence: every graph
  relationship should have evidence behind it;
- usage evidence levels are never confused (capability / static / configured
  / runtime / network-negotiated), and PQC capability discovery is never
  proof of PQC usage;
- prohibited values are never logged: private keys, secret keys, plaintext,
  passwords, tokens, session cookies, decrypted payloads, HSM key material.
  Metadata, counters and approved evidence only;
- a correction never overwrites the original event: the original stays
  byte-identical and the correction supersedes it with its own provenance;
- identical re-ingestion is idempotent (DUPLICATE), and a different event
  under an existing deduplication key is a CONFLICT: never a silent
  overwrite;
- an AGGREGATE-mode event never claims complete event coverage.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

EVENT_SCHEMA = "cryptoscan.cryptolog-event/1"

# ---- taxonomy: 12 categories + PQC subtypes -------------------------------

CRYPTO_OPERATION = "CRYPTO_OPERATION"
ALGORITHM = "ALGORITHM"
KEY_LIFECYCLE = "KEY_LIFECYCLE"
CERTIFICATE = "CERTIFICATE"
TLS = "TLS"
SSH = "SSH"
IPSEC_VPN = "IPSEC_VPN"
HSM_KMS = "HSM_KMS"
CRYPTO_LIBRARY = "CRYPTO_LIBRARY"
CONFIGURATION = "CONFIGURATION"
CRYPTO_DRIFT = "CRYPTO_DRIFT"
GOVERNANCE = "GOVERNANCE"

CATEGORIES: tuple[str, ...] = (
    CRYPTO_OPERATION, ALGORITHM, KEY_LIFECYCLE, CERTIFICATE, TLS, SSH,
    IPSEC_VPN, HSM_KMS, CRYPTO_LIBRARY, CONFIGURATION, CRYPTO_DRIFT,
    GOVERNANCE,
)

PQC_SUBTYPES: tuple[str, ...] = (
    "PQC_CAPABILITY_DISCOVERED",
    "PQC_CONFIGURATION_CHANGED",
    "PQC_OPERATION_OBSERVED",
    "PQC_NEGOTIATION_OBSERVED",
    "PQC_MIGRATION_VALIDATED",
    "PQC_REGRESSION_DETECTED",
)

#: known event types map to their taxonomy category; a known type may not
#: file itself under another category
EVENT_TYPES: dict[str, str] = {
    "CRYPTO_OPERATION_OBSERVED": CRYPTO_OPERATION,
    "ALGORITHM_OBSERVED": ALGORITHM,
    "KEY_METADATA_CHANGED": KEY_LIFECYCLE,
    "KEY_ROTATED": KEY_LIFECYCLE,
    "CERTIFICATE_ISSUED": CERTIFICATE,
    "CERTIFICATE_REPLACEMENT": CERTIFICATE,
    "CERTIFICATE_EXPIRED": CERTIFICATE,
    "TLS_NEGOTIATION_OBSERVED": TLS,
    "TLS_VERSION_CHANGED": TLS,
    "SSH_HOST_KEY_CHANGED": SSH,
    "IPSEC_TRANSFORM_CHANGED": IPSEC_VPN,
    "HSM_KEY_METADATA_CHANGE": HSM_KMS,
    "HSM_FIRMWARE_UPDATED": HSM_KMS,
    "KMS_OPERATION_OBSERVED": HSM_KMS,
    "CRYPTO_LIBRARY_ADDED": CRYPTO_LIBRARY,
    "CRYPTO_LIBRARY_REMOVED": CRYPTO_LIBRARY,
    "CRYPTO_LIBRARY_REGRESSION": CRYPTO_LIBRARY,
    "CRYPTO_CONFIGURATION_CHANGED": CONFIGURATION,
    "CRYPTOGRAPHIC_REGRESSION": CRYPTO_DRIFT,
    "GOVERNANCE_ACTION": GOVERNANCE,
    "PQC_CAPABILITY_DISCOVERED": ALGORITHM,
    "PQC_CONFIGURATION_CHANGED": CONFIGURATION,
    "PQC_OPERATION_OBSERVED": CRYPTO_OPERATION,
    "PQC_NEGOTIATION_OBSERVED": TLS,
    "PQC_MIGRATION_VALIDATED": GOVERNANCE,
    "PQC_REGRESSION_DETECTED": CRYPTO_DRIFT,
}

# ---- the three logging kinds, with distinct trust semantics ---------------

ACTIVITY = "ACTIVITY"
CHANGE = "CHANGE"
AUDIT = "AUDIT"

LOGGING_KINDS: tuple[str, ...] = (ACTIVITY, CHANGE, AUDIT)

# ---- evidence levels (never merged; capability is never usage) ------------

CAPABILITY = "CAPABILITY"
STATIC = "STATIC"
CONFIGURED = "CONFIGURED"
RUNTIME = "RUNTIME"
NETWORK_NEGOTIATED = "NETWORK_NEGOTIATED"

EVIDENCE_LEVELS: tuple[str, ...] = (
    CAPABILITY, STATIC, CONFIGURED, RUNTIME, NETWORK_NEGOTIATED)

#: levels that describe usage: a capability discovery may never claim them
USAGE_LEVELS: frozenset[str] = frozenset({RUNTIME, NETWORK_NEGOTIATED})

#: event types whose observation IS negotiation: NETWORK_NEGOTIATED or bust
_NEGOTIATION_TYPES = frozenset({"TLS_NEGOTIATION_OBSERVED",
                                "PQC_NEGOTIATION_OBSERVED"})
#: event types whose observation IS a runtime operation
_OPERATION_TYPES = frozenset({"CRYPTO_OPERATION_OBSERVED",
                              "PQC_OPERATION_OBSERVED",
                              "KMS_OPERATION_OBSERVED"})

# ---- vocabularies ---------------------------------------------------------

SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

INTEGRITY_STATES: tuple[str, ...] = ("VERIFIED", "UNVERIFIED", "INVALID_HASH",
                                     "CHAIN_BROKEN", "SIGNATURE_INVALID",
                                     "CHECKPOINT_MISSING", "ARTIFACT_MISSING")
SIGNATURE_STATES: tuple[str, ...] = ("VALID", "INVALID", "UNSIGNED", "UNKNOWN")

INVESTIGATION_STATES: tuple[str, ...] = (
    "OBSERVED", "CHANGE_OBSERVED", "PENDING_VALIDATION",
    "INVESTIGATION_REQUIRED")

SOURCE_TYPES: tuple[str, ...] = (
    "NETWORK_OBSERVATION", "CONFIGURATION_OBSERVATION", "SBOM_OBSERVATION",
    "HBOM_OBSERVATION", "HSM_OBSERVATION", "KMS_OBSERVATION",
    "CERTIFICATE_OBSERVATION", "RUNTIME_OBSERVATION", "PLATFORM_AUDIT",
    "GOVERNANCE_ACTION",
)

EVENT_MODE = "EVENT"
AGGREGATE_MODE = "AGGREGATE"
INVESTIGATION_MODE = "INVESTIGATION"
TELEMETRY_MODES: tuple[str, ...] = (EVENT_MODE, AGGREGATE_MODE,
                                    INVESTIGATION_MODE)

# ---- privacy: these are never logged --------------------------------------

PROHIBITED_KEYS: frozenset[str] = frozenset({
    "private_key", "privatekey", "secret_key", "secretkey", "secret",
    "plaintext", "password", "passphrase", "auth_token", "access_token",
    "refresh_token", "session_cookie", "cookie", "decrypted_payload",
    "key_material", "hsm_key_material", "raw_key", "seed", "pin",
})


def canonical_event_bytes(event: Mapping[str, Any] | Any) -> bytes:
    """Deterministic serialization: stable field ordering and explicit null
    handling (nulls drop: absent and null are one state); timestamps are
    strings as recorded.

    This is the identity serialization for deduplication. Layered ledger
    integrity (partitioned chains, Merkle batches, signed checkpoints) is
    built on top of it in a later phase and does not change it.
    """
    def _strip(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(k): _strip(v) for k, v in sorted(value.items())
                    if v is not None}
        if isinstance(value, (list, tuple)):
            return [_strip(v) for v in value]
        return value
    return json.dumps(_strip(event), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def event_hash(event: Mapping[str, Any] | Any) -> str:
    """Canonical event hash: SHA256 of the canonical bytes."""
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _scan_for_secrets(value: Any, path: str = "") -> str | None:
    """Return the offending path if prohibited material appears anywhere."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_l = str(key).lower()
            if key_l in PROHIBITED_KEYS:
                return f"{path}.{key}".lstrip(".")
            found = _scan_for_secrets(item, f"{path}.{key}".lstrip("."))
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found = _scan_for_secrets(item, f"{path}[{index}]")
            if found:
                return found
    return None


def make_event(*, event_type: str, category: str, logging_kind: str,
               tenant_id: str, severity: str, asset_id: str,
               source: Mapping[str, Any],
               cryptographic_context: Mapping[str, Any],
               observed_at: str, evidence_ids: Sequence[str],
               business_system_id: str | None = None,
               first_seen: str | None = None, last_seen: str | None = None,
               integrity_status: str = "UNVERIFIED",
               signature_status: str = "UNKNOWN",
               related_asset_ids: Sequence[str] = (),
               relationship_evidence_ids: Sequence[str] = (),
               deduplication_key: str | None = None,
               event_id: str | None = None,
               investigation_status: str = "OBSERVED",
               telemetry_mode: str = EVENT_MODE,
               approval_ref: str | None = None,
               attributes: Mapping[str, Any] | None = None,
               normalization_version: str = "1.0",
               rule_version: str | None = None) -> dict[str, Any]:
    """Build one validated CryptoLog event.

    Refuses: unknown taxonomy, category/type mismatch, prohibited values,
    evidence-less events, relationships without relationship evidence,
    evidence levels that confuse capability with usage, negotiation events
    that were never negotiated, and investigation-mode telemetry without an
    approval reference.
    """
    etype = _clean(event_type).upper()
    ecat = _clean(category).upper()
    kind = _clean(logging_kind).upper()
    level = str((cryptographic_context or {}).get("evidence_level") or "").upper()

    if not etype:
        raise ValueError("event_type is mandatory: an anonymous event cannot "
                         "be classified or correlated")
    if ecat not in CATEGORIES:
        raise ValueError(f"unknown category {category!r}; expected one of "
                         f"{', '.join(CATEGORIES)}")
    known = EVENT_TYPES.get(etype)
    if known is not None and known != ecat:
        raise ValueError(f"{etype} is a {known} event; it may not file "
                         f"itself under {ecat}")
    if kind not in LOGGING_KINDS:
        raise ValueError(f"unknown logging kind {logging_kind!r}; expected "
                         f"one of {', '.join(LOGGING_KINDS)}: the three "
                         "logging kinds keep distinct trust semantics")
    if not _clean(tenant_id):
        raise ValueError("tenant_id is mandatory: every event is "
                         "tenant-scoped")
    if not _clean(asset_id):
        raise ValueError("asset_id is mandatory: an event without its asset "
                         "cannot join the Digital Twin timeline")
    if _clean(severity).upper() not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}; expected one of "
                         f"{', '.join(SEVERITIES)}")
    if _clean(investigation_status).upper() not in INVESTIGATION_STATES:
        raise ValueError(f"unknown investigation status "
                         f"{investigation_status!r}; expected one of "
                         f"{', '.join(INVESTIGATION_STATES)}")
    if level not in EVIDENCE_LEVELS:
        raise ValueError(
            f"unknown evidence level "
            f"{(cryptographic_context or {}).get('evidence_level')!r}; "
            f"expected one of {', '.join(EVIDENCE_LEVELS)}: usage categories "
            "are never merged")
    source_type = _clean((source or {}).get("source_type"))
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"unknown source_type {source_type!r}; expected one "
                         f"of {', '.join(SOURCE_TYPES)}")

    # privacy: metadata and approved evidence only, never secret contents
    for label, blob in (("cryptographic_context", cryptographic_context),
                        ("source", source),
                        ("attributes", attributes or {})):
        offender = _scan_for_secrets(blob, label)
        if offender:
            raise ValueError(
                f"prohibited value at {offender}: CryptoLog collects "
                "metadata, counters, event identifiers and approved "
                "evidence, never keys, tokens, plaintext or other secret "
                "contents")

    # evidence: an observed event without evidence is a rumor
    ids = [str(e) for e in evidence_ids if _clean(e)]
    if not ids:
        raise ValueError("evidence_ids are mandatory: an event without "
                         "evidence is a rumor, and CryptoLog records "
                         "evidence")
    rel_ids = [str(r) for r in related_asset_ids if _clean(r)]
    rel_evidence = [str(e) for e in relationship_evidence_ids if _clean(e)]
    if rel_ids and not rel_evidence:
        raise ValueError(
            "relationship_evidence_ids are mandatory when related_asset_ids "
            "are asserted: every graph relationship should have evidence "
            "behind it")

    # capability is never usage
    if etype == "PQC_CAPABILITY_DISCOVERED" and level in USAGE_LEVELS:
        raise ValueError(
            "PQC capability discovery is not proof of PQC usage: a "
            "discovered capability files under CAPABILITY or STATIC "
            f"evidence, never {level}")
    if etype in _NEGOTIATION_TYPES and level != NETWORK_NEGOTIATED:
        raise ValueError(
            f"{etype} is an observed negotiation: its evidence level is "
            f"{NETWORK_NEGOTIATED}, not {level or 'unset'}")
    if etype in _OPERATION_TYPES and level != RUNTIME:
        raise ValueError(
            f"{etype} is an observed operation: its evidence level is "
            f"{RUNTIME}, not {level or 'unset'}")

    mode = _clean(telemetry_mode).upper()
    if mode not in TELEMETRY_MODES:
        raise ValueError(f"unknown telemetry mode {telemetry_mode!r}; "
                         f"expected one of {', '.join(TELEMETRY_MODES)}")
    if mode == INVESTIGATION_MODE and not _clean(approval_ref):
        raise ValueError(
            "investigation-mode telemetry needs approval_ref: detailed "
            "metadata is temporary and explicitly approved, never default")
    if (mode == AGGREGATE_MODE
            and _clean((attributes or {}).get("coverage")).upper()
            == "COMPLETE"):
        raise ValueError(
            "an aggregate-mode event never claims complete event coverage: "
            "sampling or aggregation documents the loss of visibility")

    if _clean(integrity_status).upper() not in INTEGRITY_STATES:
        raise ValueError(f"unknown integrity_status {integrity_status!r}; "
                         f"expected one of {', '.join(INTEGRITY_STATES)}")
    if _clean(signature_status).upper() not in SIGNATURE_STATES:
        raise ValueError(f"unknown signature_status {signature_status!r}; "
                         f"expected one of {', '.join(SIGNATURE_STATES)}")
    if not _clean(observed_at):
        raise ValueError("observation.observed_at is mandatory")

    event: dict[str, Any] = {
        "event_id": _clean(event_id) or None,
        "event_schema": EVENT_SCHEMA,
        "tenant_id": _clean(tenant_id),
        "event_type": etype,
        "category": ecat,
        "logging_kind": kind,
        "severity": _clean(severity).upper(),
        "investigation_status": _clean(investigation_status).upper(),
        "asset_id": _clean(asset_id),
        "business_system_id": _clean(business_system_id) or None,
        "source": dict(source),
        "cryptographic_context": dict(cryptographic_context),
        "observation": {
            "observed_at": _clean(observed_at),
            "first_seen": _clean(first_seen) or _clean(observed_at),
            "last_seen": _clean(last_seen) or _clean(observed_at),
        },
        "evidence": {
            "evidence_ids": ids,
            "integrity_status": _clean(integrity_status).upper(),
            "signature_status": _clean(signature_status).upper(),
        },
        "relationships": {
            "related_asset_ids": rel_ids,
            "relationship_evidence_ids": rel_evidence,
        },
        "processing": {
            "normalization_version": str(normalization_version),
            "rule_version": str(rule_version) if rule_version else None,
            "deduplication_key": _clean(deduplication_key) or None,
        },
        "telemetry_mode": mode,
        "approval_ref": _clean(approval_ref) or None,
        "attributes": dict(attributes or {}),
    }
    if not event["event_id"]:
        event["event_id"] = "clog_" + event_hash(event)[:16]
    return event


# ---- identity and deduplication (idempotent, never a silent overwrite) ----

INSERTED = "INSERTED"
DUPLICATE = "DUPLICATE"
CONFLICT = "CONFLICT"


def ingest(events: Iterable[Mapping[str, Any]],
           incoming: Mapping[str, Any]) -> dict[str, Any]:
    """Idempotent ingestion against the identity rules.

    Same deduplication key AND same canonical content is a DUPLICATE: the
    existing record stands. Same deduplication key with different content is
    a CONFLICT: a different event under an existing key is never a silent
    overwrite, it needs a correction or a new key. Without keys on either
    side, identity is the canonical hash.
    """
    new_key = _clean((incoming.get("processing") or {}).get("deduplication_key"))
    new_hash = event_hash(incoming)
    for existing in events:
        old_key = _clean((existing.get("processing") or {})
                         .get("deduplication_key"))
        if new_key and old_key and new_key == old_key:
            if event_hash(existing) == new_hash:
                return {"outcome": DUPLICATE, "event": dict(existing),
                        "note": "idempotent re-ingestion: the existing "
                                "record stands"}
            return {"outcome": CONFLICT, "event": dict(existing),
                    "note": "a different event under an existing "
                            "deduplication key is never a silent overwrite: "
                            "file a correction or use a new key"}
        if not new_key and not old_key and event_hash(existing) == new_hash:
            return {"outcome": DUPLICATE, "event": dict(existing),
                    "note": "idempotent re-ingestion: the existing record "
                            "stands"}
    return {"outcome": INSERTED, "event": dict(incoming), "note": "new event"}


# ---- corrections (never overwrite the original) ---------------------------

CORRECTION_SCHEMA = "cryptoscan.cryptolog-correction/1"


def supersede(*, original: Mapping[str, Any], corrected: Mapping[str, Any],
              reason: str, actor: str,
              evidence_ids: Sequence[str]) -> dict[str, Any]:
    """A correction supersedes an original event; it never overwrites it.

    Never overwrite an original event when a correction arrives: preserve
    the original and create a correction or superseding event with its own
    provenance. The record carries the original's canonical hash so the
    preserved original can be proven byte-identical.
    """
    why = _clean(reason)
    who = _clean(actor)
    if not why:
        raise ValueError("a correction without a reason is an overwrite "
                         "with extra steps: reason is mandatory")
    if not who:
        raise ValueError("a correction names its actor: provenance is "
                         "mandatory")
    ids = [str(e) for e in evidence_ids if _clean(e)]
    if not ids:
        raise ValueError("a correction carries its own evidence: "
                         "provenance is mandatory")
    return {
        "schema": CORRECTION_SCHEMA,
        "corrects_event_id": str(original.get("event_id") or ""),
        "original_hash": event_hash(original),
        "original_preserved": True,
        "corrected_event": dict(corrected),
        "reason": why,
        "actor": who,
        "evidence_ids": ids,
    }


def original_intact(original: Mapping[str, Any],
                    correction: Mapping[str, Any]) -> bool:
    """True when the preserved original still matches the correction's
    recorded hash: the original was never rewritten."""
    return event_hash(original) == str(correction.get("original_hash") or "")


def validate_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and validate an event-shaped dict through the contract.

    The ingestion gateway's schema validation: an incoming record is
    rebuilt through ``make_event``, so every construction-time refusal
    (taxonomy, privacy, evidence, capability/usage, telemetry) applies to
    stored records exactly as to locally built ones. The returned dict is
    the canonical form: its ``event_hash`` identity is what the ledger and
    deduplication record.
    """
    offender = _scan_for_secrets(dict(event), "event")
    if offender:
        raise ValueError(
            f"prohibited value at {offender}: CryptoLog collects metadata, "
            "counters, event identifiers and approved evidence, never keys, "
            "tokens, plaintext or other secret contents")
    obs = event.get("observation") or {}
    ev = event.get("evidence") or {}
    rel = event.get("relationships") or {}
    proc = event.get("processing") or {}
    return make_event(
        event_type=event.get("event_type"),
        category=event.get("category"),
        logging_kind=event.get("logging_kind"),
        tenant_id=event.get("tenant_id"),
        severity=event.get("severity"),
        asset_id=event.get("asset_id"),
        business_system_id=event.get("business_system_id"),
        source=event.get("source") or {},
        cryptographic_context=event.get("cryptographic_context") or {},
        observed_at=obs.get("observed_at"),
        first_seen=obs.get("first_seen"),
        last_seen=obs.get("last_seen"),
        evidence_ids=ev.get("evidence_ids") or [],
        integrity_status=ev.get("integrity_status") or "UNVERIFIED",
        signature_status=ev.get("signature_status") or "UNKNOWN",
        related_asset_ids=rel.get("related_asset_ids") or [],
        relationship_evidence_ids=rel.get("relationship_evidence_ids") or [],
        deduplication_key=proc.get("deduplication_key"),
        event_id=event.get("event_id"),
        investigation_status=event.get("investigation_status") or "OBSERVED",
        telemetry_mode=event.get("telemetry_mode") or "EVENT",
        approval_ref=event.get("approval_ref"),
        attributes=event.get("attributes") or {},
        normalization_version=proc.get("normalization_version") or "1.0",
        rule_version=proc.get("rule_version"),
    )
