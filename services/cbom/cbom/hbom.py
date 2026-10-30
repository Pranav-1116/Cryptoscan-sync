"""Independent, unified HBOM generator over the PERSISTED hardware estate.

§4.4, round 71. Before this module the platform had three hardware
surfaces, none of which is an independent, unified HBOM document:

* the TechBOM ``hbom`` layer — a projection inside the technology BOM
  materializer (``cbom/technology_bom.py``), not a standalone document;
* the live-engine ``GET /hardware/hbom`` — built from the controller's
  EPHEMERAL in-memory state (empty after a process restart until events
  are re-ingested), not from the database;
* the live-scan BOM — only covers hardware a scan-run happened to see.

This generator is the fourth thing the vision asks for: ONE document
over every persisted ``hardware_assets`` row (the 24/7 engine's DB
truth — the ``hardware_assets`` table IS the current truth by design),
regardless of which agent or collector observed the device. It is

* **unified** — one document for the whole estate, not per-scan;
* **independent** — its own format, its own pinning surface
  (``hbom_snapshots``), not a layer of another BOM;
* **deterministic** — no wall clock: the document is fully derived from
  the rows plus an explicit ``as_of`` anchor (the latest ``last_seen``
  across the estate when the caller does not pin one), so identical
  estates hash identically and content addressing is meaningful;
* **honest** — per-component evidence references (agent, first/last
  seen, last verified, fingerprint, the recorded evidence IDs), an
  explicit source list, and notes that say what is NOT there. No
  hardware→system dependency edges are invented: no collector records
  that linkage today, so ``dependencies`` is empty BY DECLARATION, not
  by oversight. An empty estate renders an empty document with a note,
  never a fabricated one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from shared_models.canonical import canonical_json

HBOM_FORMAT = "Cryptoscan-HBOM"
HBOM_SPEC_VERSION = "1.0"
HBOM_GENERATOR = "cryptoscan-hbom-generator/1.0"

#: The one admitted source of estate rows today (the DB is the truth).
SOURCE_LIVE_HARDWARE_INVENTORY = "live hardware inventory (hardware_assets)"

#: Hardware a stored estate observation (``/ingestion/observations``) carries. It is a
#: second admitted source because an imported or discovered estate records real devices
#: that never pass through the live agent — dropping them made the HBOM read empty on an
#: estate whose HARDWARE and HSM assets were already established with evidence.
SOURCE_ESTATE_OBSERVATION = "estate observation (HARDWARE/HSM assets)"

_DEPENDENCY_NOTE = (
    "No collector records hardware-to-system dependency edges yet; "
    "dependencies are empty by declaration, not by omission."
)

_NO_DEPENDENCIES: list[dict[str, Any]] = []


def _iso(value: Any) -> Optional[str]:
    """Normalize a datetime-ish column value to a UTC ISO string or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _as_dt(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def anchor_as_of(rows: Iterable[dict[str, Any]]) -> Optional[str]:
    """The deterministic document anchor: latest observation in the estate.

    The latest ``last_seen`` (falling back to ``first_seen``) across all
    rows. With no rows there is nothing to anchor to and the document
    says so (``as_of: null``) instead of stamping a wall clock that would
    make identical empty estates hash differently.
    """
    latest: Optional[datetime] = None
    for row in rows:
        for key in ("last_seen", "first_seen"):
            dt = _as_dt(row.get(key))
            if dt is not None and (latest is None or dt > latest):
                latest = dt
    return _iso(latest)


def _component(state: dict[str, Any]) -> dict[str, Any]:
    """One HBOM component from a persisted hardware state dict.

    Explicit field allowlist: the document is versioned and content
    addressed, so accidental row fields (tenant bookkeeping, prior-state
    blobs) must not silently shift the hash — only identity, posture and
    evidence facts belong in the BOM.
    """
    asset_id = str(state.get("asset_id") or "")
    manufacturer = str(state.get("manufacturer") or "")
    model = str(state.get("model") or "")
    name = f"{manufacturer} {model}".strip() or asset_id

    evidence_ids = [
        str(e) for e in (state.get("evidence_history") or []) if e is not None
    ]

    security_modules: dict[str, Any] = {}
    if state.get("hsm") is not None:
        security_modules["hsm"] = state.get("hsm")
    if state.get("tpm") is not None:
        security_modules["tpm"] = state.get("tpm")

    component: dict[str, Any] = {
        "bom-ref": f"hw:{asset_id}",
        "asset_id": asset_id,
        "name": name,
        "manufacturer": manufacturer,
        "model": model,
        "device_type": str(state.get("device_type") or "other"),
        "identity": {
            "serial_reference": state.get("serial_reference"),
            "hardware_revision": state.get("hardware_revision"),
            "current_fingerprint": state.get("current_fingerprint"),
            "previous_fingerprint": state.get("previous_fingerprint"),
        },
        "firmware": {
            "details": state.get("firmware"),
            "last_checked": _iso(state.get("last_firmware_check")),
        },
        "security_modules": security_modules,
        "capabilities": state.get("capabilities"),
        "crypto_capabilities": state.get("crypto_capabilities"),
        "risk": {
            "score": state.get("risk_score"),
            "level": state.get("risk_level"),
            "last_change": state.get("last_change"),
        },
        "evidence": {
            "source": str(state.get("source") or SOURCE_LIVE_HARDWARE_INVENTORY),
            "agent_id": state.get("agent_id"),
            "first_seen": _iso(state.get("first_seen")),
            "last_seen": _iso(state.get("last_seen")),
            "last_verified": _iso(state.get("last_verified")),
            "last_crypto_check": _iso(state.get("last_crypto_check")),
            "evidence_ids": evidence_ids,
        },
    }
    return component


def generate_hbom(
    rows: Iterable[dict[str, Any]],
    *,
    environment: str,
    as_of: Optional[str] = None,
    sources: Iterable[str] = (),
    notes: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the unified estate HBOM document.

    Args:
        rows: persisted hardware state dicts (``HardwareAsset.state_dict()``
            shape); any iterable, any order — the document is normalized.
        environment: the environment label the estate belongs to.
        as_of: explicit anchor. When omitted, the latest observation in
            the rows is used (see :func:`anchor_as_of`). Never a wall
            clock: identical estates must hash identically.
        sources: additional admitted sources beyond the live hardware
            inventory, recorded in ``metadata.sources`` so a reader always
            knows where a component came from.
        notes: additional declarative notes, appended verbatim.

    Returns:
        The complete document including its ``content_hash``.
    """
    states = sorted(
        (dict(row) for row in rows), key=lambda r: str(r.get("asset_id") or "")
    )
    components = [_component(state) for state in states]

    hsm_ids = sorted(
        c["asset_id"] for c in components if c["security_modules"].get("hsm")
    )
    tpm_ids = sorted(
        c["asset_id"] for c in components if c["security_modules"].get("tpm")
    )
    device_types: dict[str, int] = {}
    for component in components:
        device_types[component["device_type"]] = (
            device_types.get(component["device_type"], 0) + 1
        )

    extra_sources = [str(item) for item in sources if str(item or "").strip()]
    document_notes = [_DEPENDENCY_NOTE]
    if not components:
        document_notes.append(
            "No hardware assets are persisted for this environment yet — "
            "the HBOM is empty, not fabricated."
        )
    document_notes.extend(str(item) for item in notes if str(item or "").strip())
    anchor = as_of if as_of is not None else anchor_as_of(states)

    document: dict[str, Any] = {
        "bomFormat": HBOM_FORMAT,
        "specVersion": HBOM_SPEC_VERSION,
        "metadata": {
            "generator": HBOM_GENERATOR,
            "environment": str(environment or ""),
            "as_of": anchor,
            "component_count": len(components),
            "hsm_count": len(hsm_ids),
            "tpm_count": len(tpm_ids),
            "device_types": dict(sorted(device_types.items())),
            "sources": list(dict.fromkeys([SOURCE_LIVE_HARDWARE_INVENTORY, *extra_sources])),
            "notes": document_notes,
        },
        "components": components,
        "hsm_fleet": {"count": len(hsm_ids), "asset_ids": hsm_ids},
        "tpm_fleet": {"count": len(tpm_ids), "asset_ids": tpm_ids},
        "dependencies": _NO_DEPENDENCIES,
    }
    document["content_hash"] = compute_hbom_hash(document)
    return document


def to_json(document: dict[str, Any]) -> str:
    """The ONE canonical serialization used for content addressing."""
    return canonical_json(document)


def compute_hbom_hash(document: dict[str, Any]) -> str:
    """SHA-256 over the canonical serialization, ``content_hash`` excluded.

    The hash is computed over the document exactly as served minus the
    ``content_hash`` member itself, so the pinned value can be
    re-verified on every read of the stored payload.
    """
    import hashlib

    body = {k: v for k, v in document.items() if k != "content_hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def hbom_hash_matches(document: dict[str, Any], content_hash: str) -> bool:
    """Integrity self-check for a served/stored document."""
    return bool(content_hash) and compute_hbom_hash(document) == content_hash


def to_cyclonedx(document: dict[str, Any], *, name: str = "cryptoscan-hbom") -> dict[str, Any]:
    """Deterministic CycloneDX 1.5 rendering of an estate HBOM.

    For interop consumers. The timestamp is the document's OWN ``as_of``
    anchor (never a wall clock), and the estate content hash is carried
    as a property so the export stays traceable to its pinned source.
    """
    metadata = document.get("metadata") or {}
    components: list[dict[str, Any]] = []
    for component in document.get("components") or []:
        evidence = component.get("evidence") or {}
        identity = component.get("identity") or {}
        security_modules = component.get("security_modules") or {}
        props = [
            {"name": "asset_id", "value": str(component.get("asset_id") or "")},
            {"name": "device_type", "value": str(component.get("device_type") or "")},
            {"name": "serial", "value": str(identity.get("serial_reference") or "")},
            {"name": "hardware_revision", "value": str(identity.get("hardware_revision") or "")},
            {"name": "evidence_source", "value": str(evidence.get("source") or "")},
            {"name": "agent", "value": str(evidence.get("agent_id") or "")},
        ]
        if security_modules.get("hsm") is not None:
            props.append({"name": "hsm", "value": "true"})
        if security_modules.get("tpm") is not None:
            props.append({"name": "tpm", "value": "true"})
        firmware_details = (component.get("firmware") or {}).get("details")
        firmware_version = ""
        if isinstance(firmware_details, dict):
            firmware_version = str(
                firmware_details.get("version") or firmware_details.get("id") or ""
            )
        components.append({
            "type": "device",
            "name": str(component.get("name") or ""),
            "version": firmware_version or "unknown",
            "bom-ref": str(component.get("bom-ref") or ""),
            "properties": props,
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "device", "name": name},
            "timestamp": metadata.get("as_of"),
            "properties": [
                {"name": "environment", "value": str(metadata.get("environment") or "")},
                {"name": "cryptoscan:hbom-content-hash",
                 "value": str(document.get("content_hash") or "")},
                {"name": "cryptoscan:hbom-generator",
                 "value": str(metadata.get("generator") or "")},
            ],
        },
        "components": components,
    }
