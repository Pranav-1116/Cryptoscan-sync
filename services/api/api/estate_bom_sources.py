"""BOM rows contributed by the newest stored estate observation.

An estate observation (``POST /api/v1/ingestion/observations``) carries hardware,
HSM and vendor assets with the evidence that established them. Those rows belong in
the BOMs — a bank estate whose devices were imported is not an estate without
devices — but they are *not* live-agent rows, so they are translated here, once, and
labelled with their own source instead of being mixed into the agent inventory.

Two surfaces read this module:

* ``GET /hbom`` — the independent hardware BOM (``estate observation (HARDWARE/HSM
  assets)`` is an admitted source in the document's ``metadata.sources``);
* the TechBOM inventory (``GET /technology-bom``) — its ``hbom`` and ``vendor``
  layers, so an imported estate does not read as "0 hardware, 0 vendors".

Everything is read-only and deduplicated by ``asset_id``/name at the call site. No
observation means no rows: an empty estate stays empty rather than being filled in.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

#: asset types a stored observation carries that an HBOM reader calls hardware
HARDWARE_ASSET_TYPES: tuple[str, ...] = ("HARDWARE", "FIRMWARE", "HOST", "HSM")

#: the source label recorded on every row this module produces
SOURCE_ESTATE_OBSERVATION = "estate observation (HARDWARE/HSM assets)"


def latest_graph(db: Session) -> Any | None:
    """The rebuildable twin of the newest observation, or ``None``.

    A corrupt or absent run yields ``None`` (and a warning) rather than an exception:
    an unreadable observation must not blank out the DB half of a BOM.
    """
    from api.estate_twin_graph import RUN_KIND
    from api.routers.estate_graph import _graph_from_run
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant

    runs = ScanRunRepository(db).list_runs(limit=1, target_kind=RUN_KIND, owner=current_tenant())
    if not runs:
        return None
    try:
        return _graph_from_run(runs[0])
    except Exception as exc:  # noqa: BLE001 — stated in the log, never silently swallowed
        logger.warning("estate observation unreadable for BOM projection: %s", exc)
        return None


def hardware_rows(db: Session) -> list[dict[str, Any]]:
    """HARDWARE / HSM assets of the newest observation, in one row shape.

    The shape satisfies both readers at once: the HBOM generator's
    ``state_dict()`` contract (``hsm``, ``evidence_history``, ``source``) and the
    TechBOM ``hardware_component`` builder (``asset_id``, ``device_type`` …).
    """
    graph = latest_graph(db)
    if graph is None:
        return []
    rows: list[dict[str, Any]] = []
    for asset in graph.assets():
        kind = asset.get("type")
        if kind not in HARDWARE_ASSET_TYPES:
            continue
        identity = asset.get("identity") or {}
        attributes = asset.get("attributes") or {}
        hsm = None
        if kind == "HSM":
            hsm = {
                "model": attributes.get("model"),
                "vendor": identity.get("vendor"),
                "interface": attributes.get("interface"),
                "lifecycle": attributes.get("lifecycle"),
                "declared_only": attributes.get("actual_execution") is False,
            }
        rows.append({
            "asset_id": str(asset.get("asset_id") or ""),
            "manufacturer": identity.get("vendor") or attributes.get("manufacturer"),
            "model": attributes.get("model") or identity.get("model"),
            "device_type": (
                attributes.get("kind")
                or identity.get("partition")
                or ("hsm" if hsm else str(kind or "").lower())
            ),
            "serial_reference": identity.get("serial_number") or identity.get("serial"),
            "firmware": attributes.get("firmware"),
            "firmware_version": attributes.get("firmware"),
            "hsm": hsm,
            "tpm": attributes.get("tpm"),
            "risk_level": attributes.get("risk_level"),
            "crypto_capabilities": (
                attributes.get("crypto_capabilities") or attributes.get("capabilities")
            ),
            "security_module": "hsm" if hsm else ("tpm" if attributes.get("tpm") else ""),
            "asset": attributes.get("system_id") or asset.get("location"),
            "evidence_history": list(asset.get("evidence_refs") or asset.get("evidence_ids") or []),
            "source": SOURCE_ESTATE_OBSERVATION,
        })
    return rows


def vendor_rows(db: Session) -> list[dict[str, Any]]:
    """VENDOR assets of the newest observation, in TechBOM vendor-row shape.

    A vendor declaration is a statement about a product. It is carried here as a
    vendor-layer row (declared capability, lifecycle) — never as proof that the
    estate used that capability.
    """
    graph = latest_graph(db)
    if graph is None:
        return []
    rows: list[dict[str, Any]] = []
    for asset in graph.by_type("VENDOR"):
        identity = asset.get("identity") or {}
        attributes = asset.get("attributes") or {}
        rows.append({
            "name": asset.get("name") or identity.get("name") or "",
            "product": identity.get("product") or attributes.get("product") or "",
            "model": attributes.get("model") or attributes.get("product") or "",
            "version": attributes.get("version") or "",
            "lifecycle": attributes.get("support_lifecycle") or "",
            "risk_level": attributes.get("risk_level") or "",
            "crypto_capability": attributes.get("pqc_readiness") or "",
            "assets": [],
            "source": SOURCE_ESTATE_OBSERVATION,
        })
    return rows


def software_edges(db: Session) -> list[list[str]]:
    """Software edges of the newest observation's SBOM projection, as ``[from, to, why]``.

    An SBOM document's own dependency graph is an edge a BOM reader wants: which
    package declares which, and which application contains which library. The
    third element is the predicate, so a consumer can tell ``depends_on`` from
    ``contains`` instead of seeing one undifferentiated pile of pairs.
    """
    graph = latest_graph(db)
    if graph is None:
        return []
    try:
        projection = graph.project("SBOM")
    except Exception as exc:  # noqa: BLE001 — absent projection is reported, not invented
        logger.warning("SBOM projection unreadable for dependency edges: %s", exc)
        return []
    edges: list[list[str]] = []
    for edge in projection.get("relationships") or []:
        source, target = str(edge.get("from") or ""), str(edge.get("to") or "")
        if source and target:
            edges.append([source, target, str(edge.get("predicate") or "")])
    return edges
