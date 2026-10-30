"""Collector depth routes — runtime, network, Windows, and the six BOMs.

Four questions, each answered by a module that compiles its answer from the code
that exists in this build rather than from a hand-written claim:

* ``/discovery/runtime-depth``      what can we observe at runtime, and what has it observed?
* ``/discovery/network-protocols``  which protocols can we read, per protocol?
* ``/discovery/windows-collector``  how far does the Windows candidate actually reach?
* ``/discovery/bom-maturity``       how deep is each of the six BOMs on this estate?

The measured half of each route is optional by design: a fresh install has no
estate graph and no runtime observations, and the routes say ``NOT_OBSERVED``
with a reason instead of answering zero.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api import (
    bom_maturity,
    network_protocols,
    runtime_depth,
    windows_collector,
)

try:  # the reader lives in the network scanner service
    from network_scanner.probing import port_protocols
except ImportError:  # pragma: no cover - service not on the path
    port_protocols = None  # type: ignore[assignment]
from api.dependencies import get_current_user, get_db_session

router = APIRouter(prefix="/estate/evidence", tags=["estate-evidence"])


def _graph(db: Session) -> tuple[Any, dict[str, Any] | None, str | None]:
    """The latest stored graph, or the reason there is none.

    A missing discovery run is *not* an error for these routes: the capability
    matrix is still true (it is about the build), so it is returned with the
    measured half marked unobserved.
    """
    from api.routers.estate_graph import _graph_from_run, _latest_run  # local import: router helper

    try:
        run = _latest_run(db)
    except Exception as exc:  # noqa: BLE001 — HTTPException(404) when no run exists
        detail = getattr(exc, "detail", None)
        if isinstance(detail, dict):
            return None, None, str(detail.get("reason") or detail.get("error") or exc)
        return None, None, str(exc)
    return run, _graph_from_run(run), None


@router.get("/discovery/runtime-depth")
def runtime_depth_matrix(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """What this build can observe at runtime, per family, and what it has seen.

    ``OpenSSL installed ≠ AES-256 executed``: the matrix separates invocation
    evidence from library, configuration and wire evidence, and lists the
    families the engine *could* accept observations from but no collector here
    produces.
    """
    return runtime_depth.registry(observed=runtime_depth.observe(db))


@router.get("/discovery/network-protocols")
def network_protocol_matrix(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Per-protocol readers, and what the stored estate actually backs.

    The measured half counts assets of each protocol's target classes and how
    many of them carry network evidence. An asset class with no assets is
    ``NOT_OBSERVED`` — the estate has not shown us one, which is not the same as
    a protocol being unencrypted.
    """
    run, graph, reason = _graph(db)
    measured: dict[str, Any]
    if graph is None:
        measured = {"state": "NOT_OBSERVED", "reason": reason, "run_id": None}
    else:
        evidence_by_target: dict[str, set[str]] = {}
        network_types: dict[str, str] = {
            "RUNTIME_OBSERVED": "RUNTIME",
            "NETWORK_ACTIVE_OBSERVED": "NETWORK",
            "NETWORK_PASSIVE_OBSERVED": "NETWORK",
            "AUDIT_OBSERVED": "AUDIT",
        }
        for record in graph.evidence():
            kind = network_types.get(str(record.get("evidence_type")))
            if kind:
                evidence_by_target.setdefault(str(record.get("target")), set()).add(kind)
        assets = {str(asset["asset_id"]): asset for asset in graph.assets()}
        per_class: dict[str, dict[str, int]] = {}
        for asset_id, asset in assets.items():
            asset_type = str(asset.get("type"))
            bucket = per_class.setdefault(asset_type, {"assets": 0, "with_network_evidence": 0})
            bucket["assets"] += 1
            if "NETWORK" in evidence_by_target.get(asset_id, set()):
                bucket["with_network_evidence"] += 1
        measured = {
            "state": "OBSERVED",
            "run_id": run.id,
            "projection_id": graph.fingerprint(),
            "by_asset_class": per_class,
            "note": (
                "counts are assets of each class in this snapshot and how many are backed by a "
                "network observation. They are not a per-protocol success rate"
            ),
        }
    return {
        **network_protocols.registry(measured=measured),
        "port_table": port_protocols.coverage() if port_protocols else None,
    }


@router.get("/discovery/windows-collector")
def windows_matrix(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """How far the Windows candidate reaches — and the answer to "is it complete?".

    The measured half counts Windows hosts in the stored snapshot and how many
    of them carry any evidence at all. A host with no evidence is NOT_OBSERVED:
    the agent has not run there.
    """
    run, graph, reason = _graph(db)
    measured: dict[str, Any]
    if graph is None:
        measured = {"state": "NOT_OBSERVED", "reason": reason, "run_id": None}
    else:
        windows_hosts = 0
        with_evidence = 0
        for asset in graph.assets():
            if str(asset.get("type")) != "HOST":
                continue
            identity = asset.get("identity") or {}
            attributes = asset.get("attributes") or {}
            haystack = " ".join(
                str(value).lower()
                for value in (
                    identity.get("os"),
                    identity.get("platform"),
                    attributes.get("os"),
                    attributes.get("platform"),
                    asset.get("name"),
                )
                if value
            )
            if "windows" not in haystack:
                continue
            windows_hosts += 1
            if asset.get("evidence_refs"):
                with_evidence += 1
        measured = {
            "state": "OBSERVED",
            "run_id": run.id,
            "projection_id": graph.fingerprint(),
            "windows_hosts": windows_hosts,
            "windows_hosts_with_evidence": with_evidence,
            "reason": (
                None
                if windows_hosts
                else "no Windows host appears in this snapshot's identity attributes"
            ),
            "note": (
                "a Windows host is recognised from its identity/attributes. A host whose platform "
                "was never asserted is not counted here rather than being guessed"
            ),
        }
    return windows_collector.registry(measured=measured)


@router.get("/discovery/bom-maturity")
def bom_maturity_matrix(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """How deep each of the six BOMs is on this estate — measured, not scored."""
    run, graph, reason = _graph(db)
    if graph is None:
        return {
            "schema": bom_maturity.SCHEMA,
            "state": "NOT_OBSERVED",
            "reason": reason,
            "boms": [],
            "claim": (
                "the six BOMs are projections of one stored evidence graph; with no snapshot there "
                "is nothing to project and nothing is claimed about any BOM's depth"
            ),
        }
    return {"run_id": run.id, **bom_maturity.measure(graph)}


__all__ = ["router"]
