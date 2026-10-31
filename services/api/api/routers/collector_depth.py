"""Collector depth routes — runtime, network, Windows, and the six BOMs.

Four questions, each answered by a module that compiles its answer from the code
that exists in this build rather than from a hand-written claim:

* ``/discovery/runtime-depth``      what can we observe at runtime, and what has it observed?
* ``/discovery/network-protocols``  which protocols can we read, per protocol?
* ``/discovery/windows-collector``  how far does the Windows candidate actually reach?
* ``/discovery/bom-maturity``       how deep is each of the six BOMs on this estate?
* ``/discovery/collector-families`` which of the twenty collector families exist, and which
                                    can collect unattended

The measured half of each route is optional by design: a fresh install has no
estate graph and no runtime observations, and the routes say ``NOT_OBSERVED``
with a reason instead of answering zero.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared_models import collector_families, maturity_register

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
from api.dependencies import get_current_user, get_db_session, require_roles

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


@router.get("/discovery/maturity")
def maturity(
    user: str = Depends(get_current_user),
):
    """Where each capability reaches: what exists, what is missing, what proves it.

    Static like the four matrices around it, and for the same reason: this is a
    statement about the build, not about an estate. The measured half lives on
    the per-surface routes (/discovery/runtime-depth and friends); this route
    says which of those surfaces is allowed to be read as complete, and which is
    not.
    """
    return maturity_register.register()


@router.get("/discovery/collector-families")
def collector_family_matrix(
    user: str = Depends(get_current_user),
):
    """Every collector family the vision names, and what this build actually reaches.

    The status of each row is *computed by importing its entrypoints*, so a family
    cannot be reported shipped without code behind it, and a family whose code only
    parses data an operator supplies is reported as exactly that — real code, no
    unattended collection. ``production`` requires all three: the entrypoints import,
    the collector reads the system itself (not a file), and it reads the customer's
    estate rather than this platform's own.

    This is a statement about the build, not about an estate, so it needs no
    discovery run. It is not a coverage or maturity score.
    """
    return collector_families.register()


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
    _run, graph, _reason = _graph(db)
    return runtime_depth.registry(observed=runtime_depth.observe(db, graph))


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


# --------------------------------------------------------------------------- #
# collect: run a collector here and project the six BOMs from the result
# --------------------------------------------------------------------------- #
class CollectRequest(BaseModel):
    """What to collect, from where, and into which estate."""

    collectors: list[str] = Field(
        default_factory=lambda: ["runtime"],
        description="any of runtime | network | windows",
        max_length=3,
    )
    estate: str | None = Field(
        default=None,
        max_length=160,
        description="estate to write into; default: the newest stored observation's estate",
    )
    merge: bool = Field(
        default=True,
        description="merge into the newest stored observation (true) or store this collection alone",
    )
    scope: str | None = Field(default=None, max_length=160)
    proc_base: str = Field(default="/proc", max_length=200)
    trace_argv: list[str] | None = Field(
        default=None,
        max_length=64,
        description="optional command to run under the LD_PRELOAD shim (INVOCATION evidence)",
    )
    trace_timeout: float = Field(default=120.0, ge=1.0, le=900.0)
    targets: list[str] = Field(default_factory=list, max_length=200)
    timeout: float = Field(default=5.0, ge=0.5, le=60.0)
    artifacts: list[str] = Field(default_factory=list, max_length=500)
    windows_host: str | None = Field(default=None, max_length=200)


def _run_collectors(body: CollectRequest) -> list[dict[str, Any]]:
    from api import host_collect

    unknown = [name for name in body.collectors if name not in {"runtime", "network", "windows"}]
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={"error": "unknown_collector", "reason": f"unsupported: {', '.join(unknown)}",
                    "expected": ["runtime", "network", "windows"]},
        )
    if "network" in body.collectors and not body.targets:
        raise HTTPException(
            status_code=422,
            detail={"error": "no_targets",
                    "reason": "the network collector needs the targets to handshake; an empty "
                              "target list would look like an estate with no endpoints"},
        )
    if "windows" in body.collectors and not body.artifacts:
        raise HTTPException(
            status_code=422,
            detail={"error": "no_artifacts",
                    "reason": "the Windows collector reads exported artefacts; naming none would "
                              "look like a host with no policy"},
        )
    packages: list[dict[str, Any]] = []
    for name in body.collectors:
        if name == "runtime":
            packages.append(host_collect.collect_runtime(
                proc_base=body.proc_base,
                trace_argv=body.trace_argv,
                trace_timeout=body.trace_timeout,
            ))
        elif name == "network":
            packages.append(host_collect.collect_network(body.targets, timeout=body.timeout))
        else:
            packages.append(host_collect.collect_windows(body.artifacts, host=body.windows_host))
    return packages


@router.get("/collect/capabilities")
def collect_capabilities(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Which collectors can run from this process, and what each one establishes."""
    from api import host_collect
    from api.routers import estate_graph

    caps = host_collect.capabilities()
    try:
        run = estate_graph._latest_run(db)
        graph = estate_graph._graph_from_run(run)
    except Exception as exc:  # noqa: BLE001 — no snapshot is a state, not a failure
        detail = getattr(exc, "detail", None)
        reason = str(detail.get("reason") if isinstance(detail, dict) else detail or exc)
        caps["target_estate"] = {"state": "NO_OBSERVATION", "reason": reason, "estate": None}
        return caps
    caps["target_estate"] = {
        "state": "OBSERVED",
        "estate": graph.estate,
        "scope": graph.scope,
        "run_id": run.id,
        "projection_id": graph.fingerprint(),
        "assets": len(graph.assets()),
        "evidence": len(graph.evidence()),
    }
    return caps


@router.post("/collect")
def collect_now(
    body: CollectRequest,
    user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin")),
    db: Session = Depends(get_db_session),
):
    """Run the named collectors and re-project the six BOMs from the merged evidence.

    The collectors run **here**, in this API process, against this host (and the
    targets/artefacts named). Nothing is simulated: a target that refuses the
    handshake records that, and no evidence is invented for it.
    """
    from api import bom_maturity, host_collect
    from api.routers import estate_graph
    from shared_models.estate_graph import build_graph

    packages = _run_collectors(body)

    payload, estate = host_collect.latest_payload(db)
    if body.merge and payload is not None:
        base = payload
    else:
        base = None
    estate_name = body.estate or estate or "local-collect"
    merged = host_collect.merge_payload(base, packages, estate=estate_name)
    if body.scope:
        merged["scope"] = body.scope

    # before: the depth each BOM had on the stored snapshot (if any)
    before: dict[str, Any] | None = None
    if base is not None:
        try:
            before = bom_maturity.measure(build_graph({
                "estate": base.get("estate"),
                "scope": base.get("scope"),
                "assets": base.get("assets") or [],
                "evidence": base.get("evidence") or [],
                "relationships": base.get("relationships") or [],
                "collectors": base.get("collectors") or [],
                "coverage": base.get("coverage") or [],
            }))
        except ValueError:
            before = None

    request = estate_graph.EstateDiscoverRequest(
        estate=estate_name,
        scope=merged.get("scope"),
        inventory_id="host-collect",
        assets=merged.get("assets") or [],
        evidence=merged.get("evidence") or [],
        relationships=merged.get("relationships") or [],
        collectors=merged.get("collectors") or [],
        coverage=merged.get("coverage") or [],
        include_boms=True,
        persist=True,
    )
    collector_reports = [{"id": package["id"], **package["summary"]} for package in packages]
    try:
        result = estate_graph.run_discovery(db, user, request)
    except HTTPException as exc:
        # The engine refused the payload after the collectors had already run.
        # Carry their reports out with the refusal: without them the caller sees a
        # rule violation but not which targets failed or why.
        if exc.status_code == 422 and isinstance(exc.detail, dict):
            exc.detail = {**exc.detail, "collectors": collector_reports}
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "collection_rejected", "reason": str(exc),
                    "stored": False,
                    # The collectors already ran. Returning only the engine's
                    # complaint hides which targets failed and why, so carry their
                    # own reports out with the refusal.
                    "collectors": collector_reports,
                    "note": "a collector produced an edge the estate engine refuses; nothing was "
                            "written and the offending fact is named above"},
        ) from exc

    after_graph = build_graph({
        "estate": estate_name,
        "scope": merged.get("scope"),
        "assets": merged.get("assets") or [],
        "evidence": merged.get("evidence") or [],
        "relationships": merged.get("relationships") or [],
        "collectors": merged.get("collectors") or [],
        "coverage": merged.get("coverage") or [],
    })
    after = bom_maturity.measure(after_graph)

    def _depths(document: dict[str, Any] | None) -> dict[str, str]:
        if not document:
            return {}
        return {row["kind"]: row["depth"] for row in document.get("boms") or []}

    before_depths = _depths(before)
    after_depths = _depths(after)
    return {
        "schema": "cryptoscan.collect-result/1",
        "estate": estate_name,
        "merged_into_stored_observation": base is not None,
        "run_id": result.get("run_id"),
        "projection_id": after.get("projection_id"),
        "collectors": [
            {"id": package["id"], **package["summary"]} for package in packages
        ],
        "counts": {
            "assets": len(merged.get("assets") or []),
            "evidence": len(merged.get("evidence") or []),
            "relationships": len(merged.get("relationships") or []),
            "added_assets": sum(len(package.get("assets") or []) for package in packages),
            "added_evidence": sum(len(package.get("evidence") or []) for package in packages),
        },
        "detection": result.get("detection"),
        "bom_maturity": {
            "before": before_depths or None,
            "after": after_depths,
            "changed": {kind: {"before": before_depths.get(kind), "after": depth}
                        for kind, depth in after_depths.items()
                        if before_depths.get(kind) != depth},
            "note": (
                "depth is the strongest evidence class behind each BOM's components. A collector "
                "that established configuration cannot lift a BOM to OBSERVED, and this does not "
                "pretend otherwise"
            ),
        },
        "coverage": result.get("coverage"),
        "note": (
            "the collectors ran in this API process against this host, the named targets and the "
            "named artefacts. Everything they produced is in the stored observation named above"
        ),
    }


__all__ = ["router"]
