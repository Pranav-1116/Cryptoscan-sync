"""Event-stream + Live CBOM API.

- /stream/stats        topic depths, consumer lag, chain position
- /stream/ingest       external collectors push observations (any scanner,
                       agent, telecom TAP export) -> raw-events, processed
                       synchronously with the full deterministic pipeline
- /stream/events       recent envelopes per topic (signature-verified)
- /attacks             latest attack-detections (the 13 deterministic rules)
- /attacks/summary     counts by rule/severity
- /cbom/live/{system}  current signed CBOM + freshness
- /cbom/versions/...   version history / single version
- /cbom/diff           deterministic diff between two versions
- /cbom/verify/{sys}   re-verify signatures + hash chain from genesis
- /cbom/stream/{sys}   SSE: emits on every new CBOM version
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from api.dependencies import get_current_user
from api.security.estate_history import history_context
from api.security.socket_history import SocketRefused
from api.routers.events import stream_grant, _checkpoint

router = APIRouter(tags=["stream"], dependencies=[Depends(history_context)])


def _tenant_key() -> str | None:
    """The caller's tenant scope (set by TenantScopeMiddleware for the whole
    request). None = platform estate / single-tenant install."""
    from db.tenancy import current_tenant

    return current_tenant()


def _bus():
    from eventstream.bus import get_bus_for_tenant

    return get_bus_for_tenant(_tenant_key())


def _store_dir() -> str:
    import os

    from eventstream.partitions import tenant_partition_dir

    base = os.environ.get("CBOM_STORE_DIR") or os.path.join(
        os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR", "data"), "live_cbom"
    )
    return str(tenant_partition_dir(base, _tenant_key()))


def _processor():
    from eventstream.stream.pipeline import StreamProcessor

    cache = _processor.by_tenant
    tenant = _tenant_key()
    proc = cache.get(tenant)
    if proc is None or proc.bus is not _bus():
        proc = StreamProcessor(_bus())
        cache[tenant] = proc
    return proc


def _cbom_service():
    from eventstream.livecbom import LiveCbomService

    cache = _cbom_service.by_tenant
    tenant = _tenant_key()
    svc = cache.get(tenant)
    if svc is None or str(svc.store_dir) != _store_dir():
        svc = LiveCbomService(_store_dir())
        cache[tenant] = svc
    return svc


def _projector():
    from eventstream.livecbom import CbomProjector

    cache = _projector.by_tenant
    tenant = _tenant_key()
    proj = cache.get(tenant)
    if proj is None or proj.bus is not _bus() or proj.service is not _cbom_service():
        proj = CbomProjector(_bus(), _cbom_service())
        cache[tenant] = proj
    return proj


def reset_stream_singletons() -> None:
    """Drop every cached processor/service/projector (all partitions).

    Test seam: the old module attributes (``_processor._inst`` ...) covered
    one global instance; the caches are per-tenant now, so tests reset them
    through this helper alongside ``eventstream.bus.reset_bus()``.
    """
    _processor.by_tenant = {}
    _cbom_service.by_tenant = {}
    _projector.by_tenant = {}


_processor.by_tenant = {}
_cbom_service.by_tenant = {}
_projector.by_tenant = {}


class IngestBody(BaseModel):
    payload: dict = Field(..., description="raw observation (scanner/agent/TAP export)")
    key: str = "default"
    source: str = "collector"


@router.get("/stream/stats")
def stream_stats(user: str = Depends(get_current_user)):
    _processor()
    return _bus().stats()


@router.post("/stream/ingest")
def ingest(body: IngestBody, user: str = Depends(get_current_user)):
    proc = _processor()
    before = _bus().latest("attack-detections", limit=1)
    from_seq = (before[-1]["seq"] + 1) if before else 1
    env = proc.ingest(body.payload, key=body.key, source=body.source)
    drained = proc.drain()
    projected = _projector().drain()
    out = {
        "envelope_seq": env["seq"],
        "processed": drained,
        "cbom_versions_written": projected,
        "chain_hash": proc.chain_hash,
    }
    # verdicts produced by THIS ingestion = everything published after `before`
    out["recent_detections"] = [e["payload"] for e in _bus().replay("attack-detections", from_seq=from_seq)]
    events = _bus().read("normalized-events", f"ingest-{env['seq']}", limit=1)
    if events:
        out["dedup_key"] = events[0]["payload"].get("extra", {}).get("dedup_key")
    return out


@router.get("/stream/events")
def stream_events(topic: str, limit: int = Query(20, ge=1, le=200), user: str = Depends(get_current_user)):
    from eventstream.topics import validate_topic

    try:
        validate_topic(topic)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"topic": topic, "events": _bus().latest(topic, limit=limit)}


@router.get("/attacks")
def recent_attacks(limit: int = Query(20, ge=1, le=200), user: str = Depends(get_current_user)):
    proc = _processor()
    proc.drain()
    rows = _bus().latest("attack-detections", limit=limit)
    return {"detections": [r["payload"] for r in rows]}


@router.get("/attacks/summary")
def attack_summary(user: str = Depends(get_current_user)):
    _processor().drain()
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in _bus().latest("attack-detections", limit=500):
        p = r["payload"]
        by_rule[p["rule"]] = by_rule.get(p["rule"], 0) + 1
        by_severity[p["severity"]] = by_severity.get(p["severity"], 0) + 1
    return {"by_rule": by_rule, "by_severity": by_severity}


@router.get("/cbom/live/{system_id}")
def cbom_live(system_id: str, user: str = Depends(get_current_user)):
    _processor().drain()
    _projector().drain()
    rec = _cbom_service().current(system_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="no CBOM versioned for this system yet")
    return rec


@router.get("/cbom/versions/{system_id}")
def cbom_versions(system_id: str, limit: int = Query(20, ge=1, le=200), user: str = Depends(get_current_user)):
    svc = _cbom_service()
    path = svc._path(system_id)
    if not path.exists():
        return {"versions": []}
    rows = []
    with path.open() as fh:
        for line in fh:
            if line.strip():
                rec = json.loads(line)
                rows.append(
                    {
                        k: rec[k]
                        for k in (
                            "system_id",
                            "version_no",
                            "generated_at",
                            "version_hash",
                            "prev_hash",
                            "asset_count",
                            "jws",
                        )
                    }
                )
    return {"versions": rows[-limit:]}


@router.get("/cbom/versions/{system_id}/{version_no}")
def cbom_version(system_id: str, version_no: int, user: str = Depends(get_current_user)):
    rec = _cbom_service().load_version(system_id, version_no)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown version")
    return rec


@router.get("/cbom/diff")
def cbom_diff(
    system: str, from_v: int = Query(..., ge=1), to_v: int = Query(..., ge=1), user: str = Depends(get_current_user)
):
    result = _cbom_service().diff(system, from_v, to_v)
    if result is None:
        raise HTTPException(status_code=404, detail="unknown version pair")
    return result


@router.get("/cbom/verify/{system_id}")
def cbom_verify(system_id: str, user: str = Depends(get_current_user)):
    return _cbom_service().verify_chain(system_id)


@router.get("/cbom/stream/{system_id}")
def cbom_stream(system_id: str, request: Request, grant=Depends(stream_grant)):
    """SSE: one event per new CBOM version (real-time channel)."""
    svc = _cbom_service()
    try:
        rec = svc.current(system_id)
        last_version = rec["version_no"] if rec else 0
    except Exception as exc:
        raise HTTPException(503, detail="CBOM stream backend unavailable") from exc

    async def gen():
        nonlocal last_version
        for _ in range(600):  # bounded connection lifetime (~10 min)
            try:
                await _checkpoint(request, grant)
                rec = await run_in_threadpool(svc.current, system_id)
                if rec and rec["version_no"] != last_version:
                    # Recheck after storage I/O, not just before it. A revoked
                    # reader must not get a version read during that revocation.
                    await _checkpoint(request, grant)
                    last_version = rec["version_no"]
                    yield f"data: {json.dumps({'system_id': system_id, 'version_no': last_version, 'version_hash': rec['version_hash']})}\n\n"
            except SocketRefused as exc:
                name = "events.unavailable" if exc.code == 1011 else "events.refused"
                yield f'event: {name}\ndata: {{"advice":"stream closed; check authority/backend"}}\n\n'
                return
            except Exception:
                yield 'event: events.unavailable\ndata: {"advice":"CBOM backend unavailable; reconnect later"}\n\n'
                return
            await asyncio.sleep(1)
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")
