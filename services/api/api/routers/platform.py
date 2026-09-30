"""§32 ZELNX control-plane API — one system across network, cloud, vendor,
hardware and cryptography, plus the platform-scope self-description.

Endpoints (all deterministic, no AI):

    GET  /api/v1/platform/scope      declared scope and honest boundaries
    POST /api/v1/platform/discover    run the §1 unified discovery pipeline
    GET  /api/v1/platform/bom         combined CycloneDX CBOM + HBOM (§21/§22)
    POST /api/v1/platform/drift       §20 baseline-vs-live drift evaluation
    POST /api/v1/platform/risk        §29 eight-factor risk (estate or asset)
    POST /api/v1/platform/blast       §30 blast-radius impact query
    POST /api/v1/platform/whatif      §31 what-if migration analysis
    POST /api/v1/platform/security    §33 security-control enforcement
    GET  /api/v1/platform/evidence    §23 evidence-chain verification
"""

from __future__ import annotations

from typing import Any, Optional
import json

from fastapi import APIRouter, Depends

from api.dependencies import get_current_user, get_tenant_context
from api.events.platform_events import emit_platform_event
from api.security.rbac import require_permission
from shared_models.platform_scope import scope_manifest
from universal_platform.engine import UniversalPlatform
from universal_platform.evidence import EvidenceChain

router = APIRouter(prefix="/platform", tags=["platform"])


@router.get("/scope")
def platform_scope(user: str = Depends(get_current_user)):
    """Return the declared platform scope and honest boundaries."""
    return scope_manifest()


class _Platform:
    """Tenant-scoped computation cache rebuilt from durable state.

    The engine itself is intentionally not the authority: discovery inputs and
    drift baselines are stored in Redis so another worker can reconstruct the
    same view after a restart. The process cache only avoids repeating that
    deterministic rebuild within a worker.
    """

    _engines: dict[str, UniversalPlatform] = {}
    _loaded_fingerprints: dict[str, str] = {}

    @staticmethod
    def _tenant_key() -> str:
        try:
            from db.tenancy import current_tenant

            return str(current_tenant() or "platform")
        except Exception:
            return "platform"

    @classmethod
    def engine(cls) -> UniversalPlatform:
        from api import platform_state

        key = cls._tenant_key()
        state = platform_state.load()
        fingerprint = json.dumps(state, sort_keys=True, default=str)
        engine = cls._engines.setdefault(key, UniversalPlatform())
        if cls._loaded_fingerprints.get(key) != fingerprint:
            domains = state.get("domains") or {}
            engine = UniversalPlatform()
            engine.evidence = EvidenceChain(records=state.get("evidence") or [])
            if domains:
                engine.discover(domains, record_evidence=False)
            engine.drift.set_baseline(state.get("baseline") or {})
            cls._engines[key] = engine
            cls._loaded_fingerprints[key] = fingerprint
        return engine

    @classmethod
    def update_state(cls, **changes: Any) -> dict[str, Any]:
        from api import platform_state

        state = platform_state.load()
        state.update(changes)
        platform_state.save(state)
        cls._loaded_fingerprints.pop(cls._tenant_key(), None)
        return state


@router.get("/capabilities")
def platform_capabilities(user: str = Depends(get_current_user)):
    """GA / beta / preview tier for every console surface.

    The console reads this to label pages; the same table is embedded in
    ``/platform/scope`` and rendered to docs/CAPABILITY-MATURITY.md. Unknown
    routes are ``preview`` by default — nothing is promoted by omission.
    """
    from shared_models.capability_maturity import capability_manifest

    return capability_manifest()


@router.post("/discover")
def platform_discover(body: dict[str, Any],
                      user: str = Depends(require_permission("crypto.manage")),
                      tenant=Depends(get_tenant_context)):
    domains = body.get("domains") or {}
    _Platform.update_state(domains=domains)
    engine = _Platform.engine()
    report = engine.discover(domains, int(body.get("interval_seconds") or 3600))
    _Platform.update_state(evidence=engine.evidence.records)
    emit_platform_event(
        "PLATFORM_DISCOVERY_COMPLETED",
        f"discovery over {len(report.get('sources_run') or [])} domains",
        {
            "asset_count": report.get("asset_count", 0),
            "relationship_count": report.get("relationship_count", 0),
            "domains": list((body.get("domains") or {}).keys()),
        },
    )
    return report


@router.get("/bom")
def platform_bom(user: str = Depends(require_permission("crypto.read")),
                 tenant=Depends(get_tenant_context)):
    bom = _Platform.engine().bom()
    emit_platform_event(
        "PLATFORM_CBOM_SERVED",
        "combined CBOM + HBOM served",
        {
            "components": len(bom.get("components") or []),
            "dependencies": len(bom.get("dependencies") or []),
            "spec_version": bom.get("specVersion"),
        },
    )
    return bom


@router.post("/drift")
def platform_drift(body: dict[str, Any],
                   user: str = Depends(require_permission("crypto.read")),
                   tenant=Depends(get_tenant_context)):
    baseline = body.get("baseline") or {}
    if baseline:
        _Platform.update_state(baseline=baseline)
    engine = _Platform.engine()
    result = engine.drift_check(body.get("live") or {})
    emit_platform_event(
        "PLATFORM_DRIFT_EVALUATED",
        f"drift {'detected' if result.get('drift_detected') else 'clean'} "
        f"({result.get('total_changes', 0)} changes)",
        {
            "drift_detected": bool(result.get("drift_detected")),
            "total_changes": result.get("total_changes", 0),
        },
    )
    return result


@router.post("/risk")
def platform_risk(body: dict[str, Any],
                  user: str = Depends(require_permission("crypto.read")),
                  tenant=Depends(get_tenant_context)):
    if body.get("domains"):
        _Platform.update_state(domains=body["domains"])
    engine = _Platform.engine()
    result = engine.risk(body.get("asset") or None)
    emit_platform_event(
        "PLATFORM_RISK_SCORED",
        f"estate risk {result.get('score')} ({result.get('level')})",
        {"score": result.get("score"), "level": result.get("level")},
    )
    return result


@router.post("/blast")
def platform_blast(body: dict[str, Any],
                   user: str = Depends(require_permission("crypto.read")),
                   tenant=Depends(get_tenant_context)):
    if body.get("domains"):
        _Platform.update_state(domains=body["domains"])
    engine = _Platform.engine()
    seed = str(body.get("seed") or "")
    result = engine.blast(seed, int(body.get("max_depth") or 10))
    emit_platform_event(
        "PLATFORM_BLAST_QUERIED",
        f"blast radius for {seed!r}: {result.get('affected_count', 0)} assets",
        {"seed": seed, "affected_count": result.get("affected_count", 0)},
    )
    return result


@router.post("/whatif")
def platform_whatif(body: dict[str, Any],
                    user: str = Depends(require_permission("crypto.manage")),
                    tenant=Depends(get_tenant_context)):
    if body.get("domains"):
        _Platform.update_state(domains=body["domains"])
    engine = _Platform.engine()
    current = str(body.get("current") or "")
    target = str(body.get("target") or "")
    result = engine.what_if(current, target, body.get("protocols"))
    feasible = bool(
        result.get("checks", {}).get("libraries", {}).get("supported")
        and result.get("checks", {}).get("hardware", {}).get("supported")
    )
    emit_platform_event(
        "PLATFORM_WHATIF_ANALYZED",
        f"what-if {current} → {target}: {'feasible' if feasible else 'blocked'}",
        {"current": current, "target": target, "feasible": feasible},
    )
    return result


@router.post("/security")
def platform_security(body: dict[str, Any],
                      user: str = Depends(require_permission("crypto.manage")),
                      tenant=Depends(get_tenant_context)):
    result = _Platform.engine().enforce(body.get("request") or body)
    emit_platform_event(
        "PLATFORM_SECURITY_ENFORCED",
        f"request {'allowed' if result.get('allowed') else 'denied'}",
        {
            "allowed": bool(result.get("allowed")),
            "violations": len(result.get("violations") or []),
        },
    )
    return result


@router.get("/evidence")
def platform_evidence(user: str = Depends(require_permission("crypto.read")),
                      tenant=Depends(get_tenant_context)):
    result = _Platform.engine().evidence.verify()
    emit_platform_event(
        "PLATFORM_EVIDENCE_VERIFIED",
        f"evidence chain {'valid' if result.get('valid') else 'INVALID'} "
        f"({result.get('records', 0)} records)",
        {"valid": bool(result.get("valid")), "records": result.get("records", 0)},
    )
    return result
