"""CBOM usage proof: what the evidence observed, and what a CBOM may not claim.

Three read-only surfaces over :mod:`cbom.usage_evidence`:

* ``POST /cbom/usage`` — one asset's capability, per-layer observations, evidence
  ids and deterministically computed confidence; optionally the candidate
  algorithms a crypto-capable library supports (candidates, never ``USED``).
* ``POST /cbom/reconcile`` — every source's claim kept side by side, with
  conflicts stated instead of collapsed into one value.
* ``POST /cbom/tls-paths`` — one relationship per TLS hop, attributed to the
  endpoint that terminated it rather than to the application behind it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles

router = APIRouter(prefix="/cbom", tags=["cbom"])

#: Reading a usage profile is an analysis action: analysts, the CISO, auditors
#: (read-only reports) and supervisors may ask. It is not a dashboard read, and it
#: is not a write, so it takes a role rather than only a session.
CBOM_USAGE_READERS = ("superadmin", "ciso", "security_analyst", "auditor", "supervisor")


class CbomUsageRequest(BaseModel):
    asset: dict = Field(..., description=(
        "the asset under question: algorithm, parameters (key_size/mode/curve), purpose"))
    evidence: list[dict] = Field(default_factory=list, description=(
        "evidence events: class or layer, evidence_id, algorithm, purpose, location, "
        "observed_at. An observation with no evidence id is refused; an IMPORTED event "
        "can never be promoted to an observation"))
    component: str | None = Field(None, description=(
        "crypto-capable library to expand into candidate algorithms (capability only)"))
    algorithms: list[str] = Field(default_factory=list, description=(
        "algorithms the component supports, listed as candidates and never as usage"))


class CbomUsageResponse(BaseModel):
    profile: dict
    candidates: dict | None = None


class CbomReconcileRequest(BaseModel):
    claims: list[dict] = Field(..., description=(
        "one row per source: field, fact, source (kb/sbom/container/runtime/network/vendor) "
        "and evidence_id. Observing sources that disagree produce a conflict; nothing is "
        "collapsed"))


class CbomReconcileResponse(BaseModel):
    schema_: str = Field(alias="schema")
    rows: list[dict]
    conflicts: list[dict]
    resolved: list[dict]
    refused: list[dict]
    statement: str


class CbomTlsPathsRequest(BaseModel):
    hops: list[dict] = Field(..., description=(
        "TLS hops as observed: from, to, endpoint, observed_on, tls_version, cipher_suite, "
        "key_exchange, certificate_ref, evidence_id"))


class CbomCollectRequest(BaseModel):
    probes: list[dict] = Field(default_factory=list, description=(
        "network-scanner probes: endpoint, status, crypto.{tls_version,cipher_suite}, "
        "certificates[], scan_run_id or evidence_id. A probe that negotiated nothing "
        "produces no evidence"))
    assets: list[dict] = Field(default_factory=list, description=(
        "stored crypto findings: algorithm, key_size, mode, purpose, file_path, line_number, "
        "evidence_ids[]. A finding with no evidence row is refused"))
    operations: list[dict] = Field(default_factory=list, description=(
        "recorded crypto operations: operation, algorithm, key_size/mode/curve, evidence_id, "
        "observed_at, process. A row missing any of those is a claim, not an observation"))
    scan_run_id: str | None = Field(None, description="scan run the probes belong to")
    purposes: dict = Field(default_factory=dict, description="algorithm -> purpose")


class CbomCollectResponse(BaseModel):
    network: dict
    static: dict
    runtime: dict
    profiles: dict


class CbomNetworkUsageResponse(BaseModel):
    profiles: dict
    certificates: list[dict]
    hops: dict
    source: str
    scan_runs: int


class CbomGraphRequest(BaseModel):
    profiles: list[dict] | None = Field(None, description=(
        "usage profiles (as returned by /cbom/usage or /cbom/usage/collect); one "
        "USES_CRYPTO edge per algorithm, classified by the strongest evidence class"))
    reconciled: dict | None = Field(None, description=(
        "output of /cbom/reconcile; each conflict becomes a CONFLICTS_WITH edge with both "
        "sides' evidence — no conflict is ever resolved into an edge"))
    paths: dict | None = Field(None, description=(
        "output of /cbom/tls-paths; endpoints negotiate algorithms and terminate with "
        "certificates, and a terminator's algorithms never become the application's"))
    system: str | None = None
    application: str | None = None
    component: str | None = None


class CbomGraphResponse(BaseModel):
    edges: dict
    applied: dict
    graph: dict


class CbomPromoteRequest(BaseModel):
    components: list[dict] = Field(..., description=(
        "crypto-capable components with their evidence id: name, version, algorithms[] and "
        "evidence_id. A component with no evidence id is refused, because its capabilities "
        "cannot be attributed to a document"))
    evidence: list[dict] = Field(default_factory=list, description=(
        "collector evidence events (see /cbom/usage/collect); only an observing class "
        "promotes a candidate into the document"))
    purposes: dict = Field(default_factory=dict, description="algorithm -> purpose")
    primitives: dict = Field(default_factory=dict, description="algorithm -> primitive")
    oids: dict = Field(default_factory=dict, description="algorithm -> OID")
    document_name: str = Field("cryptoscan-promotion", description="metadata.component name")


class CbomPromoteResponse(BaseModel):
    promotion: dict
    inventory: dict
    document: dict


class CbomKmsRequest(BaseModel):
    rows: list[dict] = Field(default_factory=list, description=(
        "provider key-inventory rows: key_ref (or key_id/arn), algorithm, key_size, curve, "
        "purpose, provider, location, status, created_at, rotated_at, evidence_id. A row "
        "carrying key material is refused, never sanitised"))
    uses: list[dict] = Field(default_factory=list, description=(
        "recorded key operations: key_ref, operation, evidence_id, observed_at. An operation "
        "on a key that is not in the inventory is refused"))
    as_of: str | None = Field(None, description="ISO date the rotation policy is judged at")
    max_age_days: int = Field(365, ge=30, le=3650, description="policy rotation age")


class CbomKmsResponse(BaseModel):
    keys: dict
    usage: dict
    posture: dict


class CbomPqcHandoffRequest(BaseModel):
    assets: list[dict] = Field(default_factory=list, description=(
        "inventoried crypto assets: algorithm, key_size, purpose, usage (promotion "
        "level or usage state) and evidence_ids"))
    document: dict | None = Field(None, description=(
        "a CBOM document to hand off instead of assets; usage is read from the "
        "platform's cryptoscan: properties, and a plain document counts as unobserved"))
    as_of: str | None = None


class CbomPqcHandoffResponse(BaseModel):
    rows: list[dict]
    summary: dict
    refused: list[dict]
    statement: str
    as_of: str


class CbomHsmRequest(BaseModel):
    kind: str = Field(..., description=(
        "CAPABILITY, CONFIGURED_KEY or OPERATION — the three HSM/KMS answers, only the last "
        "of which is usage"))
    evidence_id: str | None = None
    operation: str | None = None


@router.post("/usage", response_model=CbomUsageResponse)
def cbom_usage(body: CbomUsageRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Capability, per-layer observation, evidence and confidence for one asset.

    The answer keeps the review's distinctions: ``CANDIDATE_ONLY`` means something
    *could* use this algorithm, ``OBSERVED`` means a layer watched it happen, and
    ``confidence`` is computed from the classes present — runtime and network
    together are ``VERY_HIGH`` because they are independent collection mechanisms.
    """
    from cbom import usage_evidence as ue

    try:
        profile = ue.usage_profile(body.asset, body.evidence)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    candidates = None
    if body.component:
        candidates = ue.capability_candidates(body.component, body.algorithms,
                                              evidence_id=f"component:{body.component}")
    return {"profile": profile, "candidates": candidates}


@router.post("/reconcile", response_model=CbomReconcileResponse)
def cbom_reconcile(body: CbomReconcileRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Every source's claim, the conflicts between observers, and a precedence note."""
    from cbom import usage_evidence as ue

    return ue.reconcile(body.claims)


@router.post("/tls-paths")
def cbom_tls_paths(body: CbomTlsPathsRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """One cryptographic relationship per hop (terminations are not applications)."""
    from cbom import usage_evidence as ue

    return ue.tls_paths(body.hops)


@router.post("/usage/collect", response_model=CbomCollectResponse)
def cbom_usage_collect(body: CbomCollectRequest,
                       user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Turn rows this platform already holds into CBOM evidence, then profile them.

    Network probes become ``NETWORK_OBSERVED``, stored findings with their
    evidence rows become ``STATIC_OBSERVED``, recorded operations become
    ``RUNTIME_OBSERVED`` — and every source's refusals are reported rather than
    dropped, because a row that cannot be attributed is an inventory entry, not
    an observation.
    """
    from cbom import usage_collectors as uc

    network = uc.network_events_from_probes(body.probes, scan_run_id=body.scan_run_id)
    static = uc.static_events_from_assets(body.assets)
    runtime = uc.runtime_events_from_operations(body.operations)
    profiles = uc.profiles(network["events"] + static["events"] + runtime["events"],
                           purposes=body.purposes)
    return {"network": network, "static": static, "runtime": runtime, "profiles": profiles}


@router.get("/usage/network", response_model=CbomNetworkUsageResponse)
def cbom_usage_network(db: Session = Depends(get_db_session),
                       user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """The network half of the usage profile, read from stored scan runs.

    This is the collector the network scanner already feeds: each run's probes
    become ``NETWORK_OBSERVED`` facts carrying the run they came from, plus the
    certificates served and one hop per observed endpoint. Nothing here claims
    anything about the application behind a terminator.
    """
    from cbom import usage_collectors as uc
    from db.models.network_scan_run import NetworkScanRun

    runs = db.execute(
        select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc(),
                                        NetworkScanRun.id.desc()).limit(20)
    ).scalars().all()
    probes: list[dict] = []
    for run in runs:
        for probe in ((run.result or {}).get("probes") or []):
            if isinstance(probe, dict):
                probes.append({**probe, "scan_run_id": probe.get("scan_run_id") or run.id,
                               "observed_at": probe.get("observed_at")
                               or (run.created_at.isoformat() if run.created_at else None)})
    collected = uc.network_events_from_probes(probes)
    profiles = uc.profiles(collected["events"])
    return {"profiles": profiles, "certificates": collected["certificates"],
            "hops": {"schema": collected["schema"], "paths": collected["hops"],
                     "statement": collected["statement"]},
            "source": "live" if probes else "empty", "scan_runs": len(runs)}


@router.post("/usage/graph", response_model=CbomGraphResponse)
def cbom_usage_graph(body: CbomGraphRequest,
                     user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """CBOM relationships as graph edges, written with their evidence attached.

    Three families: ``USES_CRYPTO`` (classified by the strongest evidence class —
    an SBOM-only algorithm is ``DECLARED``), ``CONFLICTS_WITH`` (two sources
    disagreeing, both evidence ids kept, never resolved into a chosen value) and
    ``NEGOTIATES``/``TERMINATES`` (a terminator's algorithms belong to the
    terminator). An edge without evidence is refused rather than drawn.
    """
    from cbom import usage_graph as ug
    from graph_engine.core.engine import GraphEngine

    try:
        edges = ug.build_graph(body.profiles, reconciled=body.reconciled, paths=body.paths,
                               system=body.system, application=body.application,
                               component=body.component)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    engine = GraphEngine()
    applied = ug.apply_graph(engine, edges["edges"])
    return {"edges": edges, "applied": applied, "graph": engine.to_vis()}


@router.post("/promote", response_model=CbomPromoteResponse)
def cbom_promote(body: CbomPromoteRequest,
                 user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Promote observed algorithms into CBOM assets, and keep the rest candidates.

    A library that supports AES does not mint ``AES-256 USED``: candidates are
    returned separately and are deliberately absent from the document, which is
    what a reviewer reads as fact. Each promoted asset carries its promotion
    level (CAPABILITY < STATIC/CONFIGURED < RUNTIME/NETWORK < VERIFIED) and the
    evidence ids that earned it, and the platform's claims sit in ``cryptoscan:``
    properties rather than in the standard's fields.
    """
    from cbom import promotion as promo

    promoted = promo.promote(body.components, body.evidence, purposes=body.purposes,
                             primitives=body.primitives, oids=body.oids)
    return {"promotion": promoted, "inventory": promo.asset_inventory(promoted),
            "document": promo.to_cbom(promoted, name=body.document_name)}


@router.post("/kms/keys", response_model=CbomKmsResponse)
def cbom_kms_keys(body: CbomKmsRequest,
                  user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """KMS/HSM key inventory: configured keys, recorded operations, and posture.

    Three answers, never one: a key that exists is ``CONFIGURED``, an operation
    that used it is ``RUNTIME_OBSERVED``, and a module that *supports* an
    algorithm is only a capability. Metadata only — a row carrying key material
    is refused, and an operation on a key nobody inventoried is refused because
    it means the inventory is incomplete, not that the operation is wrong.
    """
    from datetime import date as _date

    from cbom import kms_collectors as kc

    as_of = None
    if body.as_of:
        try:
            as_of = _date.fromisoformat(body.as_of[:10])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"as_of is not a date: {exc}")
    keys = kc.key_records_from_kms(body.rows)
    usage = kc.usage_events_from_keys(keys["records"], body.uses)
    return {"keys": keys, "usage": usage,
            "posture": kc.posture(keys["records"], as_of=as_of,
                                  max_age_days=body.max_age_days)}


@router.post("/pqc-handoff", response_model=CbomPqcHandoffResponse)
def cbom_pqc_handoff(body: CbomPqcHandoffRequest,
                     user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """CBOM inventory -> a PQC migration handoff, one row per asset.

    The document says what exists; this says what needs migration, in which order,
    and on what basis. Status, risk and priority are separate fields because a
    boolean cannot carry them: AES-256 is *classical, acceptable* while AES-128 is
    *Grover-weakened*, and an unregistered algorithm is ``UNKNOWN`` rather than
    quietly resistant. Priority only escalates — runtime evidence outranks a
    capability, and a confidentiality purpose on a Shor-vulnerable algorithm is
    ``IMMEDIATE``.
    """
    from cbom import pqc_handoff as pq

    if body.document is not None:
        return pq.handoff_from_cbom(body.document, as_of=body.as_of)
    return pq.handoff(body.assets, as_of=body.as_of)


@router.post("/hsm-evidence")
def cbom_hsm_evidence(body: CbomHsmRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """HSM capability vs configured key vs recorded operation, kept apart."""
    from cbom import usage_evidence as ue

    try:
        return ue.hsm_evidence(body.kind, evidence_id=body.evidence_id,
                               operation=body.operation)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
