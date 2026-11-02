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


class CbomRuntimeTraceRequest(BaseModel):
    operations: list[dict] = Field(default_factory=list, description=(
        "recorded crypto operations with the whole chain: application, pid, provider, "
        "provider_version, operation, algorithm, key_size/mode, observed_at, evidence_id"))
    declared: list[dict] = Field(default_factory=list, description=(
        "SBOM library declarations (name, version, evidence_id) to correlate the loaded "
        "provider against"))


class CbomRuntimeTraceResponse(BaseModel):
    traces: list[dict]
    refused: list[dict]
    providers: list[dict]
    unknown_version: list[str]
    correlations: list[dict]
    correlation_counts: dict
    components: list[dict]
    graph: dict
    summary: dict


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


class CbomEstateChainRequest(BaseModel):
    estate: dict = Field(..., description=(
        "one estate description, the shape a scan or an integration produces: name, "
        "components (SBOM rows with their algorithms), operations (runtime traces), keys "
        "and key_uses (KMS inventory and recorded operations), probes (TLS endpoints), "
        "findings (static results), conflicts (claims to reconcile), coverage (rollup and "
        "file counts), purposes, primitives and as_of"))


class CbomEstateChainResponse(BaseModel):
    estate: str
    generated_at: str
    runtime: dict
    keys: dict
    evidence: dict
    profiles: dict
    promotion: dict
    document: dict
    empty: dict
    handoff: dict
    conflicts: dict
    graph: dict
    coverage: dict
    checks: list[dict]
    summary: dict
    statement: str


class CbomNetworkAssetsRequest(BaseModel):
    hops: list[dict] = Field(default_factory=list, description=(
        "TLS hops as the network collector observed them: from, to, endpoint, "
        "observed_on (the interface that saw the handshake), cipher_suite, tls_version, "
        "evidence_id. A hop with no observer or no evidence is refused, because \"somewhere "
        "in the path\" is what lets the wrong system inherit the algorithms"))
    applications: list[str] = Field(default_factory=list, description=(
        "the applications the estate has declared. A hop's algorithm may be attributed to "
        "an application only when that application is declared (or the hop says "
        "role=APPLICATION); a hostname is never read as proof"))
    graph: dict | None = Field(None, description=(
        "a usage graph to audit: every USES_CRYPTO edge whose whole basis is a handshake "
        "that terminated in front of the subject is reported as an overclaim"))


class CbomNetworkAssetsResponse(BaseModel):
    assets: dict
    components: dict
    audit: dict
    summary: dict


class CbomTerminationPathsRequest(BaseModel):
    hops: list[dict] = Field(default_factory=list, description=(
        "TLS hops in path order: from, to, endpoint, observed_on, tls_version, "
        "cipher_suite, evidence_id, and optionally terminates/mode for a middlebox that "
        "tunnels instead of terminating"))


class CbomTerminationPathsResponse(BaseModel):
    paths: dict
    components: dict
    edges: dict
    summary: dict


class CbomCompletenessRequest(BaseModel):
    components: list[dict] = Field(default_factory=list, description=(
        "per-component inspection records: {component, tasks: [{task, status, found}], "
        "claims: [{task, algorithm, evidence_id, location}]}. A task that did not "
        "finish makes the component INCOMPLETE; a task reporting 'nothing found' while "
        "another reports a finding makes it CONTRADICTED"))


class CbomCompletenessResponse(BaseModel):
    inventory: dict
    components: list[dict]


class CbomTwinRequest(BaseModel):
    estate: dict = Field(..., description=(
        "the same estate description ``/estate-chain`` takes: components, operations, "
        "keys and key_uses, probes, findings, conflicts, coverage"))
    policy: list[dict] = Field(default_factory=list, description=(
        "crypto policy rows for drift: algorithm, key_size, allowed. A policy row that "
        "nothing was observed using is reported as not observed, not as drift"))
    advisories: list[dict] = Field(default_factory=list, description=(
        "advisories to match against the twin: id, component, fixed_in or "
        "affected_versions[], severity"))


class CbomTwinResponse(BaseModel):
    schema_: str = Field(alias="schema")
    twin: dict
    consumers: dict
    summary: dict


class CbomTlsStateRequest(BaseModel):
    observations: list[dict] = Field(default_factory=list, description=(
        "one fact in one state: endpoint, state (SUPPORTED/CONFIGURED/NEGOTIATED, or "
        "ADVERTISED/ENABLED/SELECTED), tls_version, cipher_suite, group, "
        "signature_algorithm, evidence_id, observed_at, enumeration_complete. A fact "
        "whose state is unknown, or that carries no evidence id, is refused"))
    endpoint: str | None = Field(None, description=(
        "endpoint to answer about; with version, 'can we call this protocol disabled?'"))
    version: str | None = Field(None, description=(
        "protocol to test for absence, answered only from a complete enumeration"))


class CbomTlsStateResponse(BaseModel):
    schema_: str = Field(alias="schema")
    endpoints: list[dict]
    refused: list[dict]
    checks: dict | None = None
    summary: dict
    statement: str


class CbomHistoryRequest(BaseModel):
    before: dict = Field(..., description=(
        "an earlier cryptoscan.nbom-history/1 snapshot, as built by "
        "cbom.nbom_history.snapshot from a collection run"))
    after: dict = Field(..., description="a later snapshot of the same estate")
    systems: dict[str, list[str]] | None = Field(None, description=(
        "endpoint -> affected systems, used only to name owners on a finding"))


class CbomHistoryResponse(BaseModel):
    schema_: str = Field(alias="schema")
    before: dict
    after: dict
    identical: bool
    changes: list[dict]
    counts: dict
    unchanged: int
    downgrades: int
    statement: str
    regression: dict
    summary: dict


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


@router.post("/runtime-traces", response_model=CbomRuntimeTraceResponse)
def cbom_runtime_traces(body: CbomRuntimeTraceRequest,
                        user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Process-level runtime traces -> runtime-confirmed assets, providers and edges.

    The chain the review asks for is kept whole (application → process → provider →
    operation → algorithm), a row missing any link is refused rather than promoted,
    and the loaded provider version is correlated with the SBOM's declaration — a
    mismatch is reported, never resolved.
    """
    from cbom import process_tracing as pt

    traced = pt.trace(body.operations)
    providers = pt.provider_observations(traced["traces"])
    correlation = pt.correlate(providers, body.declared)
    components = pt.to_components(traced["traces"])
    projection = pt.graph(traced["traces"])
    return {
        "traces": traced["traces"],
        "refused": traced["refused"],
        "providers": providers["providers"],
        "unknown_version": providers["unknown_version"],
        "correlations": correlation["correlations"],
        "correlation_counts": correlation["counts"],
        "components": components["components"],
        "graph": projection,
        "summary": pt.summary(traced, providers, correlation),
    }


@router.post("/tls-state", response_model=CbomTlsStateResponse)
def cbom_tls_state(body: CbomTlsStateRequest,
                   user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Supported, configured and negotiated, kept apart per endpoint.

    Review item 7: ``TLS 1.2 supported`` is not ``TLS 1.2 in use``, and
    ``TLS 1.3 negotiated`` does not prove it is the only supported protocol. The
    response keeps three evidence sets; ``checks.disabled`` answers "may we call
    this protocol gone?" only from a complete authorized enumeration, and
    ``checks.minimum`` names its basis rather than handing back one version.
    """
    from cbom import tls_state as ts

    try:
        result = ts.observe(body.observations)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    checks: dict[str, Any] | None = None
    if body.endpoint:
        checks = {"minimum": ts.minimum(result, endpoint=body.endpoint)}
        if body.version:
            checks["disabled"] = ts.disabled(result, endpoint=body.endpoint,
                                             version=body.version)
    return {**result, "checks": checks, "summary": ts.summary(result)}


@router.post("/history/compare", response_model=CbomHistoryResponse)
def cbom_history_compare(body: CbomHistoryRequest,
                         user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Two NBOM snapshots in, every change out, and the weakenings as a finding.

    Review items 18 and 21: the point-in-time NBOM gains a memory. ``changes`` is the
    complete list, ``downgrades`` counts the subset that moved the wrong way, and
    ``regression`` carries one ``NETWORK_CRYPTO_REGRESSION`` per weakened endpoint with
    the evidence from both sides. An upgrade, an added listener and an endpoint that
    stopped answering are changes and are not regressions.
    """
    from cbom import nbom_history as nh

    try:
        comparison = nh.compare(body.before, body.after, systems=body.systems)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    regressed = nh.regression(comparison)
    return {**comparison, "regression": regressed,
            "summary": nh.summary(comparison, regressed)}


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


@router.post("/completeness", response_model=CbomCompletenessResponse)
def cbom_completeness(body: CbomCompletenessRequest,
                      user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Was the component looked at, did every task finish, and do the tasks agree?

    A component with no findings is only "a component without cryptography" when
    something finished looking. ``UNMEASURED`` (nobody looked), ``INCOMPLETE`` (a
    task stopped early), ``CONTRADICTED`` (one task says clean, another found
    something) and ``EMPTY`` (every task finished and found nothing) are four
    different answers, and only ``COMPLETE`` and ``EMPTY`` may be counted when a
    total is quoted.
    """
    from cbom import inventory_completeness as ic

    rows = [ic.component(item.get("claims") or [], item.get("tasks") or [],
                         name=item.get("component"))
            for item in body.components if isinstance(item, dict)]
    return {"inventory": ic.inventory(rows), "components": rows}


@router.post("/termination-paths", response_model=CbomTerminationPathsResponse)
def cbom_termination_paths(body: CbomTerminationPathsRequest,
                           user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Client → LB → gateway → application as three relationships, not one attribute.

    ``Client --TLS1.3 AES-256-GCM--> LB --TLS1.2 AES-128-GCM--> gateway --TLS1.3
    AES-256-GCM--> application`` is three cryptographic relationships, and the
    middle one is weaker than both ends. Collapsing them into "the application uses
    AES-256-GCM" hides the only hop a reviewer needed to see; reporting the union
    ("AES-256-GCM, AES-128-GCM") hides *where* the weak suite lives. This returns
    one relationship per hop, the changes between adjacent hops, and an explicit
    refusal of the merged claim. A hop that connects to nothing is a gap, not a
    one-hop path.
    """
    from cbom import termination_paths as tp

    paths = tp.build(body.hops)
    return {
        "paths": paths,
        "components": tp.to_components(paths),
        "edges": tp.to_edges(paths),
        "summary": tp.summary(paths),
    }


@router.post("/network-assets", response_model=CbomNetworkAssetsResponse)
def cbom_network_assets(body: CbomNetworkAssetsRequest,
                        user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """A handshake is an interface fact: which endpoint, which terminator, which hop.

    ``TLS_AES_256_GCM_SHA384`` on ``payments.bank.example:443`` terminated by
    ``External LB`` is the balancer's cipher policy. The review's rule is that the
    CBOM may say so and may **not** say *Payments API uses AES-256-GCM* without
    evidence that the application terminated the hop, so an asset carries an
    application name only when the estate declared that name or the hop says it is
    the application. The optional ``graph`` audit reports every usage edge that
    rests on a fronting hop, rather than silently rewriting it.
    """
    from cbom import network_assets as na

    assets = na.assets(body.hops, applications=body.applications)
    return {
        "assets": assets,
        "components": na.to_components(assets),
        "audit": na.audit_graph(body.graph or {}, assets),
        "summary": na.summary(assets),
    }


@router.post("/estate-chain", response_model=CbomEstateChainResponse)
def cbom_estate_chain(body: CbomEstateChainRequest,
                      user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Every CBOM layer over one estate, with the seams checked.

    The single-asset and single-layer routes answer "what does this row mean". This
    answers "does the pipeline hold together": the document, its coverage, the
    handoff, the conflicts, and the twin edges are produced once from the same
    evidence — and then seven invariants are checked across them. A failing check
    comes back in ``checks`` and in ``summary.status`` as ``BROKEN``; the response
    is still 200, because a pipeline that hides its own failure is the bug.
    """
    from cbom import estate_chain as ec

    try:
        result = ec.run(body.estate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result["summary"] = ec.summary(result)
    return result


@router.post("/twin", response_model=CbomTwinResponse)
def cbom_twin(body: CbomTwinRequest,
              user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """The crypto graph and digital twin, plus the three consumers that read it.

    Review item 20's architecture: five evidence families feed one graph, the graph
    feeds the CBOM, and the twin is projected from that same evidence — so the twin
    cannot disagree with the document. Drift, PQC migration and threat intelligence
    each answer one question and inherit the claim level of the node they read; a
    consumer that reports more than its node is refused in ``claim_check``.
    """
    from cbom import digital_twin as dt

    try:
        twin = dt.build(body.estate)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    consumers = dt.consumers(twin, policy=body.policy, advisories=body.advisories,
                             as_of=body.estate.get("as_of"))
    return {
        "schema": dt.SCHEMA,
        "twin": twin,
        "consumers": consumers,
        "summary": dt.summary(twin, consumers),
    }


@router.post("/hsm-evidence")
def cbom_hsm_evidence(body: CbomHsmRequest, user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """HSM capability vs configured key vs recorded operation, kept apart."""
    from cbom import usage_evidence as ue

    try:
        return ue.hsm_evidence(body.kind, evidence_id=body.evidence_id,
                               operation=body.operation)
    except ue.EvidenceRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc))
