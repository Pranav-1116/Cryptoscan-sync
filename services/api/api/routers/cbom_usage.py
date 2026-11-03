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


class CbomNetworkIdentityRequest(BaseModel):
    observations: list[dict] = Field(default_factory=list, description=(
        "asset observations: asset_id, device_id, hostname, type, ips, environment, "
        "zone, location, certificate, collector_source, evidence_id, observed_at. An "
        "observation carrying only an IP and a port is refused, not named"))
    links: dict[str, dict] | None = Field(None, description=(
        "declared asset -> application mapping with an evidence id; without both, the "
        "link is a claim and comes back NOT_PROVEN"))


class CbomNetworkIdentityResponse(BaseModel):
    schema_: str = Field(alias="schema")
    assets: list[dict]
    refused: list[dict]
    observations: int
    collectors: list[str]
    untyped: list[str]
    statement: str
    links: dict
    summary: dict


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


class CbomPassiveRequest(BaseModel):
    contract: dict = Field(default_factory=dict, description=(
        "The privacy contract that governs this collection: contract_id, owner, "
        "purposes, lawful_basis, retention_days, salt_id and the `collects` list"))
    captures: list[dict] = Field(default_factory=list, description=(
        "Captured exchanges: handshake metadata only. Pseudonymous fields are hashed "
        "with `salt` and the raw values are never stored"))
    salt: str | None = Field(default=None, description=(
        "Per-deployment salt for pseudonymous fields. Used and discarded; never stored, "
        "logged or echoed"))
    as_of: str | None = Field(default=None, description=(
        "Evaluate retention against this moment instead of the wall clock"))


class CbomPassiveResponse(BaseModel):
    schema_: str = Field(alias="schema")
    contract_id: str | None
    observations: list[dict]
    refused: list[dict]
    expired: list[str]
    live: int
    suites: list[str]
    statement: str
    not_proven: list[str]
    facts: list[dict]
    summary: dict


class CbomIpsecRequest(BaseModel):
    tunnels: list[dict] = Field(default_factory=list, description=(
        "IPsec SAs: peer, local, ike_version, authentication, mode, state, evidence_id, "
        "observed_at, source, and `ike`/`child` objects, each with `proposal` and the "
        "CHILD SA additionally with `pfs` and `lifetime`"))


class CbomIpsecResponse(BaseModel):
    schema_: str = Field(alias="schema")
    tunnels: list[dict]
    peers: list[str]
    refused: list[dict]
    without_pfs: list[str]
    ikev1: list[str]
    weak_transforms_in_use: list[str]
    statement: str
    not_proven: list[str]
    facts: list[dict]
    quantum_vulnerable: list[str]
    summary: dict


class CbomSshRequest(BaseModel):
    sessions: list[dict] = Field(default_factory=list, description=(
        "SSH sessions: host, port, banner, evidence_id, observed_at, source, "
        "host_key_fingerprint, negotiated {kex, host_key, cipher_client_to_server, "
        "cipher_server_to_client, mac_client_to_server, mac_server_to_client}, and "
        "optionally server_supported"))


class CbomSshResponse(BaseModel):
    schema_: str = Field(alias="schema")
    sessions: list[dict]
    hosts: list[str]
    refused: list[dict]
    deprecated: dict
    asymmetric_directions: list[str]
    statement: str
    not_proven: list[str]
    facts: list[dict]
    quantum_vulnerable: list[str]
    summary: dict


class CbomTopologyRequest(BaseModel):
    claims: list[dict] = Field(default_factory=list, description=(
        "relationships: kind (one of the nine), from, to, evidence_id, observed_at, "
        "source, and optionally evidence_class. confidence is derived, never supplied. "
        "RE_ENCRYPTS also needs two handshakes; PASSTHROUGH needs a session_id"))
    nodes: list[dict] = Field(default_factory=list, description=(
        "declared nodes: name and role, so an edge cannot name a device nobody knows"))


class CbomTopologyResponse(BaseModel):
    schema_: str = Field(alias="schema")
    nodes: list[str]
    declared_nodes: list[str]
    edges: list[dict]
    refused: list[dict]
    counts: dict
    kinds_unused: list[str]
    confidence: dict
    overclaimed: list[dict]
    undeclared_nodes: list[str]
    statement: str
    audit: dict
    summary: dict


class CbomCertificateChainRequest(BaseModel):
    certificates: list[dict] = Field(default_factory=list, description=(
        "certificate records: certificate_ref (or serial + fingerprint), subject, "
        "issuer, authority/subject key id, public key algorithm and size, signature "
        "algorithm, validity, SAN, endpoint, evidence_id, source, observed_at"))
    anchors: list[str] = Field(default_factory=list, description=(
        "certificate refs the caller treats as trust anchors; a self-signed root that "
        "is not declared is reported as an unconfirmed anchor"))
    declared: dict[str, str] | None = Field(None, description=(
        "certificate_ref -> issuer certificate_ref, for paths only a PKI export knows"))


class CbomCertificateChainResponse(BaseModel):
    schema_: str = Field(alias="schema")
    certificates: dict
    refused: list[dict]
    paths: list[dict]
    resolutions: dict
    anchors_declared: list[str]
    anchors_unconfirmed: list[str]
    shared_public_keys: dict
    states: dict
    statement: str
    not_proven: list[str]
    edges: dict
    summary: dict


class CbomCipherSuiteRequest(BaseModel):
    handshakes: list[dict] = Field(default_factory=list, description=(
        "completed handshakes: endpoint, cipher_suite, tls_version, group, "
        "signature_algorithm, certificate (with public_key), evidence_id. Whatever the "
        "suite does not name and the handshake does not report stays unknown"))
    suite: str | None = Field(None, description=(
        "one suite to decompose on its own, when there is no handshake to describe"))
    group: str | None = None
    signature_algorithm: str | None = None


class CbomCipherSuiteResponse(BaseModel):
    schema_: str = Field(alias="schema")
    handshakes: list[dict]
    refused: list[dict]
    endpoints: list[str]
    ratings: dict
    with_unknown_dimensions: int
    statement: str
    dimensions: list[str]
    evidence_sources: list[str]
    algorithms: list[dict]
    algorithm_statement: str
    frontier: list[dict] | None = None


class CbomCorrelateRequest(BaseModel):
    before: dict = Field(..., description="an earlier cryptoscan.nbom-history/1 snapshot")
    after: dict = Field(..., description="a later snapshot of the same estate")
    processes: list[dict] = Field(default_factory=list, description=(
        "runtime traces in the same window: process, pid, host, evidence_id, "
        "observed_at. A process is bound to the host it was seen on"))
    window_seconds: int = Field(3600, description=(
        "the window the correlation is allowed to look across"))


class CbomCorrelateResponse(BaseModel):
    schema_: str = Field(alias="schema")
    signals: list[dict]
    window: dict
    patterns: list[dict]
    counts: dict
    levels: dict
    worst: str | None
    blind_spots: list[str]
    statement: str
    not_proven: list[str]
    never: list[str]
    summary: dict


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


@router.post("/passive", response_model=CbomPassiveResponse)
def cbom_passive(body: CbomPassiveRequest,
                 user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Passive observation, gated on a privacy contract that is checked first.

    Review item 15. A capture is accepted only if every field is **classified**, none is
    **prohibited**, and each is **listed in the contract** — a prohibited field is
    refused rather than stripped, because a silent `sanitise()` teaches operators the
    schema tolerates payload. Pseudonymous fields (client address, SNI, JA3) become
    keyed hashes: the salt is per deployment and is never stored, logged or echoed, so
    two deployments cannot join their records. An observation expires with its
    shortest-lived field, and an expired capture contributes no facts — it is reported
    as expired instead of being cited. Everything here is `OBSERVED` and stays that way:
    a tap asked the device nothing.
    """
    from cbom import passive_observation as po

    privacy = po.contract(**body.contract) if body.contract else po.contract()
    if not privacy["enforceable"]:
        # a contract that cannot be checked cannot vouch for a capture, so the request is
        # refused as a whole instead of refusing every record one at a time.
        raise HTTPException(status_code=422, detail={"contract": privacy["problems"]})
    estate = po.estate(body.captures, privacy=privacy, salt=body.salt,
                       as_of=body.as_of)
    facts = po.to_algorithms(estate)
    return {
        **estate,
        "facts": facts["facts"],
        "summary": po.summary(estate),
    }


@router.post("/ipsec", response_model=CbomIpsecResponse)
def cbom_ipsec(body: CbomIpsecRequest,
               user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """IPsec: two security associations, and forward secrecy for data as its own answer.

    Review item 14. A tunnel negotiates an **IKE SA** (phase 1) and a **CHILD SA**
    (phase 2) separately. A CHILD SA with no PFS group derives its keys from the IKE SA's
    material, so one compromised peer key exposes every rekeyed tunnel back to the start
    — and `AES-256 / SHA-256 / DH14` in phase 1 says nothing about it, which is why PFS
    is a field here rather than an inference. IKEv1 aggressive mode with a pre-shared
    key is reported as its own finding (a hash of the PSK travels on the wire), and
    `ENCR_NULL` is reported without being called safe or unsafe.
    """
    from cbom import ipsec_crypto as ic

    estate = ic.estate(body.tunnels)
    algorithms = ic.to_algorithms(estate) if estate["tunnels"] else None
    return {
        **estate,
        "facts": (algorithms or {}).get("facts", []),
        "quantum_vulnerable": (algorithms or {}).get("quantum_vulnerable", []),
        "summary": ic.summary(estate),
    }


@router.post("/ssh", response_model=CbomSshResponse)
def cbom_ssh(body: CbomSshRequest,
             user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """SSH: four negotiations, two of them per direction.

    Review item 13. Key exchange, host key, cipher and MAC are separate answers, and
    cipher and MAC are negotiated **per direction** — a host that uses
    `chacha20-poly1305` one way and `aes128-cbc` the other has one weak direction. The
    two SSH traps are handled explicitly: `ssh-rsa` is the SHA-1 signature algorithm
    (`rsa-sha2-256` is the modern one), and the server's offer is kept apart from what
    was used, because the client's preference decides.
    """
    from cbom import ssh_crypto as sc

    body_estate = sc.estate(body.sessions)
    algorithms = sc.to_algorithms(body_estate) if body_estate["sessions"] else None
    return {
        **body_estate,
        "facts": (algorithms or {}).get("facts", []),
        "quantum_vulnerable": (algorithms or {}).get("quantum_vulnerable", []),
        "summary": sc.summary(body_estate),
    }


@router.post("/topology", response_model=CbomTopologyResponse)
def cbom_topology(body: CbomTopologyRequest,
                  user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Relationships, each carrying its own evidence — or not drawn at all.

    Review item 12: a topology without provenance is fiction. An edge missing an
    evidence id, an observation time or a source is **not written** and comes back in
    ``refused`` with the reason; ``confidence`` is derived from the evidence class, so a
    caller may under-claim but never over-claim. ``RE_ENCRYPTS`` needs two handshakes in
    one path and ``PASSTHROUGH`` needs the same session id on both hops, because those
    are the two claims a single probe cannot support.
    """
    from cbom import topology as tp

    graph = tp.build(body.claims, nodes=body.nodes)
    return {**graph, "audit": tp.audit(graph), "summary": tp.summary(graph)}


@router.post("/certificate-chain", response_model=CbomCertificateChainResponse)
def cbom_certificate_chain(body: CbomCertificateChainRequest,
                           user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Endpoint → certificate → key → signature → issuer → trust chain.

    Review item 9. The path is assembled from subject/issuer names and key identifiers
    and **no signature is verified**, so ``ANCHORED`` is a shape and never a trust
    decision; an issuer missing from the inventory stops the path as ``INCOMPLETE`` with
    the missing subject named, because a chain that ends where the collection ended is a
    gap and not a root. Validity is a state with a day count, revocation is ``UNKNOWN``
    on every row, and only evidence-timed presentations become topology edges.
    """
    from cbom import certificate_chain as cc

    body_chain = cc.chain(body.certificates, anchors=body.anchors,
                          declared=body.declared)
    return {**body_chain, "edges": cc.edges(body_chain),
            "summary": cc.summary(body_chain)}


@router.post("/cipher-suite", response_model=CbomCipherSuiteResponse)
def cbom_cipher_suite(body: CbomCipherSuiteRequest,
                      user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """A suite string in, four decisions out, each with where it came from.

    Review item 8: ``TLS_AES_256_GCM_SHA384`` names an AEAD and a hash and nothing
    else. Key exchange and authentication come from the handshake — the agreed group,
    the signature algorithm, the certificate's key. A dimension nobody reported comes
    back ``NOT_NAMED`` rather than as the TLS 1.2 default, which is the guess that makes
    TLS 1.3 inventories wrong.
    """
    from cbom import cipher_suite as cs

    try:
        if body.suite and not body.handshakes:
            one = cs.decompose(body.suite, group=body.group,
                               signature_algorithm=body.signature_algorithm)
            batch = {"schema": one["schema"], "handshakes": [one], "refused": [],
                     "endpoints": [], "ratings": {one["strength"]["rating"]: 1},
                     "with_unknown_dimensions": 1 if one["not_named"] else 0,
                     "statement": one["statement"]}
        else:
            batch = cs.handshake(body.handshakes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    algorithms = cs.to_algorithms(batch["handshakes"][0]) if batch["handshakes"] else None
    frontier = cs.frontier(batch["handshakes"][0]) if batch["handshakes"] else None
    return {
        "schema": batch["schema"],
        "handshakes": batch["handshakes"],
        "refused": batch["refused"],
        "endpoints": batch["endpoints"],
        "ratings": batch["ratings"],
        "with_unknown_dimensions": batch["with_unknown_dimensions"],
        "statement": batch["statement"],
        "dimensions": list(cs.DIMENSIONS),
        "evidence_sources": list(cs.EVIDENCE),
        "algorithms": (algorithms or {}).get("facts", []),
        "algorithm_statement": (algorithms or {}).get("statement", ""),
        "frontier": (frontier or {}).get("dimensions"),
    }


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


@router.post("/network-identity", response_model=CbomNetworkIdentityResponse)
def cbom_network_identity(body: CbomNetworkIdentityRequest,
                          user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Stable network asset identity, with IP churn as history on the asset.

    Review item 20 of the NBOM review: *not* `IP:port`. An observation with no
    identity except an address is refused; two collectors on one hostname become one
    asset with two evidence ids; an address change is `IP_ADDED`/`IP_REMOVED` against
    the same asset id. An application is named only from a declared mapping with an
    evidence id, so an interface never becomes the application behind it.
    """
    from cbom import network_identity as ni

    inventory = ni.merge(body.observations)
    return {**inventory, "links": ni.link(inventory["assets"], body.links),
            "summary": ni.summary(inventory)}


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


@router.post("/history/correlate", response_model=CbomCorrelateResponse)
def cbom_history_correlate(body: CbomCorrelateRequest,
                           user: str = Depends(require_roles(*CBOM_USAGE_READERS))) -> Any:
    """Two snapshots and a window in, network patterns out — never an incident.

    Review item 19: a TLS downgrade, a certificate mutation, a new endpoint and a new
    process in one window are a ``CORRELATED_PATTERN`` classified
    ``SUSPICIOUS_ACTIVITY``. The ceiling is deliberate — the shared attack-pattern
    engine reserves level 4 for combinations corroborated across independent planes —
    so ``SECURITY_INCIDENT`` is only ever named in ``never``.
    """
    from cbom import nbom_history as nh
    from cbom import network_patterns as npat

    try:
        comparison = nh.compare(body.before, body.after)
        window = npat.signals(comparison, processes=body.processes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    result = npat.correlate(window)
    return {**result, "signals": window["signals"], "window": window["window"],
            "summary": npat.summary(result)}


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
