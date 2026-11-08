"""OS & Kernel Intelligence API
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md).

The API accepts and serves READ-ONLY collection packages (Tier 1, §11).
Collection itself runs on the host being observed; this service never
reads arbitrary paths on behalf of a caller and never performs kernel
instrumentation. Every capability row carries
runtime_usage_confirmed=false: a registered kernel implementation is
never proof of application usage (§2.2). Findings are detections, not
verdicts (§1).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.os_intelligence_repository import (
    OSIntelligenceRepository,
)
from os_intelligence.bom import BOM_KINDS, build_bom
from os_intelligence.rules import CATALOGUE, evaluate as evaluate_rules

router = APIRouter(prefix="/os-intelligence",
                   tags=["os-kernel-intelligence"])


# --- request/response models -----------------------------------------

class CollectionSubmission(BaseModel):
    """A completed read-only collection package (§7 mode A shape:
    metadata + digests; never secrets)."""
    tenant_id: str = Field(..., min_length=1, max_length=120)
    asset_id: str = Field(..., min_length=1, max_length=80)
    inventory: Dict[str, Any] = Field(
        ...,
        description="OSInventory.as_dict() output or an equivalent "
                    "signed collection package; metadata only — key "
                    "material must never be present (§7)")


class CollectionAccepted(BaseModel):
    collection_id: str
    asset_id: str
    outcome: str
    note: str = ("recorded as a read-only snapshot; runtime usage is "
                 "never confirmed by OS collection (§2.2)")


class AssetOut(BaseModel):
    asset_id: str
    collection_id: str
    kernel_name: str
    kernel_release: str
    kernel_version: str
    machine: str
    os_pretty_name: str
    os_id: str
    os_version_id: str
    arch: str
    cmdline: str
    tainted_flags: str
    tainted_meanings: List[str] = []
    environment_development_only: bool
    qualification_note: Optional[str] = None
    collector_version: str
    notes: List[str] = []
    collected_at: str


class AssetListOut(BaseModel):
    assets: List[AssetOut]
    note: str = ("each record describes ONE observed host — one "
                 "successful collection is never enterprise "
                 "qualification (§12)")


class CapabilityOut(BaseModel):
    algorithm: str
    driver: Optional[str] = None
    type: Optional[str] = None
    module: Optional[str] = None
    priority: Optional[int] = None
    blocksize: Optional[int] = None
    digestsize: Optional[int] = None
    key_size_range: Optional[List[Optional[int]]] = None
    selftest: Optional[str] = None
    hardware_accelerated: Optional[bool] = None
    runtime_usage_confirmed: bool = False
    parse_notes: List[str] = []


class CapabilityListOut(BaseModel):
    capabilities: List[CapabilityOut]
    note: str = ("inventory of REGISTERED kernel crypto "
                 "implementations — not proof of runtime use (§2.2); "
                 "the generic algorithm name and the implementation "
                 "driver are distinct; unknown key sizes are never "
                 "guessed")


class ModuleOut(BaseModel):
    name: str
    size: Optional[int] = None
    refcount: Optional[int] = None
    used_by: List[str] = []
    state: str


class ModuleListOut(BaseModel):
    modules: List[ModuleOut]
    note: str = ("loaded-module inventory — a missing module row is "
                 "never evidence that a feature is unavailable; it may "
                 "be built into the kernel (§2.1)")


class ConfigFlagOut(BaseModel):
    flag: str
    value: str
    explicitly_disabled: bool


class ConfigFlagListOut(BaseModel):
    flags: List[ConfigFlagOut]
    note: str = ("only recorded states appear as rows — a flag absent "
                 "from the config source is never reported as "
                 "'disabled' (§2.1)")


class StorageFactOut(BaseModel):
    device: str
    fstype: str
    metadata: Dict[str, Any] = {}
    notes: List[str] = []


class StorageListOut(BaseModel):
    storage: List[StorageFactOut]
    note: str = ("disk-encryption METADATA only — no recovery keys, key "
                 "files or secrets are collected (§7)")


class TrustFactOut(BaseModel):
    subject: str
    state: str
    evidence_class: str
    metadata: Dict[str, Any] = {}
    notes: List[str] = []


class TrustListOut(BaseModel):
    hardware_trust: List[TrustFactOut]
    note: str = ("device presence is metadata, never a trust verdict "
                 "(§12)")


class FindingOut(BaseModel):
    finding_type: str
    host_id: Optional[str] = None
    algorithm: str = ""
    implementation: str = ""
    evidence_source: str = ""
    observation_type: str
    runtime_usage_confirmed: bool = False
    evidence_class: str
    severity_label: Optional[str] = None
    severity_factors: Optional[Dict[str, Any]] = None
    risk_model_version: Optional[str] = None
    details: Dict[str, Any] = {}
    limitations: List[str] = []


class FindingListOut(BaseModel):
    findings: List[FindingOut]
    note: str = ("detections, not verdicts (§1); severity is computed "
                 "with preserved factors and a model version — never "
                 "named by hand; a collection with no findings is never "
                 "'no issues'")


class BomComponentOut(BaseModel):
    type: str
    name: str
    version: str = ""
    properties: Dict[str, Any] = {}


class BomRelationshipOut(BaseModel):
    source: str
    relationship: str
    target: str
    provenance: str
    limitations: List[str] = []


class BomOut(BaseModel):
    schema_name: str = Field(..., alias="schema")
    kind: str
    subject: str
    components: List[BomComponentOut] = []
    relationships: List[BomRelationshipOut] = []
    coverage: Dict[str, Any] = {}
    note: str

    model_config = {"populate_by_name": True}


class RuleFindingOut(BaseModel):
    finding_type: str
    host_id: Optional[str] = None
    algorithm: str = ""
    implementation: str = ""
    evidence_source: str = ""
    observation_type: str
    runtime_usage_confirmed: bool = False
    evidence_class: str
    severity_label: Optional[str] = None
    severity_factors: Optional[Dict[str, Any]] = None
    risk_model_version: Optional[str] = None
    details: Dict[str, Any] = {}
    limitations: List[str] = []


class RuleResultOut(BaseModel):
    rule_id: str
    detection: str
    potential_impact: str
    status: str
    evaluation_note: str
    findings: List[RuleFindingOut] = []


class RuleCatalogueOut(BaseModel):
    rules: List[Dict[str, str]]
    note: str = ("OS-CRYPTO detections, not automatic vulnerability "
                 "verdicts (§9); severity is computed (R=f(S,E,X,B,C)) "
                 "with preserved factors — never a multiplied "
                 "'scientifically validated score'; a not_evaluable "
                 "rule is never a clean result (§2.1)")


class RuleEvaluationOut(BaseModel):
    rule_model_version: str
    results: List[RuleResultOut]
    note: str


class CoverageOut(BaseModel):
    sources_attempted: List[str] = []
    sources_collected: List[str] = []
    sources_unavailable: List[Dict[str, str]] = []
    source_digests: Dict[str, str] = {}
    note: Optional[str] = None


def _repo(db: Session) -> OSIntelligenceRepository:
    return OSIntelligenceRepository(db)


# --- routes ----------------------------------------------------------

@router.post("/collections", response_model=CollectionAccepted,
             status_code=201)
def submit_collection(body: CollectionSubmission, response: Response,
                      db: Session = Depends(get_db_session),
                      user=Depends(get_current_user)) -> CollectionAccepted:
    """Record one completed read-only collection.

    The package is metadata: identities, registrations, states,
    digests. Key material must never appear in a collection package
    (§7) — and runtime usage is never confirmed by it (§2.2)."""
    inventory = body.inventory
    if not isinstance(inventory.get("identity", None), dict):
        raise HTTPException(
            status_code=422,
            detail="collection package must carry an identity section — "
                   "content is validated, never assumed")
    coverage = inventory.get("coverage")
    if not isinstance(coverage, dict):
        raise HTTPException(
            status_code=422,
            detail="collection package must carry a coverage section — "
                   "an unverifiable package is never recorded as valid "
                   "(§2.1)")
    # Run the OS-CRYPTO catalogue over the collected inventory: the
    # results are detections, never verdicts (§9), and every finding
    # carries its computed severity factors. The submission body's own
    # findings are preserved; rule findings are appended.
    rule_report = evaluate_rules(inventory)
    rule_findings = [f for r in rule_report.results for f in r.findings]
    inventory = dict(inventory)
    inventory["findings"] = list(inventory.get("findings") or []) + \
        rule_findings
    result = _repo(db).record_collection(
        tenant_id=body.tenant_id,
        asset_id=body.asset_id,
        inventory=inventory)
    response.status_code = 201
    return CollectionAccepted(**result)


@router.get("/assets/{asset_id}/bom", response_model=BomOut)
def asset_bom(asset_id: str, kind: str = Query("techbom"),
              tenant_id: str = Query(...),
              db: Session = Depends(get_db_session),
              user=Depends(get_current_user)) -> BomOut:
    """Project one recorded collection into the shared BOM ecosystem
    (§15 step 6): sbom, cbom, hbom or techbom. Components are
    registrations and metadata — never proof of runtime use; the
    engine emits NO 'uses' edge (§8). An unknown kind is refused,
    never guessed."""
    if kind not in BOM_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"unknown BOM kind {kind!r} — expected one of "
                   f"{list(BOM_KINDS)}; content is validated, never "
                   "assumed")
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    asset = repo.get_asset(tenant_id, asset_id)
    inventory = {
        "host_id": asset_id,
        "identity": asset or {},
        "crypto_api": repo.list_capabilities(tenant_id, collection_id),
        "modules": repo.list_modules(tenant_id, collection_id),
        "hardware_trust": repo.list_trust(tenant_id, collection_id),
        "coverage": repo.get_coverage(tenant_id, collection_id) or {},
    }
    bom = build_bom(kind, inventory).as_dict()
    return BomOut(**bom)


@router.get("/rules", response_model=RuleCatalogueOut)
def rule_catalogue(user=Depends(get_current_user)) -> RuleCatalogueOut:
    """The OS-CRYPTO-001…018 catalogue (§9)."""
    return RuleCatalogueOut(
        rules=[{"rule_id": r[0], "detection": r[1],
                "potential_impact": r[2]} for r in CATALOGUE])


@router.get("/assets/{asset_id}/rule-evaluation",
            response_model=RuleEvaluationOut)
def asset_rule_evaluation(asset_id: str, tenant_id: str = Query(...),
                          db: Session = Depends(get_db_session),
                          user=Depends(get_current_user)
                          ) -> RuleEvaluationOut:
    """Re-evaluate the catalogue over the asset's latest recorded
    collection. Results are detections, never verdicts."""
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    coverage = repo.get_coverage(tenant_id, collection_id)
    asset = repo.get_asset(tenant_id, asset_id)
    inventory = {
        "host_id": asset_id,
        "identity": asset or {},
        "crypto_api": repo.list_capabilities(tenant_id, collection_id),
        "modules": repo.list_modules(tenant_id, collection_id),
        "config_flags": {f["flag"]: f["value"] for f in
                         repo.list_config_flags(tenant_id, collection_id)},
        "storage": repo.list_storage(tenant_id, collection_id),
        "hardware_trust": repo.list_trust(tenant_id, collection_id),
        "coverage": coverage or {},
    }
    report = evaluate_rules(inventory)
    return RuleEvaluationOut(**report.as_dict())


@router.get("/assets", response_model=AssetListOut)
def list_assets(tenant_id: str = Query(...),
                db: Session = Depends(get_db_session),
                user=Depends(get_current_user)) -> AssetListOut:
    return AssetListOut(assets=_repo(db).list_assets(tenant_id))


@router.get("/assets/{asset_id}", response_model=AssetOut)
def asset_details(asset_id: str, tenant_id: str = Query(...),
                  db: Session = Depends(get_db_session),
                  user=Depends(get_current_user)) -> AssetOut:
    record = _repo(db).get_asset(tenant_id, asset_id)
    if record is None:
        raise HTTPException(status_code=404,
                            detail="no collection recorded for this "
                                   "asset — a missing asset is never a "
                                   "clean asset")
    return AssetOut(**record)


def _collection_or_404(repo: OSIntelligenceRepository, tenant_id: str,
                       asset_id: str) -> str:
    collection_id = repo.latest_collection(tenant_id, asset_id)
    if collection_id is None:
        raise HTTPException(status_code=404,
                            detail="no collection recorded for this "
                                   "asset — a missing asset is never a "
                                   "clean asset")
    return collection_id


@router.get("/assets/{asset_id}/crypto-capabilities",
            response_model=CapabilityListOut)
def asset_capabilities(asset_id: str, tenant_id: str = Query(...),
                       db: Session = Depends(get_db_session),
                       user=Depends(get_current_user)
                       ) -> CapabilityListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return CapabilityListOut(
        capabilities=[CapabilityOut(**c) for c in
                      repo.list_capabilities(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/modules", response_model=ModuleListOut)
def asset_modules(asset_id: str, tenant_id: str = Query(...),
                  db: Session = Depends(get_db_session),
                  user=Depends(get_current_user)) -> ModuleListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return ModuleListOut(
        modules=[ModuleOut(**m) for m in
                 repo.list_modules(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/config-flags",
            response_model=ConfigFlagListOut)
def asset_config_flags(asset_id: str, tenant_id: str = Query(...),
                       db: Session = Depends(get_db_session),
                       user=Depends(get_current_user)
                       ) -> ConfigFlagListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return ConfigFlagListOut(
        flags=[ConfigFlagOut(**f) for f in
               repo.list_config_flags(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/storage", response_model=StorageListOut)
def asset_storage(asset_id: str, tenant_id: str = Query(...),
                  db: Session = Depends(get_db_session),
                  user=Depends(get_current_user)) -> StorageListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return StorageListOut(
        storage=[StorageFactOut(**s) for s in
                 repo.list_storage(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/hardware-trust",
            response_model=TrustListOut)
def asset_hardware_trust(asset_id: str, tenant_id: str = Query(...),
                         db: Session = Depends(get_db_session),
                         user=Depends(get_current_user)) -> TrustListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return TrustListOut(
        hardware_trust=[TrustFactOut(**t) for t in
                        repo.list_trust(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/findings", response_model=FindingListOut)
def asset_findings(asset_id: str, tenant_id: str = Query(...),
                   db: Session = Depends(get_db_session),
                   user=Depends(get_current_user)) -> FindingListOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    return FindingListOut(
        findings=[FindingOut(**f) for f in
                  repo.list_findings(tenant_id, collection_id)])


@router.get("/assets/{asset_id}/coverage", response_model=CoverageOut)
def asset_coverage(asset_id: str, tenant_id: str = Query(...),
                   db: Session = Depends(get_db_session),
                   user=Depends(get_current_user)) -> CoverageOut:
    repo = _repo(db)
    collection_id = _collection_or_404(repo, tenant_id, asset_id)
    coverage = repo.get_coverage(tenant_id, collection_id)
    if coverage is None:
        raise HTTPException(status_code=404,
                            detail="coverage record unavailable — "
                                   "recorded as unavailable, never as "
                                   "complete (§2.1)")
    return CoverageOut(**coverage)
