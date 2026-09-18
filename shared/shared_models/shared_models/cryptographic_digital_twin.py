"""
Cryptographic Digital Twin — Real Product Models
Deterministic, No AI, Fully Auditable, Isolated
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json
import uuid

def canon(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

class TwinEntityType(str, Enum):
    CRYPTO_ASSET = "CryptoAsset"
    SYSTEM = "System"
    NETWORK_ENDPOINT = "NetworkEndpoint"
    CERTIFICATE = "Certificate"
    KEY = "Key"
    BUSINESS_PROCESS = "BusinessProcess"
    VENDOR = "Vendor"
    PROTOCOL = "Protocol"
    LIBRARY = "Library"
    CONTAINER = "Container"

class RelationshipType(str, Enum):
    USES = "USES"
    CALLS = "CALLS"
    SUPPORTS = "SUPPORTS"
    OWNED_BY = "OWNED_BY"
    MUST_COMPLY_WITH = "MUST_COMPLY_WITH"
    DEPENDS_ON_VENDOR = "DEPENDS_ON_VENDOR"
    EXPOSES = "EXPOSES"
    PROTECTED_BY = "PROTECTED_BY"
    ISSUED_BY = "ISSUED_BY"
    HAS_KEY = "HAS_KEY"
    STORED_IN = "STORED_IN"
    PROTECTS = "PROTECTS"
    PROVIDED_BY = "PROVIDED_BY"
    PROVIDES = "PROVIDES"
    DEPENDS_ON = "DEPENDS_ON"
    CONTAINS = "CONTAINS"
    RUNS_ON = "RUNS_ON"

class ScenarioType(str, Enum):
    MIGRATION_SIMULATION = "MIGRATION_SIMULATION"
    POLICY_SIMULATION = "POLICY_SIMULATION"
    ATTACK_SIMULATION = "ATTACK_SIMULATION"
    FAILURE_SIMULATION = "FAILURE_SIMULATION"
    QUANTUM_SIMULATION = "QUANTUM_SIMULATION"
    REGULATORY_SIMULATION = "REGULATORY_SIMULATION"
    CHAOS_SIMULATION = "CHAOS_SIMULATION"
    CAPACITY_SIMULATION = "CAPACITY_SIMULATION"
    VENDOR_SIMULATION = "VENDOR_SIMULATION"
    CUSTOM_SIMULATION = "CUSTOM_SIMULATION"

class ChangeType(str, Enum):
    ALGORITHM_SWAP = "ALGORITHM_SWAP"
    KEY_ROTATION = "KEY_ROTATION"
    CERT_RENEWAL = "CERT_RENEWAL"
    PROTOCOL_UPGRADE = "PROTOCOL_UPGRADE"
    LIBRARY_UPGRADE = "LIBRARY_UPGRADE"
    POLICY_ENABLE = "POLICY_ENABLE"
    POLICY_DISABLE = "POLICY_DISABLE"
    SYSTEM_DECOMMISSION = "SYSTEM_DECOMMISSION"
    VENDOR_REPLACE = "VENDOR_REPLACE"
    ADD_MTLS = "ADD_MTLS"
    ENABLE_PQC = "ENABLE_PQC"
    HYBRID_MODE = "HYBRID_MODE"

@dataclass
class TwinEntity:
    id: str
    entity_type: TwinEntityType
    name: str
    system_id: str
    properties: Dict[str, Any] = field(default_factory=dict)
    crypto_properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    compliance_status: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = sha256_hex(canon({
                "id": self.id,
                "type": self.entity_type,
                "name": self.name,
                "system_id": self.system_id,
                "props": self.properties
            }))

@dataclass
class TwinRelationship:
    id: str
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class TwinSnapshot:
    snapshot_id: str
    timestamp: str
    entities: List[TwinEntity]
    relationships: List[TwinRelationship]
    merkle_root: str
    previous_hash: str
    hash: str
    signature: str = ""
    entity_count: int = 0
    relationship_count: int = 0

    def __post_init__(self):
        self.entity_count = len(self.entities)
        self.relationship_count = len(self.relationships)

@dataclass
class SimulationChange:
    change_type: ChangeType
    target_id: Optional[str] = None
    target_type: Optional[str] = None
    from_value: Optional[str] = None
    to_value: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SimulationRequest:
    scenario_type: ScenarioType
    name: str
    scope: Dict[str, Any] = field(default_factory=dict)
    changes: List[SimulationChange] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    assumptions: Dict[str, Any] = field(default_factory=dict)
    at_timestamp: Optional[str] = None
    created_by: str = "system"

@dataclass
class ImpactAnalysis:
    direct_systems: int
    downstream_systems: int
    incompatible_systems: int
    incompatible_list: List[str]
    blast_radius: Dict[str, Any]
    affected_entities: List[str]
    affected_relationships: List[str]
    propagation_path: List[List[str]]

@dataclass
class EffortEstimation:
    total_hours: int
    critical_path_weeks: int
    team_required: int
    breakdown: Dict[str, int]

@dataclass
class CostEstimation:
    engineering: int
    testing: int
    downtime: int
    total: int
    breakdown: Dict[str, int]

@dataclass
class RiskAssessment:
    before_score: float
    after_score: float
    improvement: float
    before_level: str
    after_level: str
    factors: Dict[str, float]

@dataclass
class SimulationResult:
    simulation_id: str
    scenario_type: ScenarioType
    name: str
    scope: Dict[str, Any]
    changes: List[SimulationChange]
    impact: ImpactAnalysis
    effort: EffortEstimation
    cost: CostEstimation
    risk: RiskAssessment
    timeline: Dict[str, Any]
    recommendations: List[str]
    compliance_impact: Dict[str, Any]
    report: str
    deterministic: bool = True
    isolation: str = "simulation runs on cloned twin state fully isolated"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hash: str = ""
