"""Universal Cryptography Scanner — shared models (§1–§36).

Deterministic, catalog-driven types for the whole crypto engine: evidence,
observations, classifications, quantum status, readiness, agility and the
§29 explainable finding shape. No AI anywhere: every verdict is a pure
function of evidence and explicit tables.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# enums
# --------------------------------------------------------------------------- #

class EvidenceType(str, Enum):
    """One evidence class feeding the fusion engine (§28)."""
    AST = "AST"                      # source API call / import
    BINARY = "BINARY"                # symbols / imports / constants in binaries
    RUNTIME = "RUNTIME"              # observed loaded library / exercised API
    LIBRARY = "LIBRARY"              # library fingerprint / dependency
    PROTOCOL = "PROTOCOL"            # TLS/SSH/IPsec handshake or configuration
    CONFIG = "CONFIG"                # configuration file / policy
    CERTIFICATE = "CERTIFICATE"      # certificate analysis
    KEY_METADATA = "KEY_METADATA"    # key metadata (never secret material)
    TRUST_STORE = "TRUST_STORE"      # trust store / CA analysis
    DEPENDENCY = "DEPENDENCY"        # package dependency manifest


class Classification(str, Enum):
    """§17 crypto classification for every finding."""
    ALGORITHM = "ALGORITHM"
    PRIMITIVE = "PRIMITIVE"
    PROTOCOL = "PROTOCOL"
    IMPLEMENTATION = "IMPLEMENTATION"
    KEY = "KEY"
    CERTIFICATE = "CERTIFICATE"
    CRYPTO_LIBRARY = "CRYPTO_LIBRARY"
    CRYPTO_PROVIDER = "CRYPTO_PROVIDER"
    HARDWARE_CAPABILITY = "HARDWARE_CAPABILITY"
    CONFIGURATION = "CONFIGURATION"


class Operation(str, Enum):
    HASH = "hash"
    HMAC = "hmac"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    KEYGEN = "key_generation"
    KEYEXCHANGE = "key_exchange"
    KDF = "kdf"
    RANDOM = "random"
    CERTIFICATE_HANDLING = "certificate_handling"
    TLS_CONFIG = "tls_configuration"
    KEY_STORAGE = "key_storage"
    UNKNOWN = "unknown"


class QuantumStatus(str, Enum):
    """§18/§19 quantum classification of a crypto asset."""
    CLASSICAL = "CLASSICAL"
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    QUANTUM_SAFE = "QUANTUM_SAFE"
    HYBRID = "HYBRID"
    PQC_READY = "PQC_READY"
    PQC_UNKNOWN = "PQC_UNKNOWN"


class ConfidenceBand(str, Enum):
    """§28 confidence bands."""
    CONFIRMED = "CONFIRMED"              # 95–100
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"  # 85–94
    MEDIUM = "MEDIUM"                    # 70–84
    LOW = "LOW"                          # 50–69
    UNCONFIRMED = "UNCONFIRMED"          # <50


class ImplementationClass(str, Enum):
    """§24 custom-crypto classification."""
    KNOWN_LIBRARY = "KNOWN_LIBRARY"
    KNOWN_IMPLEMENTATION = "KNOWN_IMPLEMENTATION"
    MODIFIED_IMPLEMENTATION = "MODIFIED_IMPLEMENTATION"
    CUSTOM_IMPLEMENTATION = "CUSTOM_IMPLEMENTATION"
    UNKNOWN = "UNKNOWN"


class LifecycleStatus(str, Enum):
    """§2 NIST lifecycle/status of an algorithm — never a static PQC boolean."""
    STANDARDIZED = "STANDARDIZED"                    # final standard (e.g. FIPS 203)
    SELECTED_FOR_STANDARDIZATION = "SELECTED_FOR_STANDARDIZATION"  # e.g. HQC
    CANDIDATE = "CANDIDATE"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"
    REJECTED = "REJECTED"


class MigrationPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    SUPPRESSED = "SUPPRESSED"
    REVIEWED = "REVIEWED"


class CryptoEventType(str, Enum):
    """§34 live crypto event types."""
    CERT_RENEWED = "CERT_RENEWED"
    CERT_NEW = "CERT_NEW"
    CERT_EXPIRING = "CERT_EXPIRING"
    CERT_REVOKED = "CERT_REVOKED"
    ALGORITHM_DETECTED = "ALGORITHM_DETECTED"
    ALGORITHM_REMOVED = "ALGORITHM_REMOVED"
    LIBRARY_UPGRADED = "LIBRARY_UPGRADED"
    TLS_POLICY_CHANGED = "TLS_POLICY_CHANGED"
    KEY_ROTATED = "KEY_ROTATED"
    KEY_EXPIRED = "KEY_EXPIRED"
    PQC_CAPABILITY_CHANGED = "PQC_CAPABILITY_CHANGED"
    PROTOCOL_CHANGED = "PROTOCOL_CHANGED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    IMPLEMENTATION_CHANGED = "IMPLEMENTATION_CHANGED"
    UNKNOWN_CRYPTO_OPERATION = "UNKNOWN_CRYPTO_OPERATION"


# --------------------------------------------------------------------------- #
# evidence & observations
# --------------------------------------------------------------------------- #

class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: EvidenceType
    detail: str
    location: str = ""
    weight: Optional[float] = None  # filled by the fusion engine (§28)


class CryptoObservation(BaseModel):
    """A single crypto observation after detection + fusion (§3 shape)."""
    model_config = ConfigDict(extra="allow")

    algorithm: str                       # canonical registry name
    primitive: str = ""
    operation: Optional[Operation] = None
    library: Optional[str] = None
    implementation: Optional[str] = None
    provider: Optional[str] = None
    key_size: Optional[int] = None
    curve: Optional[str] = None
    padding: Optional[str] = None
    digest: Optional[str] = None
    protocol: Optional[str] = None
    asset_id: str = "default"
    location: str = ""
    classification: Classification = Classification.ALGORITHM
    quantum_status: QuantumStatus = QuantumStatus.PQC_UNKNOWN
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.0
    band: ConfidenceBand = ConfidenceBand.UNCONFIRMED
    usage: bool = False          # §27: actually exercised?
    capability: bool = False     # §27: supported by hardware/impl?
    source: str = ""             # which detector produced it
    raw: dict[str, Any] = Field(default_factory=dict)

    def evidence_kinds(self) -> set[EvidenceType]:
        return {e.kind for e in self.evidence}


class CryptoFinding(BaseModel):
    """§29 explainable finding — WHAT/WHERE/HOW/WHY/EVIDENCE/CONFIDENCE/IMPACT/RECOMMENDATION."""
    model_config = ConfigDict(extra="allow")

    finding_id: str
    what: str
    where: str
    how_detected: str
    why_classified: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = 0.0
    band: ConfidenceBand = ConfidenceBand.UNCONFIRMED
    impact: str = ""
    recommendation: str = ""
    classification: Classification = Classification.ALGORITHM
    algorithm: str = ""
    operation: Optional[str] = None
    asset_id: str = "default"
    quantum_status: QuantumStatus = QuantumStatus.PQC_UNKNOWN
    migration_priority: Optional[MigrationPriority] = None
    severity: str = "info"
    status: FindingStatus = FindingStatus.OPEN
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


# --------------------------------------------------------------------------- #
# §2 registry entry (extends shared_models.algorithm_registry)
# --------------------------------------------------------------------------- #

class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    algorithm: str
    family: str                      # block-cipher / stream-cipher / aead / hash / mac /
                                     # pke / signature / key-agree / kdf / kem-pqc / signature-pqc / rng
    kind: str = "algorithm"          # algorithm | protocol | curve | mode
    nist_lifecycle: LifecycleStatus = LifecycleStatus.STANDARDIZED
    standard_reference: str = ""     # e.g. "FIPS 203", "FIPS 186-5", "NIST IR 8547"
    quantum_status: QuantumStatus = QuantumStatus.QUANTUM_SAFE
    quantum_impact: str = ""         # "shor" (breaks) / "grover" (halves security) / ""
    key_sizes: tuple[int, ...] = ()
    curves: tuple[str, ...] = ()
    variants: tuple[str, ...] = ()   # e.g. RSA-PKCS1, RSA-PSS; AES-GCM, AES-CBC
    oid: str = ""                    # CycloneDX cryptography registry OID (§35)
    notes: str = ""
