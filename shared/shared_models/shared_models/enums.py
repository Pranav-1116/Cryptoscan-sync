"""Shared enumerations across CryptoScan services."""

from enum import Enum


class ApiType(str, Enum):
    """Type of cryptographic API detected."""
    CIPHER_INSTANCE = "CIPHER_INSTANCE"
    MESSAGE_DIGEST = "MESSAGE_DIGEST"
    KEY_GENERATOR = "KEY_GENERATOR"
    SIGNATURE = "SIGNATURE"
    HARDCODED_KEY = "HARDCODED_KEY"
    KEY_PAIR_GENERATOR = "KEY_PAIR_GENERATOR"
    SECRET_KEY_SPEC = "SECRET_KEY_SPEC"
    KEY_AGREEMENT = "KEY_AGREEMENT"
    MAC = "MAC"
    UNKNOWN = "UNKNOWN"


class Confidence(str, Enum):
    """Confidence level of a detection."""
    HIGH = "HIGH"       # Algorithm from string literal, direct call
    MEDIUM = "MEDIUM"   # Algorithm from local variable (traceable)
    LOW = "LOW"         # Algorithm from parameter/field, reflection


class Purpose(str, Enum):
    """Cryptographic purpose of the detected call."""
    ENCRYPTION = "ENCRYPTION"
    DECRYPTION = "DECRYPTION"
    HASHING = "HASHING"
    SIGNING = "SIGNING"
    VERIFICATION = "VERIFICATION"
    KEY_GENERATION = "KEY_GENERATION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    MAC_GENERATION = "MAC_GENERATION"
    UNKNOWN = "UNKNOWN"


class AlgorithmFamily(str, Enum):
    """Family/category of cryptographic algorithm."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    SIGNATURE = "signature"
    UNKNOWN = "unknown"


class NistDesignation(str, Enum):
    """NIST approval status for cryptographic algorithm."""
    APPROVED = "APPROVED"
    ALLOWED = "ALLOWED"
    DEPRECATED = "DEPRECATED"
    DISALLOWED = "DISALLOWED"
    UNKNOWN = "UNKNOWN"


class ComplianceStatus(str, Enum):
    """Overall compliance status of a finding."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    PENDING = "PENDING"


class DriftType(str, Enum):
    """Type of crypto drift detected."""
    NEW_CRYPTO = "NEW_CRYPTO"
    REMOVED_CRYPTO = "REMOVED_CRYPTO"
    CHANGED_CRYPTO = "CHANGED_CRYPTO"
    DEGRADED_CRYPTO = "DEGRADED_CRYPTO"


class DriftSeverity(str, Enum):
    """Severity of a drift event."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class ScanStatus(str, Enum):
    """Status of a scan session."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStatus(str, Enum):
    """Status of a scan job in the queue."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DriftResolutionStatus(str, Enum):
    """Resolution status of a drift event."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"