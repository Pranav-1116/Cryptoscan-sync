"""RevocationStatus, ExpiryStatus."""

from __future__ import annotations

from enum import Enum


class RevocationStatus(str, Enum):
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class ExpiryStatus(str, Enum):
    VALID = "VALID"
    EXPIRING_SOON = "EXPIRING_SOON"
    EXPIRING_CRITICAL = "EXPIRING_CRITICAL"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"
