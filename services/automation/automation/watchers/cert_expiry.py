"""Deterministic certificate-expiry watcher (no AI/ML).

Classifies every certificate's lifecycle posture from pure date arithmetic and
emits deterministic, thresholded alerts that the automation engine consumes:

    already expired  -> CRITICAL  (event certificate_expiring, immediate action)
    <= 7 days        -> CRITICAL  (high priority renewal)
    <= 20 days       -> WARN / HIGH
    valid            -> OK

It also flags weak certificates (short key, broken signature algorithm,
self-signed in production). No inference — fixed thresholds and policy lookups.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

#: deterministic thresholds (days)
WARN_DAYS = 20
HIGH_DAYS = 7

WEAK_SIGNATURE_ALGORITHMS = frozenset({
    "md5", "sha1", "md2", "md4",
})
MIN_RSA_BITS = 2048
MIN_EC_BITS = 224


class CertState(str, Enum):
    EXPIRED = "EXPIRED"
    CRITICAL = "RENEW_IMMEDIATELY"
    WARN = "RENEW_SOON"
    OK = "VALID"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CertAssessment:
    cert_id: str
    days_remaining: int | None
    state: CertState
    severity: Severity
    reasons: list[str] = field(default_factory=list)

    @property
    def alert(self) -> bool:
        return self.state in (CertState.EXPIRED, CertState.CRITICAL, CertState.WARN)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cert_id": self.cert_id,
            "days_remaining": self.days_remaining,
            "state": self.state.value,
            "severity": self.severity.value,
            "reasons": self.reasons,
            "alert": self.alert,
            "automation_event": "certificate_expiring" if self.alert else None,
        }


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def assess_certificate(cert: dict[str, Any], *, now: datetime | None = None) -> CertAssessment:
    """Assess one certificate (expiry + crypto strength), deterministically."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cert_id = str(cert.get("id") or cert.get("fingerprint_sha256")
                  or cert.get("fingerprint") or "?")
    reasons: list[str] = []

    not_after = _parse_dt(cert.get("not_after") or cert.get("expires_at"))
    days = None
    state = CertState.UNKNOWN
    severity = Severity.LOW

    if not_after is not None:
        days = int((not_after - now).total_seconds() // 86400)
        if days < 0:
            state = CertState.EXPIRED
            severity = Severity.CRITICAL
            reasons.append(f"certificate expired {-days} day(s) ago")
        elif days <= HIGH_DAYS:
            state = CertState.CRITICAL
            severity = Severity.CRITICAL
            reasons.append(f"certificate expires in {days} day(s) (≤{HIGH_DAYS})")
        elif days <= WARN_DAYS:
            state = CertState.WARN
            severity = Severity.HIGH
            reasons.append(f"certificate expires in {days} day(s) (≤{WARN_DAYS})")
        else:
            state = CertState.OK
            severity = Severity.INFO

    # strength checks can only raise severity, never lower it
    sig = str(cert.get("signature_algorithm") or cert.get("public_key_algorithm") or "").lower()
    if any(weak in sig for weak in WEAK_SIGNATURE_ALGORITHMS):
        reasons.append(f"weak/broken signature algorithm {sig or 'unknown'}")
        severity = Severity.CRITICAL
        if state == CertState.OK:
            state = CertState.WARN
    key_algo = str(cert.get("public_key_algorithm") or "").lower()
    key_size = cert.get("public_key_size")
    try:
        key_size_int = int(key_size) if key_size is not None else None
    except (TypeError, ValueError):
        key_size_int = None
    if key_size_int is not None:
        if "rsa" in key_algo and key_size_int < MIN_RSA_BITS:
            reasons.append(f"RSA key {key_size_int} bits below {MIN_RSA_BITS}")
            severity = Severity.CRITICAL
            if state == CertState.OK:
                state = CertState.WARN
        elif ("ec" in key_algo or "ecdsa" in key_algo) and key_size_int < MIN_EC_BITS:
            reasons.append(f"EC key {key_size_int} bits below {MIN_EC_BITS}")
            severity = Severity.CRITICAL
            if state == CertState.OK:
                state = CertState.WARN
    if cert.get("is_self_signed") and str(cert.get("environment", "production")).lower() not in (
            "dev", "development", "test", "staging"):
        reasons.append("self-signed certificate in production")
        if severity in (Severity.LOW, Severity.INFO):
            severity = Severity.MEDIUM
        if state == CertState.OK:
            state = CertState.WARN

    if not_after is None and not reasons:
        state = CertState.UNKNOWN
        severity = Severity.INFO
        reasons.append("no expiry date available")

    return CertAssessment(cert_id=cert_id, days_remaining=days, state=state,
                          severity=severity, reasons=reasons)


@dataclass
class CertWatchReport:
    total: int = 0
    expired: int = 0
    critical: int = 0
    warn: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total, "expired": self.expired,
            "critical": self.critical, "warn": self.warn,
            "alerts": self.alerts,
        }


def watch_certificates(certs: Iterable[dict[str, Any]], *,
                       now: datetime | None = None) -> CertWatchReport:
    """Assess a batch and return only the actionable alerts (deterministic)."""
    report = CertWatchReport()
    for cert in certs:
        a = assess_certificate(cert, now=now)
        report.total += 1
        if a.state == CertState.EXPIRED:
            report.expired += 1
        elif a.state == CertState.CRITICAL:
            report.critical += 1
        elif a.state == CertState.WARN:
            report.warn += 1
        if a.alert:
            report.alerts.append(a.as_dict())
    # most urgent first (expired, then least days remaining)
    report.alerts.sort(key=lambda a: (
        a["state"] != CertState.EXPIRED.value,
        a["days_remaining"] if a["days_remaining"] is not None else 99999,
    ))
    return report
