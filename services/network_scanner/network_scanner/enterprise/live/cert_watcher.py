"""Live Certificate Monitoring.

A dedicated certificate watcher detects:

    New Certificate · Certificate Renewed · Certificate Revoked ·
    Certificate Expiring · Certificate Reused · Algorithm Changed

and automatically updates the certificate graph, dependency graph, live
CBOM, PQC risk score and compliance status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Iterable

CERT_EVENTS = (
    "NEW_CERTIFICATE",
    "CERTIFICATE_RENEWED",
    "CERTIFICATE_REVOKED",
    "CERTIFICATE_EXPIRING",
    "CERTIFICATE_REUSED",
    "ALGORITHM_CHANGED",
)


@dataclass
class CertChange:
    fingerprint: str
    kind: str
    subject: str = ""
    issuer: str = ""
    previous: dict[str, Any] = field(default_factory=dict)
    current: dict[str, Any] = field(default_factory=dict)
    affected_endpoints: list[str] = field(default_factory=list)
    updates: list[str] = field(default_factory=list)
    observed_at: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"fingerprint": self.fingerprint, "kind": self.kind,
                "subject": self.subject, "issuer": self.issuer,
                "previous": dict(self.previous),
                "current": dict(self.current),
                "affected_endpoints": list(self.affected_endpoints),
                "updates": list(self.updates),
                "observed_at": self.observed_at}


class CertificateWatcher:
    """Tracks known certificates and classifies lifecycle changes.

    ``endpoint_index`` maps certificate fingerprint → list of endpoints that
    present it (so a rotation can enumerate consumers).
    """

    def __init__(self, *,
                 clock: Callable[[], Any] | None = None,
                 expiry_horizon_days: int = 30) -> None:
        self._known: dict[str, dict[str, Any]] = {}
        self._changes: list[CertChange] = []
        self._endpoint_index: dict[str, list[str]] = {}
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._horizon = timedelta(days=expiry_horizon_days)

    def changes(self) -> list[CertChange]:
        return list(self._changes)

    def known(self) -> dict[str, dict[str, Any]]:
        return {fp: dict(cert) for fp, cert in self._known.items()}

    def associate(self, fingerprint: str, endpoint: str) -> None:
        self._endpoint_index.setdefault(fingerprint, [])
        if endpoint not in self._endpoint_index[fingerprint]:
            self._endpoint_index[fingerprint].append(endpoint)

    def endpoints_for(self, fingerprint: str) -> list[str]:
        return list(self._endpoint_index.get(fingerprint, []))

    # ------------------------------------------------------------- observe

    def observe(self, cert: dict[str, Any], *,
                endpoints: Iterable[str] = (),
                revoked: Iterable[str] = (),
                now: Any | None = None) -> list[CertChange]:
        """Classify a certificate observation against the known set.

        Returns the list of lifecycle changes for this certificate.
        """
        now = now if now is not None else self._clock()
        fingerprint = str(cert.get("fingerprint_sha256") or cert.get("fingerprint") or "")
        if not fingerprint:
            return []
        affected = list(endpoints) or self.endpoints_for(fingerprint)
        for endpoint in affected:
            self.associate(fingerprint, endpoint)

        previous = self._known.get(fingerprint)
        changes: list[CertChange] = []
        if previous is None:
            change = CertChange(
                fingerprint=fingerprint, kind="NEW_CERTIFICATE",
                subject=str(cert.get("subject") or ""),
                issuer=str(cert.get("issuer") or ""),
                previous={}, current=dict(cert),
                affected_endpoints=affected,
                updates=["certificate_graph", "dependency_graph", "live_cbom",
                         "pqc_risk", "compliance_status"],
                observed_at=now)
            self._changes.append(change)
            changes.append(change)
        else:
            diff = {k: v for k, v in cert.items() if v != previous.get(k)}
            self._classify_existing(fingerprint, previous, cert, diff, affected,
                                    now, changes)

        self._known[fingerprint] = dict(cert)

        # revoked check
        if fingerprint in set(revoked):
            change = CertChange(
                fingerprint=fingerprint, kind="CERTIFICATE_REVOKED",
                subject=str(cert.get("subject") or ""),
                issuer=str(cert.get("issuer") or ""),
                previous=dict(self._known.get(fingerprint, {})),
                current=dict(cert),
                affected_endpoints=affected,
                updates=["certificate_graph", "dependency_graph", "live_cbom",
                         "pqc_risk", "compliance_status"],
                observed_at=now)
            self._changes.append(change)
            changes.append(change)

        # expiring check
        if self._is_expiring(cert, now):
            change = CertChange(
                fingerprint=fingerprint, kind="CERTIFICATE_EXPIRING",
                subject=str(cert.get("subject") or ""),
                issuer=str(cert.get("issuer") or ""),
                previous={}, current=dict(cert),
                affected_endpoints=affected,
                updates=["live_cbom", "pqc_risk", "compliance_status"],
                observed_at=now)
            self._changes.append(change)
            changes.append(change)
        return changes

    # ------------------------------------------------------------- classify

    def _classify_existing(self, fingerprint: str, previous: dict[str, Any],
                           current: dict[str, Any], diff: dict[str, Any],
                           affected: list[str], now: Any,
                           out: list[CertChange]) -> None:
        algorithm_changed = any(
            k in ("signature_algorithm", "public_key_algorithm", "key_algorithm")
            for k in diff)
        renewed = diff.get("not_valid_after") is not None or diff.get("serial_number") is not None
        if algorithm_changed:
            out.append(CertChange(
                fingerprint=fingerprint, kind="ALGORITHM_CHANGED",
                subject=str(current.get("subject") or ""),
                issuer=str(current.get("issuer") or ""),
                previous=dict(previous), current=dict(current),
                affected_endpoints=affected,
                updates=["live_cbom", "pqc_risk", "compliance_status"],
                observed_at=now))
        if renewed:
            out.append(CertChange(
                fingerprint=fingerprint, kind="CERTIFICATE_RENEWED",
                subject=str(current.get("subject") or ""),
                issuer=str(current.get("issuer") or ""),
                previous=dict(previous), current=dict(current),
                affected_endpoints=affected,
                updates=["certificate_graph", "dependency_graph", "live_cbom",
                         "pqc_risk", "compliance_status"],
                observed_at=now))

    def _is_expiring(self, cert: dict[str, Any], now: Any) -> bool:
        raw = cert.get("not_valid_after") or cert.get("expires_on")
        if raw is None:
            return False
        if hasattr(raw, "isoformat"):
            expires = raw
        else:
            try:
                expires = datetime.fromisoformat(str(raw))
            except ValueError:
                return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= now + self._horizon

    def detect_reuse(self, certs: Iterable[dict[str, Any]]) -> list[CertChange]:
        """Emit CERTIFICATE_REUSED for each fingerprint used by >1 subject."""
        by_fp: dict[str, set[str]] = {}
        for cert in certs:
            fp = str(cert.get("fingerprint_sha256") or cert.get("fingerprint") or "")
            if fp:
                by_fp.setdefault(fp, set()).add(str(cert.get("subject") or ""))
        out: list[CertChange] = []
        for fp, subjects in by_fp.items():
            if len(subjects) > 1:
                change = CertChange(
                    fingerprint=fp, kind="CERTIFICATE_REUSED",
                    subject=", ".join(sorted(subjects)),
                    affected_endpoints=self.endpoints_for(fp),
                    updates=["dependency_graph", "live_cbom", "pqc_risk"],
                    observed_at=self._clock())
                self._changes.append(change)
                out.append(change)
        return out
