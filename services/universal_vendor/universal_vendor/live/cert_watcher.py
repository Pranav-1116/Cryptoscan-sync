"""Universal Certificate Watcher (24/7 spec §9).

One certificate monitoring engine across every vendor surface — Cisco,
Palo Alto, Fortinet, F5, HSM, PKI, cloud, applications. Detects:
new, changed, renewed, expired, revoked, algorithm changed, key size
changed, chain changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from universal_vendor.plugin import content_hash


@dataclass
class WatchedCertificate:
    cert_id: str                    # stable identity: content hash of subject+issuer+serial
    subject: str
    issuer: str
    serial: str = ""
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    not_after: Optional[str] = None
    revoked: bool = False
    chain: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WatchedCertificate":
        identity = content_hash({
            "subject": data.get("subject", ""),
            "issuer": data.get("issuer", ""),
            "serial": data.get("serial", ""),
        })
        return cls(
            cert_id=identity,
            subject=str(data.get("subject", "")),
            issuer=str(data.get("issuer", "")),
            serial=str(data.get("serial", "")),
            algorithm=data.get("algorithm"),
            key_size=data.get("key_size"),
            not_after=data.get("not_after"),
            revoked=bool(data.get("revoked", False)),
            chain=list(data.get("chain") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"cert_id": self.cert_id, "subject": self.subject,
                "issuer": self.issuer, "serial": self.serial,
                "algorithm": self.algorithm, "key_size": self.key_size,
                "not_after": self.not_after, "revoked": self.revoked,
                "chain": list(self.chain),
                "first_seen": self.first_seen, "last_seen": self.last_seen}


class CertificateChange(str):
    NEW = "NEW"
    CHANGED = "CHANGED"
    RENEWED = "RENEWED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ALGORITHM_CHANGED = "ALGORITHM_CHANGED"
    KEY_SIZE_CHANGED = "KEY_SIZE_CHANGED"
    CHAIN_CHANGED = "CHAIN_CHANGED"


class UniversalCertificateWatcher:
    def __init__(self) -> None:
        self._certs: dict[str, WatchedCertificate] = {}
        self._changes: list[dict[str, Any]] = []

    def watch(self, data: dict[str, Any], *, vendor: str = "", asset_id: str = "") -> list[str]:
        """Feed one certificate observation; returns detected change types."""
        cert = WatchedCertificate.from_dict(data)
        now = datetime.now(timezone.utc).isoformat()
        existing = self._certs.get(cert.cert_id)

        if existing is None:
            # same subject+issuer already tracked with a different serial →
            # this is a renewal of the same certificate identity, not a new one
            renewed = any(
                other.subject == cert.subject and other.issuer == cert.issuer
                and other.serial != cert.serial
                for other in self._certs.values()
            )
            self._certs[cert.cert_id] = cert
            change = [CertificateChange.RENEWED if renewed else CertificateChange.NEW]
            self._record(cert, change, vendor, asset_id)
            return change

        # update seen state
        existing.last_seen = now
        changes: list[str] = []

        if existing.revoked != cert.revoked:
            changes.append(CertificateChange.REVOKED if cert.revoked
                           else CertificateChange.CHANGED)
        elif cert.not_after and cert.not_after <= now and not existing.not_after:
            changes.append(CertificateChange.EXPIRED)

        if cert.algorithm and existing.algorithm and cert.algorithm != existing.algorithm:
            changes.append(CertificateChange.ALGORITHM_CHANGED)
        if cert.key_size and existing.key_size and cert.key_size != existing.key_size:
            changes.append(CertificateChange.KEY_SIZE_CHANGED)
        if cert.chain and existing.chain and cert.chain != existing.chain:
            changes.append(CertificateChange.CHAIN_CHANGED)

        if not changes:
            changes.append(CertificateChange.CHANGED)

        # fold observable fields in
        existing.algorithm = cert.algorithm or existing.algorithm
        existing.key_size = cert.key_size or existing.key_size
        existing.not_after = cert.not_after or existing.not_after
        existing.revoked = cert.revoked
        if cert.chain:
            existing.chain = cert.chain

        self._record(existing, changes, vendor, asset_id)
        return changes

    def _record(self, cert: WatchedCertificate, changes: list[str],
                vendor: str, asset_id: str) -> None:
        self._changes.append({
            "cert_id": cert.cert_id,
            "subject": cert.subject,
            "changes": list(changes),
            "vendor": vendor,
            "asset_id": asset_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificate": cert.to_dict(),
        })

    def certificate(self, cert_id: str) -> Optional[WatchedCertificate]:
        return self._certs.get(cert_id)

    def certificates(self) -> list[WatchedCertificate]:
        return list(self._certs.values())

    def changes(self) -> list[dict[str, Any]]:
        return list(self._changes)

    def count(self) -> int:
        return len(self._certs)
