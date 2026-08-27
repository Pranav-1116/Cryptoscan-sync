"""Exceptions, agility scores, OT inventory, vendor crypto, certificate usages."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.certificate_usage import CertificateUsage
from db.models.ot_device import OtCryptoFinding, OtDevice
from db.models.policy_exception import ExceptionReview, PolicyException
from db.models.system import System
from db.models.system_agility_score import SystemAgilityScore
from db.models.vendor import Vendor
from db.models.vendor_crypto import VendorCryptoInventory


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MaturityRepository:
    def __init__(self, session: Session):
        self.session = session

    # --- certificate usages ---

    def upsert_usage(self, fingerprint: str, location: str, usage_type: str = "UNKNOWN") -> CertificateUsage:
        row = self.session.execute(
            select(CertificateUsage).where(
                CertificateUsage.fingerprint_sha256 == fingerprint,
                CertificateUsage.location == location,
            )
        ).scalar_one_or_none()
        if row:
            row.last_seen = _now()
            row.usage_type = usage_type or row.usage_type
            self.session.flush()
            return row
        row = CertificateUsage(
            fingerprint_sha256=fingerprint,
            location=location,
            usage_type=usage_type,
            last_seen=_now(),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def usages_for(self, fingerprint: str) -> list[CertificateUsage]:
        return list(
            self.session.execute(
                select(CertificateUsage).where(CertificateUsage.fingerprint_sha256 == fingerprint)
            ).scalars()
        )

    # --- agility ---

    def save_agility(self, system_id: str, payload: dict[str, Any]) -> SystemAgilityScore:
        row = SystemAgilityScore(
            system_id=system_id,
            agility_score=int(payload.get("agility_score") or payload.get("score") or 0),
            category=str(payload.get("category") or "CRITICAL"),
            factor_scores=payload.get("factor_scores") or payload.get("factors"),
            recommendations=payload.get("recommendations") or [],
            calculated_at=_now(),
            calculation_version=str(payload.get("calculation_version") or "agility-v1.0"),
            readiness_score=payload.get("readiness_score"),
            readiness_category=payload.get("readiness_category"),
            readiness=payload.get("readiness"),
        )
        self.session.add(row)
        system = self.session.get(System, system_id)
        if system is not None:
            system.current_agility_score = row.agility_score
            system.agility_category = row.category
            if row.readiness_score is not None:
                system.migration_readiness_score = row.readiness_score
                system.migration_readiness_category = row.readiness_category
        self.session.flush()
        return row

    def latest_agility(self, system_id: str) -> SystemAgilityScore | None:
        return self.session.execute(
            select(SystemAgilityScore)
            .where(SystemAgilityScore.system_id == system_id)
            .order_by(SystemAgilityScore.calculated_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    def previous_agility(self, system_id: str) -> SystemAgilityScore | None:
        """Second-newest score for a system (for trend deltas), or None."""
        return self.session.execute(
            select(SystemAgilityScore)
            .where(SystemAgilityScore.system_id == system_id)
            .order_by(SystemAgilityScore.calculated_at.desc())
            .offset(1)
            .limit(1)
        ).scalar_one_or_none()

    def list_agility(self) -> list[SystemAgilityScore]:
        return list(
            self.session.execute(
                select(SystemAgilityScore).order_by(SystemAgilityScore.calculated_at.desc())
            ).scalars()
        )

    def latest_agility_by_system(self) -> list[SystemAgilityScore]:
        rows = self.list_agility()
        seen: dict[str, SystemAgilityScore] = {}
        for row in rows:
            if row.system_id not in seen:
                seen[row.system_id] = row
        return list(seen.values())

    # --- exceptions ---

    def create_exception(self, **kwargs) -> PolicyException:
        kwargs.setdefault("status", "PENDING")
        kwargs.setdefault("requested_at", _now())
        row = PolicyException(**kwargs)
        self.session.add(row)
        self.session.flush()
        return row

    def get_exception(self, exception_id: str) -> PolicyException | None:
        return self.session.get(PolicyException, exception_id)

    def list_exceptions(self, *, status: str | None = None) -> list[PolicyException]:
        stmt = select(PolicyException).order_by(PolicyException.created_at.desc())
        if status:
            stmt = stmt.where(PolicyException.status == status)
        return list(self.session.execute(stmt).scalars())

    def set_exception_status(self, exception_id: str, **kwargs) -> PolicyException | None:
        row = self.get_exception(exception_id)
        if row is None:
            return None
        for key, value in kwargs.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
        self.session.flush()
        return row

    def add_review(self, exception_id: str, **kwargs) -> ExceptionReview:
        row = ExceptionReview(exception_id=exception_id, review_date=_now(), **kwargs)
        self.session.add(row)
        exception = self.get_exception(exception_id)
        if exception is not None:
            exception.last_reviewed = _now()
        self.session.flush()
        return row

    def expire_due(self, *, now: datetime | None = None) -> list[PolicyException]:
        now = now or _now()
        expired = []
        for row in self.list_exceptions(status="APPROVED"):
            if row.expiration_date and row.expiration_date <= now:
                row.status = "EXPIRED"
                expired.append(row)
        self.session.flush()
        return expired

    # --- vendor crypto ---

    def add_vendor_crypto(self, vendor_id: str, **kwargs) -> VendorCryptoInventory:
        kwargs.setdefault("discovered_at", _now())
        row = VendorCryptoInventory(vendor_id=vendor_id, **kwargs)
        self.session.add(row)
        vendor = self.session.get(Vendor, vendor_id)
        if vendor is not None:
            vendor.last_assessment_date = _now()
        self.session.flush()
        return row

    def list_vendor_crypto(self, vendor_id: str) -> list[VendorCryptoInventory]:
        return list(
            self.session.execute(
                select(VendorCryptoInventory).where(VendorCryptoInventory.vendor_id == vendor_id)
            ).scalars()
        )

    def replace_vendor_crypto(self, vendor_id: str, items: list[dict[str, Any]]) -> list[VendorCryptoInventory]:
        existing = self.list_vendor_crypto(vendor_id)
        for row in existing:
            self.session.delete(row)
        self.session.flush()
        stored = []
        for item in items:
            stored.append(self.add_vendor_crypto(vendor_id, **{k: v for k, v in item.items() if k != "vendor_id"}))
        return stored

    # --- OT ---

    def upsert_ot_device(self, payload: dict[str, Any]) -> OtDevice:
        ip = payload.get("ip_address")
        row = None
        if ip:
            row = self.session.execute(select(OtDevice).where(OtDevice.ip_address == ip)).scalar_one_or_none()
        now = _now()
        if row is None:
            row = OtDevice(
                ip_address=ip,
                mac_address=payload.get("mac_address"),
                vendor=payload.get("vendor"),
                device_type=payload.get("device_type"),
                model=payload.get("model"),
                firmware_version=payload.get("firmware_version"),
                protocols_observed=list(payload.get("protocols_observed") or []),
                first_seen=now,
                last_seen=now,
                location=payload.get("location"),
                criticality=payload.get("criticality"),
            )
            self.session.add(row)
            self.session.flush()
            return row
        row.last_seen = now
        for key in ("mac_address", "vendor", "device_type", "model", "firmware_version", "location", "criticality"):
            if payload.get(key):
                setattr(row, key, payload[key])
        protocols = list(row.protocols_observed or [])
        for proto in payload.get("protocols_observed") or []:
            if proto not in protocols:
                protocols.append(proto)
        row.protocols_observed = protocols
        self.session.flush()
        return row

    def add_ot_finding(self, device_id: str | None, payload: dict[str, Any]) -> OtCryptoFinding:
        row = OtCryptoFinding(
            device_id=device_id,
            protocol=payload.get("protocol"),
            crypto_config=payload.get("crypto_config") or payload.get("crypto"),
            has_crypto=bool(payload.get("has_crypto")),
            security_level=payload.get("security_level"),
            vulnerabilities=payload.get("vulnerabilities") or [],
            confidence=payload.get("confidence") or "MEDIUM",
            observed_at=_now(),
            observation_count=int(payload.get("observation_count") or 1),
            compliance_issue=payload.get("compliance_issue"),
            note=payload.get("note"),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_ot_devices(self) -> list[OtDevice]:
        return list(self.session.execute(select(OtDevice).order_by(OtDevice.ip_address)).scalars())

    def list_ot_findings(self) -> list[OtCryptoFinding]:
        return list(self.session.execute(select(OtCryptoFinding).order_by(OtCryptoFinding.created_at.desc())).scalars())
