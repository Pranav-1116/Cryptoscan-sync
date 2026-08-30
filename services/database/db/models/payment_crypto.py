"""Payment cryptography inventory: HSM keys, ceremonies, audit events, findings.

This is the cryptography a bank's 10M daily transactions actually depend on —
LMK/ZMK/ZPK hierarchies, PIN verification keys, CVKs, MAC keys, BDKs and EMV
issuer keys. It lives in HSMs and key blocks, invisible to code/TLS/cloud
scans; these tables make it first-class inventory with ceremony provenance
and audit-trail telemetry attached.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

# X9.24/TR-39 + operational states
KEY_STATES = ("PRE_ACTIVATION", "ACTIVE", "SUSPENDED", "COMPROMISED", "DESTROYED", "EXPIRED")

# Payment key usages (superset of TR-31 usage names we map to)
KEY_USAGES = (
    "KEK", "BASE_DERIVATION_KEY", "ZONE_MASTER_KEY_ZMK", "ZONE_PIN_KEY_ZPK",
    "PIN_VERIFICATION_KEY", "CARD_VERIFICATION_KEY_CVK", "MAC_KEY",
    "ISSUER_MASTER_KEY_IMK", "EMV_ISSUER_MASTER_KEY", "DATA_ENCRYPTION_KEY", "OTHER",
)


class PaymentKey(BaseModel):
    __tablename__ = "payment_keys"

    key_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)  # operator/HSM key reference
    name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    hsm_device: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    key_usage: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    algorithm: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    key_block_version: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)  # TR-31 version, e.g. B0
    key_block_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)          # parse failure reason
    activation_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expiry_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)  # planned rotation
    custodian_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)  # MANUAL | TR31 | HSM_EVENT
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class KeyCeremony(BaseModel):
    __tablename__ = "key_ceremonies"

    ceremony_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    held_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    custodians: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)  # names/IDs of custodians
    m_of_n: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # e.g. "3-of-5"
    dual_control: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    documented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class HsmEvent(BaseModel):
    __tablename__ = "hsm_events"

    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    device: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="INFO")
    detail: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class PaymentTransactionVolume(BaseModel):
    """Daily transaction count from core banking — the denominator of the
    crypto-per-transaction ratio (PAY-014). One row per day, upserted."""

    __tablename__ = "payment_transaction_volume"

    day: Mapped[date] = mapped_column(Date, nullable=False, unique=True, index=True)
    transaction_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)


class PaymentPolicyFinding(BaseModel):
    __tablename__ = "payment_policy_findings"

    rule_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    blocking: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN", index=True)  # OPEN | ACCEPTED | RESOLVED
    resolved_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    evaluated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
