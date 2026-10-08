"""Declared linkage models: crypto↔hardware, vendor-of-vendor, twin
snapshots and cascade watches.

These are the four data models the cascade stack was missing:

* :class:`CryptoHardwareLink` — an operator-declared join between a crypto
  asset and the hardware device that serves it. Deliberately *declared*,
  not inferred: the platform will not guess which HSM holds which key, but
  once someone who knows declares it, device cascades can name dependents.
* :class:`VendorDependency` — sub-tier supply-chain edges (vendor of
  vendor), so vendor cascades can walk transitive exposure instead of
  listing it as an honest unknown.
* :class:`TwinSnapshot` — a versioned, content-addressed capture of the
  digital-twin estate snapshot, so "what was the blast radius at v5 / last
  audit?" becomes a replay instead of a shrug.
* :class:`CascadeWatch` — a saved cascade target that is re-run on demand
  (run-due), diffed against its previous answer, and reported when the
  blast radius changes.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CryptoHardwareLink(BaseModel, TenantScoped):
    __tablename__ = "crypto_hardware_links"
    __table_args__ = (UniqueConstraint("asset_id", "hardware_asset_id",
                                       name="uq_crypto_hardware_link"),)

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("crypto_assets.id", ondelete="CASCADE"),
        nullable=False, index=True)
    hardware_asset_id: Mapped[str] = mapped_column(
        String(200), nullable=False, index=True)  # hardware_assets.asset_id
    declared_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class VendorDependency(BaseModel, TenantScoped):
    __tablename__ = "vendor_dependencies"
    __table_args__ = (UniqueConstraint("parent_vendor_id", "child_vendor_id",
                                       name="uq_vendor_dependency"),)

    parent_vendor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vendors.id", ondelete="CASCADE"),
        nullable=False, index=True)
    child_vendor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vendors.id", ondelete="CASCADE"),
        nullable=False, index=True)
    relation: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    declared_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class TwinSnapshot(BaseModel, TenantScoped):
    __tablename__ = "twin_snapshots"

    version: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class CascadeWatch(BaseModel, TenantScoped):
    __tablename__ = "cascade_watches"

    target: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    target_kind: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
