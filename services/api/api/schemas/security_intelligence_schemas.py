"""Typed request models for the security-intelligence decision endpoints.

These endpoints expose pure, deterministic engines (identity resolution, scan
profiles, finding dedup/risk-chain, verification/freshness state and scan
triggers) under ``/api/v1/security/intelligence/*``. Typed bodies give the
frontend and any automation a stable contract instead of a raw ``dict``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ObservationIn(BaseModel):
    """One scanner's view of an asset (spec #1)."""

    source: str = Field(default="unknown")
    ids: dict[str, str] = Field(default_factory=dict)
    attrs: dict[str, object] = Field(default_factory=dict)
    observed_at: str | None = None


class IdentityResolveRequest(BaseModel):
    observations: list[ObservationIn] = Field(default_factory=list)


class ScanProfileResolveRequest(BaseModel):
    profile: str
    sector: str | None = None
    scan: dict[str, object] = Field(default_factory=dict)
    privacy: dict[str, object] = Field(default_factory=dict)
    limits: dict[str, object] = Field(default_factory=dict)


class CorrelateRequest(BaseModel):
    findings: list[dict[str, object]] = Field(default_factory=list)


class RiskChainRequest(BaseModel):
    asset_id: str
    findings: list[dict[str, object]] = Field(default_factory=list)
    critical_asset: bool = False
    business_value: str | None = None


class AssetStateRequest(BaseModel):
    sources: dict[str, str] = Field(default_factory=dict)
    verification: str | None = None
    last_seen_epoch: float | None = None
    now: float | None = None
    verified: bool = False


class ScanScheduleRequest(BaseModel):
    cadence: str = Field(default="on_demand")
    event: str | None = None
    scan_type: str = Field(default="standard")
    baseline_at: float | None = None
    now: float | None = None
    changed_assets: list[str] = Field(default_factory=list)
