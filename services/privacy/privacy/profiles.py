"""Scan Profiles (spec #8).

Instead of configuring every scan manually, a named profile bundles the whole
decision: which targets are in scope, how aggressive the scan is, what data may
be collected, and on what schedule. Profiles are the *usability* layer over the
policy engine — they resolve to a :class:`~privacy.policy.PolicyBundle` plus a
trigger cadence, so the gate still evaluates the same fail-closed chain.

A profile can never loosen the sector policy: calling :func:`resolve_profile`
always applies ``apply_sector_overrides`` after the profile's own settings, so a
BANK-PRODUCTION profile on a banking sector never weakens banking defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from privacy.policy import apply_sector_overrides, build_policy, SECTOR_PROFILES
from privacy.ratelimit import Limits


@dataclass(frozen=True)
class ScanProfile:
    """A named, reusable scanning configuration.

    ``scope`` filters which targets the profile is allowed to touch; ``mode`` /
    ``intensity`` set default scan behaviour; ``schedule`` is the default cadence
    (one of the trigger kinds in :mod:`privacy.triggers`); ``data_collection`` is
    a privacy sub-keyword controlling collection breadth.
    """

    id: str
    name: str
    description: str = ""
    mode: str = "read-only"
    intensity: str = "low"
    schedule: str = "on_demand"
    scope: dict[str, Any] = field(default_factory=dict)
    data_collection: str = "minimal"
    limit: dict[str, Any] = field(default_factory=dict)
    sectors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "intensity": self.intensity,
            "schedule": self.schedule,
            "scope": dict(self.scope),
            "data_collection": self.data_collection,
            "limit": dict(self.limit),
            "sectors": list(self.sectors),
        }


#: the sanctioned profiles. ``data_collection`` maps to privacy settings;
#: ``limits`` are clamped by :func:`resolve_profile`.
SCAN_PROFILES: dict[str, ScanProfile] = {
    "bank-production": ScanProfile(
        "bank-production", "BANK-PRODUCTION",
        "Read-only, low-intensity, production-safe; never collect secrets/PII; "
        "conservative rate caps for banking estates.",
        mode="read-only", intensity="low", schedule="on_change",
        scope={"environments": ["prod"], "production_protected": True, "hsm_protected": True},
        data_collection="minimal",
        limit={"qps": 3, "connections": 25}, sectors=("banking",),
    ),
    "healthcare-production": ScanProfile(
        "healthcare-production", "HEALTHCARE-PRODUCTION",
        "Patient-safety first: passive/default scan modes, no aggressive probing, "
        "strict PII minimization.",
        mode="read-only", intensity="low", schedule="daily",
        scope={"environments": ["prod"], "production_protected": True},
        data_collection="restricted", limit={"qps": 2, "connections": 20},
        sectors=("healthcare",),
    ),
    "cloud-audit": ScanProfile(
        "cloud-audit", "CLOUD-AUDIT",
        "Read-only audit of cloud accounts and resource configurations; "
        "throttles to the provider's API quota.",
        mode="read-only", intensity="medium", schedule="on_change",
        scope={"asset_types": ["cloud_resource"]},
        data_collection="standard", limit={"qps": 10, "connections": 100},
        sectors=("generic",),
    ),
    "pqc-discovery": ScanProfile(
        "pqc-discovery", "PQC-DISCOVERY",
        "Post-quantum migration focus: discover algorithm/key-size exposure and "
        "harvest-now-decrypt-later risk across the estate.",
        mode="read-only", intensity="deep", schedule="weekly",
        scope={"asset_types": ["crypto", "certificate", "system"]},
        data_collection="standard", limit={"qps": 8, "connections": 80},
        sectors=("generic",),
    ),
    "low-impact": ScanProfile(
        "low-impact", "LOW-IMPACT",
        "Passive, non-intrusive discovery for sensitive, OT or production "
        "environments where active probing is forbidden.",
        mode="read-only", intensity="low", schedule="on_change",
        scope={"passive": True, "production_protected": True},
        data_collection="minimal", limit={"qps": 5, "connections": 20},
        sectors=("generic",),
    ),
    "deep-assessment": ScanProfile(
        "deep-assessment", "DEEP-ASSESSMENT",
        "Full-depth assessment for development/non-production estates: firmware, "
        "binary and library inspection.",
        mode="controlled_active", intensity="high", schedule="weekly",
        scope={"environments": ["dev", "staging"]},
        data_collection="standard", limit={"qps": 20, "connections": 150},
        sectors=("generic",),
    ),
    "ot-safe": ScanProfile(
        "ot-safe", "OT-SAFE",
        "OT/ICS/SCADA-safe: passive-only, discovery + targeted, read-only, "
        "maintenance-window aware.",
        mode="read-only", intensity="low", schedule="on_change",
        scope={"ot": True, "passive": True, "maintenance_window_aware": True},
        data_collection="restricted", limit={"qps": 1, "connections": 10},
        sectors=("energy",),
    ),
}


def get_profile(profile_id: str) -> ScanProfile:
    """Return a profile by id, raising ``KeyError`` for an unknown id."""
    return SCAN_PROFILES[profile_id.strip().lower()]


def _collection_settings(data_collection: str) -> dict[str, Any]:
    """Map a data-collection keyword to privacy settings (never loosens)."""
    base = {
        "collect_pii": False,
        "collect_private_keys": False,
        "collect_secrets": False,
        "redact_secrets": True,
        "tokenize_identifiers": True,
        "mask_sensitive_fields": True,
        "data_minimization": True,
    }
    if data_collection == "restricted":
        # only observation metadata, no content
        base.update({"collect_pii": False, "collect_private_keys": False,
                     "collect_secrets": False, "tokenize_identifiers": True})
    elif data_collection == "minimal":
        base.update({"collect_pii": False, "collect_private_keys": False,
                     "collect_secrets": False})
    # "standard" keeps all conservative-on settings (no collection of secrets)
    return base


def resolve_profile(profile_id: str, *, sector: str | None = None,
                    scan: dict[str, Any] | None = None,
                    privacy: dict[str, Any] | None = None,
                    limits: dict[str, Any] | None = None) -> dict[str, Any]:
    """Resolve a profile into a concrete policy bundle + limits.

    Returns a dict with ``profile``, ``policy`` (the :class:`PolicyBundle`), and
    ``limits`` (a :class:`~privacy.ratelimit.Limits`). The sector override is
    applied LAST so a profile on a regulated sector can never loosen the sector's
    protections. Numeric limits from the profile are clamps (never raise).
    """
    profile = get_profile(profile_id)
    scan_cfg: dict[str, Any] = {
        "mode": profile.mode,
        "intensity": profile.intensity,
        **profile.scope,
        **(scan or {}),
    }
    privacy_cfg: dict[str, Any] = {
        **_collection_settings(profile.data_collection),
        **(privacy or {}),
    }
    policy = build_policy(scan_cfg, privacy_cfg, sector=None)
    if sector:
        policy = apply_sector_overrides(policy, sector)

    # Build Limits from profile + sector caps (clamp downward, never raise).
    profile_caps = {**profile.limit, **(limits or {})}
    prof = (SECTOR_PROFILES.get(sector) or {}) if sector else {}
    sector_caps = prof.get("scan") or {}
    lim = Limits()
    mapping = {
        "qps": "requests_per_second",
        "requests_per_second": "requests_per_second",
        "connections": "max_connections",
        "max_connections": "max_connections",
        "concurrency": "max_concurrency",
        "max_concurrency": "max_concurrency",
    }
    for key, val in profile_caps.items():
        attr = mapping.get(key)
        if attr and isinstance(val, (int, float)):
            current = getattr(lim, attr)
            setattr(lim, attr, min(val, current))
    for key, val in sector_caps.items():
        if key == "rate_limit_qps" and isinstance(val, (int, float)):
            lim.requests_per_second = min(val, lim.requests_per_second)
        elif key == "max_connections" and isinstance(val, (int, float)):
            lim.max_connections = min(val, lim.max_connections)

    return {
        "profile": profile.to_dict(),
        "policy": policy,
        "limits": lim,
    }
