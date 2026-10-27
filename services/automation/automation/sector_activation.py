"""Deterministic automatic sector policy activation (no AI/ML).

When a customer selects a sector (banking, healthcare, energy, telecom,
government, manufacturing, …), the engine activates a deterministic policy
configuration derived purely from the sector profile: which policy packs to
turn on, which compliance frameworks to map findings onto, which scan modes to
recommend, the evidence requirements, and a set of sector-appropriate automation
rules to seed. The universal scanner is unchanged — this only configures context
and policy, exactly per the doctrine ("same observations, sector policy").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sector_profiles.catalog import SECTOR_ALIASES, SECTOR_PROFILES

#: default automation rules seeded for a sector (safe, recommend-tier only).
#: These are WHEN/IF/THEN rules the automation engine understands.
_BASE_SEED_RULES: tuple[dict[str, Any], ...] = (
    {"rule_id": "cert-expiry-sector", "when": "certificate_expiring",
     "if": [{"field": "days_remaining", "operator": "lte", "value": 7}],
     "then": ["create_alert", "create_ticket", "notify_crypto_team"], "severity": "CRITICAL"},
    {"rule_id": "quantum-sector", "when": "quantum_vulnerable_detected",
     "if": [{"field": "criticality", "operator": "in",
             "value": ["CRITICAL", "HIGH", "MISSION_CRITICAL", "VERY_HIGH"]}],
     "then": ["create_alert", "add_pqc_queue", "create_migration_task", "create_ticket"],
     "severity": "HIGH"},
    {"rule_id": "unauthorized-asset", "when": "new_asset",
     "if": [{"field": "authorized", "operator": "equals", "value": False}],
     "then": ["create_alert", "create_ticket"], "severity": "HIGH"},
)

#: extra seed rules keyed by sector (sector-specific regulatory emphasis).
_SECTOR_SEED_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    "banking": (
        {"rule_id": "banking-hsm-change", "when": "drift_detected",
         "if": [{"field": "asset_class", "operator": "contains", "value": "hsm"}],
         "then": ["create_alert", "create_ticket", "request_approval"], "severity": "CRITICAL"},
        {"rule_id": "banking-payment-crypto", "when": "crypto_asset_detected",
         "if": [{"field": "asset_class", "operator": "in",
                 "value": ["payment_system", "swift", "payment_hsm"]}],
         "then": ["create_alert", "create_ticket", "add_pqc_queue"], "severity": "CRITICAL"},
    ),
    "healthcare": (
        {"rule_id": "healthcare-phi-crypto", "when": "vulnerable_library_detected",
         "if": [{"field": "data_class", "operator": "equals", "value": "PHI"}],
         "then": ["create_alert", "create_ticket"], "severity": "HIGH"},
    ),
    "energy": (
        {"rule_id": "energy-ot-safety", "when": "drift_detected",
         "if": [{"field": "is_ot", "operator": "equals", "value": True}],
         "then": ["create_alert", "create_ticket", "request_approval"], "severity": "CRITICAL"},
    ),
}


@dataclass
class SectorActivation:
    sector: str
    name: str
    policy_packs: list[str]
    compliance_frameworks: list[str]
    recommended_modes: list[str]
    required_evidence: list[str]
    integrations: list[str]
    scanning_notes: list[str]
    seed_rules: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sector": self.sector,
            "name": self.name,
            "policy_packs": self.policy_packs,
            "compliance_frameworks": self.compliance_frameworks,
            "recommended_modes": self.recommended_modes,
            "required_evidence": self.required_evidence,
            "integrations": self.integrations,
            "scanning_notes": self.scanning_notes,
            "seed_rules": self.seed_rules,
            "seed_rule_count": len(self.seed_rules),
        }


def normalize_sector(sector: str) -> str | None:
    """Resolve an alias/spelling to a canonical sector id; None if unknown."""
    key = str(sector or "").strip().lower().replace(" ", "_").replace("-", "_")
    if key in SECTOR_PROFILES:
        return key
    return SECTOR_ALIASES.get(key)


def activate_sector(sector: str) -> SectorActivation:
    """Produce the deterministic policy activation for a sector.

    Raises KeyError for an unknown sector (fail-closed: do not silently apply a
    generic policy when a regulated sector was named but not recognized).
    """
    canonical = normalize_sector(sector)
    if canonical is None:
        raise KeyError(f"unknown sector {sector!r}; known: {sorted(SECTOR_PROFILES)}")
    profile = SECTOR_PROFILES[canonical]

    seed_rules = [dict(r) for r in _BASE_SEED_RULES]
    seed_rules += [dict(r) for r in _SECTOR_SEED_RULES.get(canonical, ())]

    return SectorActivation(
        sector=canonical,
        name=profile.name,
        policy_packs=list(profile.policy_packs),
        compliance_frameworks=list(profile.compliance_frameworks),
        recommended_modes=list(profile.recommended_modes),
        required_evidence=list(profile.required_evidence),
        integrations=list(profile.integrations),
        scanning_notes=list(profile.scanning_notes),
        seed_rules=seed_rules,
    )


def available_sectors() -> list[dict[str, Any]]:
    """List canonical sectors with a one-line policy summary."""
    return [
        {"sector": sid, "name": p.name,
         "policy_packs": list(p.policy_packs),
         "frameworks": list(p.compliance_frameworks)[:4]}
        for sid, p in sorted(SECTOR_PROFILES.items())
    ]
