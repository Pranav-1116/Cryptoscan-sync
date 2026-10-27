"""Scan modes for the universal engine.

The engine is the same across sectors; a scan *mode* selects how aggressive
or deep a particular run is. Sector profiles recommend a default subset, but
modes are engine-level concepts available to every deployment.

Modes (architecture §22): discovery, standard, deep, passive, continuous,
targeted, compliance, pqc.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanMode:
    id: str
    name: str
    description: str
    active_probing: bool
    depth: str            # "inventory" | "standard" | "deep"
    mutating: bool        # ever writes/credentialed action against targets
    default_interval_s: int | None  # for continuous mode; None = on-demand


SCAN_MODES: dict[str, ScanMode] = {
    "discovery": ScanMode(
        "discovery", "Discovery",
        "Build the asset inventory only — hosts, services, devices, cloud resources. "
        "No expensive deep analysis.",
        active_probing=True, depth="inventory", mutating=False, default_interval_s=None,
    ),
    "standard": ScanMode(
        "standard", "Standard",
        "Asset, service and configuration discovery; crypto identification across layers.",
        active_probing=True, depth="standard", mutating=False, default_interval_s=None,
    ),
    "deep": ScanMode(
        "deep", "Deep",
        "Detailed cryptographic, application and hardware analysis; firmware, binary and "
        "library inspection.",
        active_probing=True, depth="deep", mutating=False, default_interval_s=None,
    ),
    "passive": ScanMode(
        "passive", "Passive / Low-impact",
        "Observe traffic, events and configuration without aggressive probing — required for "
        "OT/ICS, SCADA and patient-safety environments.",
        active_probing=False, depth="standard", mutating=False, default_interval_s=None,
    ),
    "continuous": ScanMode(
        "continuous", "Continuous (24/7)",
        "Event-driven re-scan: on change, identify the affected asset and dependencies, run "
        "the relevant scanner, update CBOM/risk.",
        active_probing=True, depth="standard", mutating=False, default_interval_s=3600,
    ),
    "targeted": ScanMode(
        "targeted", "Targeted",
        "Scan a single selected asset or dependency path rather than the whole estate.",
        active_probing=True, depth="deep", mutating=False, default_interval_s=None,
    ),
    "compliance": ScanMode(
        "compliance", "Compliance",
        "Evaluate a selected policy/framework set and produce evidence-backed control status.",
        active_probing=True, depth="standard", mutating=False, default_interval_s=None,
    ),
    "pqc": ScanMode(
        "pqc", "Post-Quantum Focus",
        "Focus specifically on cryptographic migration exposure: harvest-now-decrypt-later "
        "risk, CNSA 2.0 / PQC readiness.",
        active_probing=True, depth="deep", mutating=False, default_interval_s=None,
    ),
}

#: modes considered safe to run against sensitive OT/ICS environments
OT_SAFE_MODES = ("discovery", "passive", "targeted", "continuous")


def get_mode(mode_id: str) -> ScanMode:
    return SCAN_MODES[str(mode_id).strip().lower()]


def list_modes() -> list[ScanMode]:
    return list(SCAN_MODES.values())


def is_ot_safe(mode_id: str) -> bool:
    return str(mode_id).strip().lower() in OT_SAFE_MODES


def recommend_modes(sector_id: str, ot_environment: bool = False) -> list[dict]:
    """Resolve a sector's recommended modes, flagging OT-safety.

    Pass ot_environment=True to force passive-safe recommendations for
    industrial estates (energy/manufacturing) even beyond their profile.
    """
    from sector_profiles.catalog import get_profile

    profile = get_profile(sector_id)
    mode_ids = list(profile.recommended_modes)
    if ot_environment:
        # passive-first ordering for sensitive OT/ICS estates
        if "passive" in mode_ids:
            mode_ids.remove("passive")
        mode_ids = ["passive"] + mode_ids
    out = []
    for mid in mode_ids:
        mode = SCAN_MODES.get(mid)
        if mode is None:
            continue
        out.append(
            {
                "id": mode.id,
                "name": mode.name,
                "description": mode.description,
                "active_probing": mode.active_probing,
                "ot_safe": is_ot_safe(mode.id),
            }
        )
    return out
