"""Deterministic automation playbooks (reusable, auditable workflows).

A playbook is an ordered list of safe actions that the automation engine runs in
response to a class of event. Each step carries its safety tier so the engine can
auto-run observe/analyze/recommend steps and stop at the first step that needs
human approval (a recommendation/gate is produced rather than an automatic
change). Playbooks are declarative and deterministic — no inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from automation.safety import classify_action


class PlaybookTrigger(str, Enum):
    NEW_CRYPTO_ASSET = "new_crypto_asset"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    CERTIFICATE_CHANGED = "certificate_changed"
    NEW_ASSET = "new_asset"
    VULNERABLE_LIBRARY = "vulnerable_library"
    DRIFT = "drift_detected"


@dataclass
class PlaybookStep:
    action: str
    tier: str
    note: str = ""
    requires_approval: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"action": self.action, "tier": self.tier,
                "requires_approval": self.requires_approval, "note": self.note}


@dataclass
class Playbook:
    id: str
    trigger: str
    name: str
    steps: list[PlaybookStep] = field(default_factory=list)
    description: str = ""

    def auto_steps(self) -> list[PlaybookStep]:
        return [s for s in self.steps if not s.requires_approval]

    def gated_steps(self) -> list[PlaybookStep]:
        return [s for s in self.steps if s.requires_approval]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "trigger": self.trigger, "name": self.name,
            "description": self.description,
            "steps": [s.as_dict() for s in self.steps],
            "auto_step_count": len(self.auto_steps()),
            "approval_step_count": len(self.gated_steps()),
        }


def _step(action: str, note: str = "") -> PlaybookStep:
    decision = classify_action(action)
    return PlaybookStep(action=action, tier=decision.tier, note=note,
                        requires_approval=decision.requires_approval)


def _build() -> dict[str, Playbook]:
    defs: dict[str, Playbook] = {}

    def add(pid, trigger, name, description, actions):
        defs[pid] = Playbook(
            id=pid, trigger=trigger, name=name, description=description,
            steps=[_step(a, note) for a, note in actions],
        )

    add("pb_pqc", PlaybookTrigger.QUANTUM_VULNERABLE.value,
        "PQC migration playbook",
        "Detect quantum-vulnerable crypto, map dependencies, recommend migration, "
        "queue a migration task, and validate after migration.",
        [("targeted_rescan", "confirm vulnerable algorithm/key size"),
         ("update_cbom", "refresh cryptographic bill of materials"),
         ("add_pqc_queue", "add to post-quantum migration queue"),
         ("create_migration_task", "open migration task with complexity"),
         ("create_ticket", "track owner + validation requirement"),
         ("create_alert", "notify crypto team of quantum risk"),
         ("request_approval", "gated: migration execution needs human sign-off")])

    add("pb_certificate_expiring", PlaybookTrigger.CERTIFICATE_EXPIRING.value,
        "Certificate expiry playbook",
        "Find owner and dependent systems, alert and open a ticket, monitor the "
        "replacement, and validate the new certificate.",
        [("targeted_rescan", "confirm certificate + chain"),
         ("create_alert", "expiry warning (20d=warn, 7d=high, expired=critical)"),
         ("create_ticket", "assign certificate owner"),
         ("notify_crypto_team", "notify on-call"),
         ("request_approval", "gated: reissuing/rotating a cert changes production")])

    add("pb_new_asset", PlaybookTrigger.NEW_ASSET.value,
        "New asset playbook",
        "Identify, fingerprint, scan with auto-selected scanners, run crypto "
        "analysis, update CBOM/HBOM, and recalculate risk.",
        [("targeted_rescan", "run auto-selected scanner set"),
         ("update_cbom", "add asset to CBOM"),
         ("create_alert", "unauthorized/new asset alert"),
         ("create_ticket", "asset onboarding + ownership ticket")])

    add("pb_vulnerable_library", PlaybookTrigger.VULNERABLE_LIBRARY.value,
        "Vulnerable library playbook",
        "Correlate library/version to known vulnerabilities, enumerate affected "
        "business systems via the dependency graph, and raise tickets.",
        [("targeted_rescan", "confirm vulnerable version"),
         ("update_cbom", "mark library vulnerable in CBOM"),
         ("create_alert", "vulnerable crypto library in use"),
         ("create_ticket", "remediation ticket with blast radius")])

    add("pb_drift", PlaybookTrigger.DRIFT.value,
        "Drift playbook",
        "Diff current state vs sealed baseline and alert/ticket on regressions.",
        [("targeted_rescan", "re-confirm the changed asset"),
         ("create_alert", "critical crypto drift alert"),
         ("create_ticket", "investigate drift"),
         ("request_approval", "gated: rollback/remediation changes production")])

    return defs


_PLAYBOOKS = _build()


def get_playbook(trigger: str) -> Playbook | None:
    return _PLAYBOOKS.get(trigger)


def all_playbooks() -> list[Playbook]:
    return list(_PLAYBOOKS.values())


def playbook_for_event(event_kind: str) -> Playbook | None:
    """Map a raw event kind onto its playbook (deterministic lookup)."""
    mapping = {
        "quantum_vulnerable_detected": "pb_pqc",
        "crypto_asset_detected": "pb_pqc",
        "certificate_expiring": "pb_certificate_expiring",
        "certificate_changed": "pb_certificate_expiring",
        "new_asset": "pb_new_asset",
        "vulnerable_library_detected": "pb_vulnerable_library",
        "drift_detected": "pb_drift",
    }
    pid = mapping.get(event_kind)
    return _PLAYBOOKS.get(pid) if pid else None
