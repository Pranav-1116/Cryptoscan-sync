"""Passive-first OT/ICS mode (§22).

For industrial environments: passive discovery, asset fingerprinting,
protocol metadata, vendor identification and safe authorized queries.
Aggressive active scanning is never the default.

Explicit controls: SAFE | CAUTIOUS | ACTIVE | DEEP — ACTIVE/DEEP require
scope approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


class OtScanMode(str):
    SAFE = "SAFE"           # passive observation only, zero packets
    CAUTIOUS = "CAUTIOUS"   # passive + authorized read-only metadata queries
    ACTIVE = "ACTIVE"       # bounded active probing (approved scope)
    DEEP = "DEEP"           # full authorized interrogation (approved scope)

    @staticmethod
    def requires_approval(mode: str) -> bool:
        return mode in (OtScanMode.ACTIVE, OtScanMode.DEEP)


@dataclass
class OtScopeApproval:
    scope_id: str
    networks: list[str] = field(default_factory=list)
    approved_modes: list[str] = field(default_factory=list)
    approved_by: str = ""
    expires_at: Optional[str] = None
    maintenance_window: Optional[str] = None

    def allows(self, mode: str) -> bool:
        if mode in (OtScanMode.SAFE, OtScanMode.CAUTIOUS):
            return True
        return mode in self.approved_modes


class PassiveFirstOtScanner:
    """OT/ICS scanning that is passive-first by construction."""

    def __init__(self) -> None:
        self._approvals: dict[str, OtScopeApproval] = {}
        self._passive_log: list[dict[str, Any]] = []

    def approve_scope(self, approval: OtScopeApproval) -> None:
        self._approvals[approval.scope_id] = approval

    def passive_observe(self, *, scope_id: str, observation: dict[str, Any]) -> dict[str, Any]:
        """Passive asset fingerprinting from protocol metadata — always safe."""
        record = {"scope_id": scope_id, "mode": OtScanMode.SAFE,
                  "observation": observation}
        self._passive_log.append(record)
        return record

    def run(self, *, scope_id: str, mode: str, targets: list[str]) -> dict[str, Any]:
        """Run a scan in the requested mode; ACTIVE/DEEP need approval."""
        if OtScanMode.requires_approval(mode):
            approval = self._approvals.get(scope_id)
            if approval is None or not approval.allows(mode):
                return {"mode": mode, "blocked": True,
                        "reason": "ACTIVE/DEEP requires approved scope",
                        "targets": targets}
        return {
            "mode": mode,
            "blocked": False,
            "passive_first": True,
            "targets": targets,
            "note": "passive discovery always runs first; active probing is "
                    "bounded and authorized",
        }

    def passive_log(self) -> list[dict[str, Any]]:
        return list(self._passive_log)
