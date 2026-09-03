"""Deterministic OT/ICS maintenance-window safety guard (no AI/ML).

First-class safe-scanning policy for operational equipment. Ordinary IT
"scan it live" strategy must NEVER be applied to PLCs/DCS/SIS/safety controllers:

* **Passive-first**: operations that only observe (passive traffic capture,
  filesystem/PCAP reading, inventory, telemetry, metrics) are allowed at any
  time and never require a window. The scanner itself never sends packets.
* **Active/intrusive** operations (active probing, firmware push, config change,
  scan that authenticates to or writes a device) are allowed ONLY inside an
  approved maintenance window covering that device (and scope), within bounds,
  with a valid change ticket and approver, and only up to the device's allowed
  action class. Safety-integrity devices (SIS / safety controller) can never be
  actively probed — a window is not sufficient.

Every decision is a pure rule evaluation (wall-clock time + policy table); there
is no model inference and no network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# --------------------------------------------------------------- safety model

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class DenyReason(str, Enum):
    NO_SUCH_DEVICE = "NO_SUCH_DEVICE"
    SAFETY_CONTROLLER_PROTECTED = "SAFETY_CONTROLLER_PROTECTED"
    OUTSIDE_WINDOW = "OUTSIDE_WINDOW"
    WINDOW_EXPIRED = "WINDOW_EXPIRED"
    WINDOW_NOT_STARTED = "WINDOW_NOT_STARTED"
    WINDOW_SCOPE_MISMATCH = "WINDOW_SCOPE_MISMATCH"
    CRITICALITY_WINDOW_REQUIRED = "CRITICALITY_WINDOW_REQUIRED"
    ACTION_EXCEEDS_WINDOW_CLASS = "ACTION_EXCEEDS_WINDOW_CLASS"
    NO_APPROVAL = "NO_APPROVAL"
    NO_CHANGE_TICKET = "NO_CHANGE_TICKET"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    ACTION_NOT_PERMITTED_FOR_DEVICE = "ACTION_NOT_PERMITTED_FOR_DEVICE"


#: operations that only observe — always permitted, never require a window.
PASSIVE_OPERATIONS = frozenset({
    "passive_capture", "filesystem_read", "pcap_read", "inventory",
    "telemetry_poll", "metrics_render", "vuln_correlate", "report",
    "baseline_observe", "config_backup_readonly",
})

#: operations that disturb a device — require an approved window.
ACTIVE_OPERATIONS = frozenset({
    "active_probe", "credentialed_scan", "firmware_pull", "firmware_push",
    "config_write", "reboot", "service_toggle", "firmware_update",
})

#: how disruptive each active action is (higher = needs a broader window).
ACTION_CLASS = {
    "active_probe": "interact",
    "credentialed_scan": "interact",
    "firmware_pull": "interact",
    "firmware_push": "change",
    "config_write": "change",
    "reboot": "change",
    "service_toggle": "change",
    "firmware_update": "change",
}
#: window classes, ordered from least to most permissive.
WINDOW_CLASS_ORDER = {"observe": 0, "interact": 1, "change": 2}

#: device criticality tiers; any tier at/above this needs a window for active ops.
CRITICALITY_TIERS = ("LOW", "MEDIUM", "HIGH", "SAFETY")
#: device types that are safety-integrity — actively untouchable, window or not.
SAFETY_DEVICE_TYPES = frozenset({
    "sis", "safety_controller", "safety_plc", "esd", "emergency_shutdown",
    "safety_relay", "sil_controller",
})


@dataclass(frozen=True)
class OtDevice:
    id: str
    criticality: str = "MEDIUM"
    device_type: str = ""
    zone: str = ""          # e.g. Purdue zone / site area
    site: str = ""

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "OtDevice":
        return OtDevice(
            id=str(d.get("id") or d.get("device_id") or ""),
            criticality=str(d.get("criticality") or "MEDIUM").upper(),
            device_type=str(d.get("device_type") or "").lower(),
            zone=str(d.get("zone") or d.get("location") or ""),
            site=str(d.get("site") or ""),
        )

    def is_safety(self) -> bool:
        if self.criticality == "SAFETY":
            return True
        return any(t in self.device_type for t in SAFETY_DEVICE_TYPES)


@dataclass
class MaintenanceWindow:
    id: str
    starts_at: datetime
    ends_at: datetime
    device_ids: frozenset[str] = frozenset()      # empty = scoped by zone/site only
    zones: frozenset[str] = frozenset()
    sites: frozenset[str] = frozenset()
    allowed_action_class: str = "interact"         # observe|interact|change
    approved_by: str = ""
    change_ticket: str = ""
    operations: frozenset[str] = frozenset(ACTIVE_OPERATIONS)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "MaintenanceWindow":
        def _dt(key: str) -> datetime:
            v = d.get(key)
            if isinstance(v, datetime):
                dt = v
            else:
                dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        raw_zones = d.get("zones")
        if raw_zones is None and d.get("zone"):
            raw_zones = [d["zone"]]
        return MaintenanceWindow(
            id=str(d.get("id") or d.get("window_id") or ""),
            starts_at=_dt("starts_at"),
            ends_at=_dt("ends_at"),
            device_ids=frozenset(str(x) for x in (d.get("device_ids") or [])),
            zones=frozenset(str(x) for x in (raw_zones or [])),
            sites=frozenset(str(x) for x in (d.get("sites") or [])),
            allowed_action_class=str(d.get("allowed_action_class") or "interact").lower(),
            approved_by=str(d.get("approved_by") or ""),
            change_ticket=str(d.get("change_ticket") or d.get("ticket") or ""),
            operations=frozenset(d.get("operations") or ACTIVE_OPERATIONS),
        )

    def covers_device(self, device: OtDevice) -> bool:
        if self.device_ids and device.id in self.device_ids:
            return True
        if self.zones and device.zone and device.zone in self.zones:
            return True
        if self.sites and device.site and device.site in self.sites:
            return True
        # a window that names nothing cannot implicitly cover a specific device
        return False


@dataclass
class OtDecision:
    decision: Decision
    reason: str | None = None
    passive: bool = False
    window_id: str | None = None
    matched_window: bool = False
    detail: str = ""
    rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "allowed": self.decision == Decision.ALLOW,
            "reason": self.reason.value if self.reason else None,
            "passive": self.passive,
            "window_id": self.window_id,
            "matched_window": self.matched_window,
            "detail": self.detail,
            "rules": self.rules,
        }


_TICKET_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{2,}$")


def _deny(reason: DenyReason, detail: str, rules: list[str]) -> OtDecision:
    return OtDecision(decision=Decision.DENY, reason=reason, detail=detail, rules=rules)


def authorize_operation(
    operation: str,
    device: OtDevice | None,
    windows: list[MaintenanceWindow] | None = None,
    *,
    now: datetime | None = None,
    change_ticket: str = "",
) -> OtDecision:
    """Evaluate whether ``operation`` may run against an OT device right now.

    Deterministic and side-effect free. ``windows`` is the set of approved
    windows active for the caller's scope; the function never fetches anything.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    op = str(operation or "").strip().lower()
    rules: list[str] = []

    if op in PASSIVE_OPERATIONS:
        rules.append("passive_first: observe-only operations are always safe")
        return OtDecision(decision=Decision.ALLOW, passive=True,
                          detail="observe-only operation; no maintenance window required",
                          rules=rules)

    if op not in ACTIVE_OPERATIONS:
        return _deny(DenyReason.UNKNOWN_OPERATION,
                     f"unknown or non-classified operation: {operation!r}",
                     ["allowlist: operation must be classified passive or active"])

    if device is None:
        return _deny(DenyReason.NO_SUCH_DEVICE,
                     "active operations require a known OT device target",
                     ["fail_closed: cannot safety-check an unknown target"])

    # Safety-integrity controllers can never be actively probed.
    if device.is_safety():
        return _deny(DenyReason.SAFETY_CONTROLLER_PROTECTED,
                     f"device {device.id} is a safety-integrity controller "
                     f"({device.device_type or 'SAFETY'}); active operations are prohibited",
                     ["safety_override: SIS/ESD/safety controllers are never actively probed"])

    windows = windows or []
    action_class = ACTION_CLASS[op]
    rules.append(f"active_operation: {op} is class '{action_class}'")

    # active op requires at least one covering, in-effect, sufficiently broad window
    for w in windows:
        wrules = list(rules)
        if not w.covers_device(device):
            continue
        if now < w.starts_at:
            return _deny(DenyReason.WINDOW_NOT_STARTED,
                         f"window {w.id} starts at {w.starts_at.isoformat()}",
                         wrules + ["window: current time is before window start"])
        if now > w.ends_at:
            continue  # expired window — keep looking, else fall through to expired
        if op not in w.operations:
            wrules.append(f"window {w.id} does not list operation {op}")
            continue
        if WINDOW_CLASS_ORDER.get(w.allowed_action_class, 0) < WINDOW_CLASS_ORDER[action_class]:
            return _deny(DenyReason.ACTION_EXCEEDS_WINDOW_CLASS,
                         f"action '{action_class}' exceeds window {w.id} class "
                         f"'{w.allowed_action_class}'",
                         wrules + ["window: action disruption class exceeds granted class"])
        if not w.approved_by:
            return _deny(DenyReason.NO_APPROVAL,
                         f"window {w.id} has no recorded approver",
                         wrules + ["window: human approver required"])
        ticket = change_ticket or w.change_ticket
        if not ticket:
            return _deny(DenyReason.NO_CHANGE_TICKET,
                         f"active operation {op} requires a change ticket",
                         wrules + ["window: valid change ticket required"])
        if not _TICKET_RE.match(str(ticket)):
            return _deny(DenyReason.NO_CHANGE_TICKET,
                         f"change ticket {ticket!r} is not a valid ticket reference",
                         wrules + ["window: ticket must be a vault/ITS reference e.g. CHG-1234"])
        wrules.append(f"window {w.id} in effect [{w.starts_at.isoformat()}..{w.ends_at.isoformat()}]")
        wrules.append(f"approved_by={w.approved_by} ticket={ticket}")
        return OtDecision(decision=Decision.ALLOW, passive=False, window_id=w.id,
                          matched_window=True,
                          detail=f"{op} permitted within approved window {w.id}",
                          rules=wrules)

    # no covering window matched
    if device.criticality in ("HIGH", "MEDIUM", "LOW"):
        reason = DenyReason.OUTSIDE_WINDOW
        # distinguish "a window exists for the device but expired"
        for w in windows:
            if w.covers_device(device) and now > w.ends_at:
                return _deny(DenyReason.WINDOW_EXPIRED,
                             f"the only window covering {device.id} ({w.id}) ended "
                             f"{w.ends_at.isoformat()}",
                             rules + ["fail_closed: active operations outside an approved window"])
    else:
        reason = DenyReason.CRITICALITY_WINDOW_REQUIRED

    return _deny(reason,
                 f"no approved maintenance window covering device {device.id} is in effect",
                 rules + ["fail_closed: active operations require an in-effect approved window"])
