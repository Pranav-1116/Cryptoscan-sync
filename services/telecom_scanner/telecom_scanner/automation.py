"""Telecom → automation linkage (pure).

Realtime posture events only matter if something actionable happens. Rather
than a parallel telecom automation system, telecom events map onto the
platform's existing rules engine (services/automation): the same rule
conditions, the same action vocabulary, the same governance gates.

Mapping policy (event payload ``kind`` → automation event kind):

* ``TELECOM_CERT_EXPIRING``       → ``certificate_expiring``   (existing cert
  playbook: rescan, alert, ticket, gated rotation)
* ``TELECOM_REACHABILITY_LOST``   → ``agent_offline``          (a monitored
  network function went dark — new telecom playbook)
* ``TELECOM_FINDINGS_CHANGED`` / ``TELECOM_FINDING`` with severity
  high/critical                    → ``drift_detected``         (crypto posture
  drift: new weak verdict or lost reachability on the estate)
* everything else (recoveries, info findings, target added) → None — noise
  never wakes the automation engine.

The condition data handed to rules carries the telecom identity (nf_id,
carrier_code, plmn-adjacent fields, plane, environment) so operator rules
can target e.g. "plane == roaming" or "carrier_code == de-telekom".
"""
from __future__ import annotations

from typing import Any, Mapping

_EVENT_KIND_BY_TELECOM = {
    "TELECOM_CERT_EXPIRING": "certificate_expiring",
    "TELECOM_REACHABILITY_LOST": "agent_offline",
}
_DRIFT_KINDS = ("TELECOM_FINDINGS_CHANGED", "TELECOM_FINDING")
_ACTIONABLE_SEVERITIES = ("high", "critical")


def automation_event_kind(payload: Mapping[str, Any]) -> str | None:
    """Automation event kind for a telecom bus event, or None (not actionable)."""
    kind = str(payload.get("kind") or "").upper()
    if kind in _EVENT_KIND_BY_TELECOM:
        return _EVENT_KIND_BY_TELECOM[kind]
    if kind in _DRIFT_KINDS and str(payload.get("severity") or "").lower() in _ACTIONABLE_SEVERITIES:
        return "drift_detected"
    return None


def automation_data(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Condition data for the rules engine — telecom identity + context."""
    data = {
        "nf_id": payload.get("nf_id") or payload.get("target"),
        "nf_type": payload.get("nf_type"),
        "carrier_code": payload.get("carrier_code"),
        "plane": payload.get("plane"),
        "environment": payload.get("environment"),
        "severity": str(payload.get("severity") or "").upper(),
        "message": payload.get("message"),
        "endpoint": payload.get("endpoint"),
    }
    return {k: v for k, v in data.items() if v is not None}
