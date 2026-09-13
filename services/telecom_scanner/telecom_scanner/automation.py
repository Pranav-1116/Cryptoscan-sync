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
* ``TELECOM_PQC_DROPPED``          → ``quantum_vulnerable_detected``
  (a link LOST hybrid PQC — it is quantum-vulnerable again; reuses the
  existing pb_pqc playbook: rescan, CBOM refresh, migration queue, ticket,
  alert, gated approval. No new action vocabulary was invented.)
* everything else (recoveries, ``TELECOM_PQC_READY``, info findings,
  target added) → None — noise never wakes the automation engine.

The condition data handed to rules carries the telecom identity (nf_id,
carrier_code, plmn-adjacent fields, plane, environment) so operator rules
can target e.g. "plane == roaming" or "carrier_code == de-telekom".
"""
from __future__ import annotations

from typing import Any, Mapping

_EVENT_KIND_BY_TELECOM = {
    "TELECOM_CERT_EXPIRING": "certificate_expiring",
    "TELECOM_REACHABILITY_LOST": "agent_offline",
    "TELECOM_PQC_DROPPED": "quantum_vulnerable_detected",
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

def telecom_guardrail_rules() -> list[dict[str, Any]]:
    """Curated operator-installable guardrail rules for a telecom estate.

    Installed via POST /automation/telecom-guardrails (idempotent upsert);
    they ride the SAME rules engine, actions and governance gates as any
    operator-authored rule — this preset just encodes the 3GPP/NIST defaults
    so an operator does not have to author them by hand:

    * roaming PQC drop — a SEPP edge that LOST hybrid key exchange enters the
      PQC migration queue with a ticket and an alert (CRITICAL);
    * mission-plane NF down — a 5GC/EPC/IMS network function gone dark raises
      a ticket + NOC-visible alert (HIGH); roaming-plane down stays with the
      default pb_telecom_nf_down playbook;
    * SEPP certificate expiry — a ticket ahead of a roaming-link cert
      expiring (MEDIUM); rotation itself stays behind the playbook's gated
      approval.
    """
    return [
        {
            "rule_id": "guardrail-roaming-pqc-drop",
            "name": "Roaming PQC guardrail — hybrid key exchange lost",
            "when": "quantum_vulnerable_detected",
            "if": [{"field": "plane", "operator": "equals", "value": "roaming"}],
            "then": ["add_pqc_queue", "create_ticket", "create_alert"],
            "severity": "CRITICAL",
        },
        {
            "rule_id": "guardrail-mission-nf-down",
            "name": "Mission-plane NF down guardrail",
            "when": "agent_offline",
            "if": [{"field": "plane", "operator": "not_equals", "value": "roaming"}],
            "then": ["create_ticket", "create_alert"],
            "severity": "HIGH",
        },
        {
            "rule_id": "guardrail-sepp-cert-expiry",
            "name": "SEPP certificate expiry guardrail",
            "when": "certificate_expiring",
            "if": [{"field": "nf_type", "operator": "equals", "value": "sepp"}],
            "then": ["create_ticket"],
            "severity": "MEDIUM",
        },
    ]

