"""Threat finding lifecycle (gap analysis §G): the consistent finding structure
and the four-level change distinction.

A finding is not a feeling: every record carries the field set the review names
(``finding_id`` … ``owner``) and evidence behind it. The change ladder is
strictly one-way in *proof*, never in automation:

1. ``CONFIGURATION_CHANGE`` — an expected vs unexpected difference,
2. ``SUSPICIOUS_CHANGE`` — a change that fails a policy or pattern,
3. ``CORRELATED_PATTERN`` — several observations that correlate,
4. ``CONFIRMED_INCIDENT`` — a compromise confirmed by a human with incident
   evidence.

**A pattern never automatically becomes a confirmed compromise.** The engine
may build records up to ``CORRELATED_PATTERN``; ``CONFIRMED_INCIDENT`` is only
reachable through :func:`confirm_incident`, which requires the incident
reference and the human who confirmed it. There is no code path from
correlation to confirmation without a human.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

FINDING_SCHEMA = "cryptoscan.finding-lifecycle/1"

CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
SUSPICIOUS_CHANGE = "SUSPICIOUS_CHANGE"
CORRELATED_PATTERN = "CORRELATED_PATTERN"
CONFIRMED_INCIDENT = "CONFIRMED_INCIDENT"
CHANGE_CLASSES: tuple[str, ...] = (CONFIGURATION_CHANGE, SUSPICIOUS_CHANGE,
                                   CORRELATED_PATTERN, CONFIRMED_INCIDENT)

SEVERITIES: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
CONFIDENCE_LEVELS: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH"})

OPEN, ASSIGNED, INVESTIGATING = "OPEN", "ASSIGNED", "INVESTIGATING"
RESOLVED, ACCEPTED = "RESOLVED", "ACCEPTED"
STATUSES: tuple[str, ...] = (OPEN, ASSIGNED, INVESTIGATING, RESOLVED, ACCEPTED)

#: classes an engine-built record may hold on its own
ENGINE_REACHABLE: frozenset[str] = frozenset(
    {CONFIGURATION_CHANGE, SUSPICIOUS_CHANGE, CORRELATED_PATTERN})


def finding_record(*, finding_id: str, pattern_id: str, tenant_id: str,
                   affected_asset_ids: Sequence[str],
                   affected_system_ids: Sequence[str],
                   severity: str, confidence: str, first_seen: str,
                   last_seen: str, evidence_ids: Sequence[str],
                   observed_change: str, expected_state: str, reason: str,
                   not_proven: str, recommended_investigation: str,
                   change_class: str = CONFIGURATION_CHANGE,
                   owner: str | None = None,
                   status: str = OPEN) -> dict[str, Any]:
    """One finding in the consistent structure. Evidence is mandatory.

    Refusals: a finding with no evidence is a rumour; a class above
    ``CORRELATED_PATTERN`` is not the engine's to claim; a finding with no
    ``not_proven`` statement overclaims certainty; empty ``reason`` or
    ``expected_state`` leaves the finding unexplainable.
    """
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "a finding with no evidence is a rumour: file the observations "
            "behind it or do not record a finding")
    cls = str(change_class or "").upper()
    if cls not in CHANGE_CLASSES:
        raise ValueError(f"unknown change class {change_class!r}; expected one "
                         f"of {', '.join(CHANGE_CLASSES)}")
    if cls not in ENGINE_REACHABLE:
        raise ValueError(
            f"{cls} is not the engine's to claim: a pattern never "
            f"automatically becomes a confirmed compromise — a human confirms "
            f"with incident evidence via confirm_incident()")
    sev = str(severity or "").upper()
    if sev not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}; expected one of "
                         f"{', '.join(sorted(SEVERITIES))}")
    conf = str(confidence or "").upper()
    if conf not in CONFIDENCE_LEVELS:
        raise ValueError(f"unknown confidence {confidence!r}; expected one of "
                         f"{', '.join(sorted(CONFIDENCE_LEVELS))}")
    if not str(not_proven or "").strip():
        raise ValueError(
            "not_proven is mandatory: a finding that names no uncertainty "
            "overclaims certainty")
    for field_name, value in (("observed_change", observed_change),
                              ("expected_state", expected_state),
                              ("reason", reason),
                              ("recommended_investigation",
                               recommended_investigation)):
        if not str(value or "").strip():
            raise ValueError(f"{field_name} is mandatory: a finding must say "
                             f"what changed, what was expected, why it "
                             f"matters, and what to investigate")
    state = str(status or "").upper()
    if state not in STATUSES:
        raise ValueError(f"unknown status {status!r}; expected one of "
                         f"{', '.join(STATUSES)}")
    return {
        "schema": FINDING_SCHEMA,
        "finding_id": str(finding_id),
        "tenant_id": str(tenant_id),
        "pattern_id": str(pattern_id),
        "affected_asset_ids": [str(a) for a in affected_asset_ids if str(a).strip()],
        "affected_system_ids": [str(s) for s in affected_system_ids if str(s).strip()],
        "severity": sev,
        "confidence": conf,
        "first_seen": str(first_seen),
        "last_seen": str(last_seen),
        "evidence_ids": ids,
        "observed_change": str(observed_change),
        "expected_state": str(expected_state),
        "reason": str(reason),
        "not_proven": str(not_proven),
        "recommended_investigation": str(recommended_investigation),
        "change_class": cls,
        "status": state,
        "owner": str(owner) if owner else None,
        "confirmation": None,
    }


def confirm_incident(finding: Mapping[str, Any], *, incident_ref: str,
                     actor: str, at: str,
                     evidence_ids: Sequence[str]) -> dict[str, Any]:
    """The only path to ``CONFIRMED_INCIDENT`` — a human, named, with incident
    evidence. Returns a new record; the input is untouched.

    An engine-written ``CORRELATED_PATTERN`` stays a pattern until this is
    called. Confirmation without an incident reference or without a human
    actor is refused.
    """
    if not str(incident_ref or "").strip():
        raise ValueError(
            "an incident reference is mandatory: a confirmed compromise names "
            "the incident it was confirmed under")
    if not str(actor or "").strip():
        raise ValueError(
            "confirmation requires a named human: the engine cannot confirm "
            "its own pattern")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "confirmation requires incident evidence: a confirmation with no "
            "evidence is a rumour about a rumour")
    updated = dict(finding)
    updated["change_class"] = CONFIRMED_INCIDENT
    updated["confirmation"] = {
        "incident_ref": str(incident_ref), "actor": str(actor),
        "at": str(at), "evidence_ids": ids,
    }
    return updated


def assign(finding: Mapping[str, Any], *, owner: str, actor: str) -> dict[str, Any]:
    """Finding assignment (gap analysis §J). The assigner is recorded."""
    if not str(owner or "").strip():
        raise ValueError("an owner is mandatory: an unassigned finding is a "
                         "finding nobody owns")
    if not str(actor or "").strip():
        raise ValueError("the assigning actor is mandatory: assignment is a "
                         "decision and decisions have actors")
    updated = dict(finding)
    updated["owner"] = str(owner)
    updated["status"] = ASSIGNED
    updated.setdefault("assignments", []).append(
        {"owner": str(owner), "actor": str(actor)})
    return updated


def finding_digest(finding: Mapping[str, Any]) -> str:
    """Deterministic digest over the finding body — reproducibility, not proof."""
    body = {k: v for k, v in dict(finding).items() if k != "schema"}
    material = repr(sorted(body.items())).encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()
