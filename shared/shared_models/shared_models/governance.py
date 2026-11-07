"""Governance workflows (roadmap item 9).

Findings become work: assignment, tickets, risk acceptance, expiring exceptions,
approvals, evidence attachment, auditor sign-off — and an **immutable audit**
that records every state change in a hash chain.

The rules this module enforces:

* roles are real: each transition checks the actor's role against a matrix, and
  a refused transition is refused — not silently allowed;
* a risk acceptance or an exception **must expire**: an authorisation with no end
  date is a permanent hole with a friendly name;
* an expired authorisation cannot be cited: "we accepted this" is only true
  while the acceptance is alive;
* decisions carry evidence: accepting risk, granting an exception and resolving
  all require evidence ids — a governance decision with no evidence is an
  assertion;
* the audit is append-only and hash-chained: every event commits to the previous
  hash, so a deleted or edited event breaks verification and is detected.

There is no update or delete entry point for audit events anywhere in this
module, by design.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

GOVERNANCE_SCHEMA = "cryptoscan.governance/1"

#: the six roles the roadmap names
PLATFORM_ADMIN = "PLATFORM_ADMIN"
SECURITY_ARCHITECT = "SECURITY_ARCHITECT"
CRYPTO_ENGINEER = "CRYPTO_ENGINEER"
INFRA_ENGINEER = "INFRA_ENGINEER"
AUDITOR = "AUDITOR"
EXECUTIVE = "EXECUTIVE"
ROLES: tuple[str, ...] = (PLATFORM_ADMIN, SECURITY_ARCHITECT, CRYPTO_ENGINEER,
                          INFRA_ENGINEER, AUDITOR, EXECUTIVE)

OPEN, ASSIGNED, IN_PROGRESS = "OPEN", "ASSIGNED", "IN_PROGRESS"
RISK_ACCEPTED, EXCEPTION_GRANTED = "RISK_ACCEPTED", "EXCEPTION_GRANTED"
RESOLVED, AUDITOR_SIGNED_OFF = "RESOLVED", "AUDITOR_SIGNED_OFF"
STATES: tuple[str, ...] = (OPEN, ASSIGNED, IN_PROGRESS, RISK_ACCEPTED,
                           EXCEPTION_GRANTED, RESOLVED, AUDITOR_SIGNED_OFF)

#: action → (allowed roles, from-states, to-state, needs expiry, needs evidence)
_ACTIONS: dict[str, tuple[frozenset[str], frozenset[str], str, bool, bool]] = {
    "ASSIGN": (frozenset({PLATFORM_ADMIN, SECURITY_ARCHITECT}),
               frozenset({OPEN}), ASSIGNED, False, False),
    "START": (frozenset({CRYPTO_ENGINEER, INFRA_ENGINEER, SECURITY_ARCHITECT}),
              frozenset({ASSIGNED}), IN_PROGRESS, False, False),
    "ACCEPT_RISK": (frozenset({SECURITY_ARCHITECT, EXECUTIVE}),
                    frozenset({IN_PROGRESS}), RISK_ACCEPTED, True, True),
    "GRANT_EXCEPTION": (frozenset({SECURITY_ARCHITECT}),
                        frozenset({IN_PROGRESS}), EXCEPTION_GRANTED, True, True),
    "RESOLVE": (frozenset({CRYPTO_ENGINEER, INFRA_ENGINEER, SECURITY_ARCHITECT}),
                frozenset({IN_PROGRESS}), RESOLVED, False, True),
    "SIGN_OFF": (frozenset({AUDITOR}),
                 frozenset({RISK_ACCEPTED, EXCEPTION_GRANTED, RESOLVED}),
                 AUDITOR_SIGNED_OFF, False, False),
}


def _canonical(event: Mapping[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"),
                      default=str)


def _hash(prev_hash: str, event: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        (prev_hash + _canonical(event)).encode("utf-8")).hexdigest()


def create_ticket(*, ticket_id: str, subject: str, opened_by: str,
                  role: str, now: Any) -> dict[str, Any]:
    """Open a ticket. The first audit event is the opening itself."""
    role_name = str(role or "").upper()
    if role_name not in ROLES:
        raise ValueError(f"unknown role {role!r}; expected one of {', '.join(ROLES)}")
    genesis = "sha256:" + "0" * 64
    event = {"seq": 0, "action": "OPEN_TICKET", "actor": str(opened_by),
             "role": role_name, "at": _stamp(now),
             "note": f"ticket {ticket_id} opened for {subject}",
             "evidence_ids": []}
    entry_hash = _hash(genesis, event)
    return {
        "schema": GOVERNANCE_SCHEMA,
        "ticket_id": str(ticket_id), "subject": str(subject),
        "state": OPEN, "assignee": None,
        "authorizations": [],
        "evidence_ids": [],
        "audit": [{**event, "prev_hash": genesis, "entry_hash": entry_hash}],
    }


def _stamp(now: Any) -> str:
    if isinstance(now, datetime):
        moment = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
        return moment.isoformat()
    return str(now)


def transition(ticket: Mapping[str, Any], action: str, *, actor: str, role: str,
               now: Any, evidence_ids: Sequence[str] = (),
               expires_at: str | None = None,
               note: str | None = None,
               assignee: str | None = None) -> dict[str, Any]:
    """Apply one governance action. Returns a NEW ticket; the input is untouched.

    Refusals raise ``ValueError`` with the rule that refused: wrong role, wrong
    state, a decision without evidence, or an authorisation without an expiry.
    """
    name = str(action or "").upper()
    if name not in _ACTIONS:
        raise ValueError(f"unknown governance action {action!r}; expected one of "
                         f"{', '.join(_ACTIONS)}")
    allowed_roles, from_states, to_state, needs_expiry, needs_evidence = _ACTIONS[name]
    role_name = str(role or "").upper()
    if role_name not in allowed_roles:
        raise ValueError(
            f"role {role_name} may not {name}: this action belongs to "
            f"{', '.join(sorted(allowed_roles))}")
    current = str(ticket.get("state") or OPEN)
    if current not in from_states:
        raise ValueError(
            f"{name} is not valid from state {current}: valid from "
            f"{', '.join(sorted(from_states))}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if needs_evidence and not ids:
        raise ValueError(
            f"{name} is a decision and requires evidence: a governance decision "
            f"with no evidence is an assertion")
    if needs_expiry and not str(expires_at or "").strip():
        raise ValueError(
            f"{name} requires expires_at: an authorisation with no end date is a "
            f"permanent hole with a friendly name")

    event: dict[str, Any] = {
        "seq": len(ticket.get("audit") or []),
        "action": name, "actor": str(actor), "role": role_name,
        "at": _stamp(now),
        "note": str(note) if note else None,
        "evidence_ids": ids,
    }
    audit = list(ticket.get("audit") or [])
    prev_hash = audit[-1]["entry_hash"] if audit else "sha256:" + "0" * 64
    entry_hash = _hash(prev_hash, event)
    audit.append({**event, "prev_hash": prev_hash, "entry_hash": entry_hash})

    authorizations = [dict(a) for a in ticket.get("authorizations") or []]
    if needs_expiry:
        authorizations.append({
            "kind": name, "granted_by": str(actor), "role": role_name,
            "granted_at": _stamp(now), "expires_at": str(expires_at),
            "evidence_ids": ids, "active": True,
        })

    return {
        **{k: v for k, v in dict(ticket).items()
           if k not in {"state", "audit", "authorizations", "assignee", "evidence_ids"}},
        "state": to_state,
        "assignee": (str(assignee) if assignee
                     else (str(actor) if name == "ASSIGN" else ticket.get("assignee"))),
        "authorizations": authorizations,
        "evidence_ids": sorted(set(ticket.get("evidence_ids") or []) | set(ids)),
        "audit": audit,
    }


def active_authorization(ticket: Mapping[str, Any], *, now: Any,
                         kind: str | None = None) -> dict[str, Any]:
    """The live authorisation for this ticket, or an honest refusal.

    An expired acceptance or exception cannot be cited: the record stays in the
    history and says exactly why it is no longer usable.
    """
    moment = datetime.fromisoformat(_stamp(now).replace("Z", "+00:00"))
    for auth in ticket.get("authorizations") or []:
        if kind and auth.get("kind") != kind:
            continue
        expiry = datetime.fromisoformat(
            str(auth["expires_at"]).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry >= moment:
            return {"usable": True, "authorization": auth,
                    "reason": "the authorisation is inside its window"}
    return {"usable": False, "authorization": None,
            "reason": ("no live authorisation: either none was granted or every "
                       "grant has expired — an expired authorisation cannot be "
                       "cited, and its absence is not consent")}


def verify_audit(ticket: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute the hash chain. Any edit, deletion or reordering is detected."""
    audit = ticket.get("audit") or []
    prev_hash = "sha256:" + "0" * 64
    for index, entry in enumerate(audit):
        if entry.get("seq") != index:
            return {"verified": False,
                    "problem": f"audit sequence broken at entry {index}"}
        if entry.get("prev_hash") != prev_hash:
            return {"verified": False,
                    "problem": f"previous-hash mismatch at entry {index}: an "
                               f"entry was inserted, removed or reordered"}
        material = {k: v for k, v in entry.items()
                    if k not in {"entry_hash", "prev_hash"}}
        expected = _hash(prev_hash, material)
        if entry.get("entry_hash") != expected:
            return {"verified": False,
                    "problem": f"entry hash mismatch at entry {index}: the "
                               f"entry was edited after it was written"}
        prev_hash = entry["entry_hash"]
    return {"verified": True,
            "problem": None,
            "entries": len(audit),
            "note": ("the audit is append-only and hash-chained: every event "
                     "commits to the one before it")}
