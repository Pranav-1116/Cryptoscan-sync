"""One vocabulary for "what happened to this control", used everywhere it is reported.

The failure this module exists to prevent is a single one: **"no findings" as the universal
answer**. A control that was never reached, a control that answered `401`, a control that
answered three of seven sections, and a dialect nobody has written a driver for all produce the
same empty list of findings — and a console that renders the list renders all four as "nothing
to report".

So the layer has one taxonomy, and every surface that reports a control's state reports it in
these terms: the collector's ``health()``, ``live_snapshot()``'s ``read`` block, the projection's
``summary.coverage``, the API's ``/security-controls/health`` route, and the harness.

The states, and why each is distinct
------------------------------------

======================================  ==============================================
state                                   means
======================================  ==============================================
``OK``                                  every declared section was read
``PARTIAL_READ``                        some sections answered; ``failed_sections`` names
                                        the rest — *not* a pass and *not* a failure
``AUTH_FAILED``                         the credential was refused (401/403); the device is
                                        reachable and we are not admitted
``RATE_LIMITED``                        the device asked us to slow down; the read is
                                        incomplete because the device said so
``BAD_RESPONSE``                        the device answered with something that is not the
                                        dialect (wrong shape, 404 on a declared endpoint)
``UNREACHABLE``                         no answer at all — network, timeout, refused socket
``UNSUPPORTED_DIALECT``                 nobody wrote a driver for this vendor; the dialect row
                                        still documents its endpoints and nothing was read
``NOT_CONFIGURED``                      the control was never given to the platform: no
                                        credential, no address, no feed
``REFUSED``                             the layer refused the read on a rule — a non-GET
                                        method, an unverified TLS session, a mutating spec
======================================  ==============================================

Grouping matters for reporting: ``OK`` and ``PARTIAL_READ`` are **collected** (something is
known), ``AUTH_FAILED``/``RATE_LIMITED``/``BAD_RESPONSE``/``UNREACHABLE`` are **failed**
(nothing new is known), ``UNSUPPORTED_DIALECT``/``NOT_CONFIGURED`` are **absent** (the platform
was never able to ask). A summary that mixes the three is how a coverage gap becomes a
reassurance.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .base import _norm

OK = "OK"
PARTIAL_READ = "PARTIAL_READ"
AUTH_FAILED = "AUTH_FAILED"
RATE_LIMITED = "RATE_LIMITED"
BAD_RESPONSE = "BAD_RESPONSE"
UNREACHABLE = "UNREACHABLE"
UNSUPPORTED_DIALECT = "UNSUPPORTED_DIALECT"
NOT_CONFIGURED = "NOT_CONFIGURED"
REFUSED = "REFUSED"

#: every state a control can be in, strongest first
STATES: tuple[str, ...] = (OK, PARTIAL_READ, AUTH_FAILED, RATE_LIMITED, BAD_RESPONSE,
                           UNREACHABLE, UNSUPPORTED_DIALECT, NOT_CONFIGURED, REFUSED)

#: states in which the layer learned something. A partial read is here because three of seven
#: sections is knowledge; it is simply not complete knowledge.
COLLECTED: frozenset[str] = frozenset({OK, PARTIAL_READ})
#: states in which the control was reachable in principle and the read still failed
FAILED: frozenset[str] = frozenset({AUTH_FAILED, RATE_LIMITED, BAD_RESPONSE, UNREACHABLE})
#: states in which the platform could not ask at all — an integration gap, not a device fault
ABSENT: frozenset[str] = frozenset({UNSUPPORTED_DIALECT, NOT_CONFIGURED})
#: states the layer chose, deliberately
CHOSEN: frozenset[str] = frozenset({REFUSED})

_SEVERITY: dict[str, int] = {
    OK: 0, PARTIAL_READ: 2, REFUSED: 3, NOT_CONFIGURED: 4, UNSUPPORTED_DIALECT: 4,
    RATE_LIMITED: 5, BAD_RESPONSE: 6, AUTH_FAILED: 7, UNREACHABLE: 8,
}

_MEANING: dict[str, str] = {
    OK: "every declared section was read",
    PARTIAL_READ: ("some declared sections answered and some did not; the rows that arrived are "
                   "stored and the sections that failed are named"),
    AUTH_FAILED: ("the device is reachable and refused the credential; this is an admission "
                  "problem, not a network one"),
    RATE_LIMITED: ("the device asked the collector to slow down, so the read is incomplete "
                   "because the device said so"),
    BAD_RESPONSE: ("the device answered with something that is not this dialect: a wrong "
                   "shape, or a 404 on an endpoint the adapter declares"),
    UNREACHABLE: "no answer at all — a refused socket, a timeout, or a route that does not exist",
    UNSUPPORTED_DIALECT: ("no driver exists for this vendor; its dialect row documents the "
                          "endpoints and nothing was read"),
    NOT_CONFIGURED: ("the control was never given to the platform: no credential, no address, "
                     "no feed"),
    REFUSED: ("the layer refused the read on its own rule — a non-GET method, an unverified "
              "TLS session, a spec that declared a write"),
}

_ACTION: dict[str, str] = {
    OK: "none",
    PARTIAL_READ: ("read the failed sections by hand, or fix the endpoint the dialect declares "
                   "for them"),
    AUTH_FAILED: "rotate the collector credential and re-read",
    RATE_LIMITED: "widen the collection interval or raise the device's API quota",
    BAD_RESPONSE: "check the device's API version against the dialect row",
    UNREACHABLE: "check the route, the DNS name and the listener",
    UNSUPPORTED_DIALECT: "add a dialect row, or collect this vendor through an existing path",
    NOT_CONFIGURED: "give the control an address and a credential, or record why it is absent",
    REFUSED: "read the refusal: the layer will not do this, and the reason is in the record",
}

#: states a caller should retry unchanged
RETRYABLE: frozenset[str] = frozenset({RATE_LIMITED, UNREACHABLE, BAD_RESPONSE})


def normalise(state: Any) -> str:
    """A state from any spelling a caller might have used, or a refusal.

    Transport states, collector states and taxonomy states are the same strings where they
    overlap, and this is the one place that fact is asserted rather than assumed.
    """
    text = _norm(state).upper()
    if text in STATES:
        return text
    from .base import ControlRefused

    raise ControlRefused(
        "UNKNOWN_STATE",
        f"{text or '(none)'} is not a state this layer reports; it reports "
        f"{', '.join(STATES)}. An unknown state is not a quiet one — it is a bug in whatever "
        "produced it.")


def describe(state: Any) -> dict[str, Any]:
    """Everything a console needs to render one state without inventing the wording."""
    code = normalise(state)
    group = ("COLLECTED" if code in COLLECTED else
             "ABSENT" if code in ABSENT else
             "CHOSEN" if code in CHOSEN else "FAILED")
    return {
        "state": code,
        "group": group,
        "meaning": _MEANING[code],
        "operator_action": _ACTION[code],
        "retryable": code in RETRYABLE,
        "severity": _SEVERITY[code],
        "collected": code in COLLECTED,
    }


def worst(states: Iterable[Any]) -> str:
    """The state a set of sections reduces to. Empty is ``NOT_CONFIGURED``, never ``OK``."""
    values = [normalise(state) for state in states or ()]
    if not values:
        return NOT_CONFIGURED
    return max(values, key=lambda code: _SEVERITY[code])


def summarise(entries: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Coverage over a set of controls, with the sentence a console must not omit.

    ``entries`` are mappings with at least ``control`` and ``state``; anything else is carried
    into ``per_control`` untouched so a caller can render the detail it already has.
    """
    rows = [dict(row) for row in entries or ()]
    counts = {state: 0 for state in STATES}
    per_control: list[dict[str, Any]] = []
    for row in rows:
        code = normalise(row.get("state"))
        counts[code] += 1
        per_control.append({**describe(code), "control": _norm(row.get("control")),
                            "vendor": row.get("vendor"), "system": row.get("system"),
                            "detail": row.get("detail")})
    total = len(rows)
    collected = sum(count for code, count in counts.items() if code in COLLECTED)
    failed = sum(count for code, count in counts.items() if code in FAILED)
    absent = sum(count for code, count in counts.items() if code in ABSENT)
    refused = sum(count for code, count in counts.items() if code in CHOSEN)
    complete = bool(total) and counts[OK] == total
    return {
        "total": total,
        "counts": {code: count for code, count in counts.items() if count},
        "collected": collected,
        "failed": failed,
        "absent": absent,
        "refused": refused,
        "complete": complete,
        # a run with nothing configured is not a clean run, it is an empty one
        "nothing_asked": total == 0,
        "worst": worst([row.get("state") for row in rows]) if rows else NOT_CONFIGURED,
        "statement": _statement(total=total, collected=collected, failed=failed, absent=absent,
                                refused=refused, ok=counts[OK]),
        "per_control": sorted(per_control, key=lambda row: row["control"]),
    }


def _statement(*, total: int, collected: int, failed: int, absent: int, refused: int,
               ok: int) -> str:
    if total == 0:
        return ("no control was asked: an empty collection is a collection that did not "
                "happen, not one that found nothing")
    parts = [f"{collected} of {total} control(s) were read"]
    if ok == total:
        return parts[0] + ", all completely"
    if failed:
        parts.append(f"{failed} could not be read")
    if absent:
        parts.append(f"{absent} could not be asked (no driver or no configuration)")
    if refused:
        parts.append(f"{refused} was refused by the layer's own rules")
    if collected != total:
        parts.append("the rows from the remaining controls are not evidence of their state")
    return "; ".join(parts)


def for_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """What changed in coverage between two collections.

    A read that used to be complete and is now partial is a finding in its own right, and it is
    the one an operator most needs: the estate did not change, the collector did.
    """
    left = {row["control"]: row["state"] for row in before.get("per_control") or []}
    right = {row["control"]: row["state"] for row in after.get("per_control") or []}
    degraded = [{"control": control, "was": left[control], "now": right[control]}
                for control in sorted(set(left) & set(right))
                if left[control] in COLLECTED and right[control] not in COLLECTED]
    recovered = [{"control": control, "was": left[control], "now": right[control]}
                 for control in sorted(set(left) & set(right))
                 if left[control] not in COLLECTED and right[control] in COLLECTED]
    return {
        "degraded": degraded,
        "recovered": recovered,
        "appeared": sorted(set(right) - set(left)),
        "disappeared": sorted(set(left) - set(right)),
        "regressed": bool(degraded),
        "statement": (f"{len(degraded)} control(s) stopped being readable and "
                      f"{len(recovered)} started" if degraded or recovered
                      else "coverage is unchanged"),
    }
