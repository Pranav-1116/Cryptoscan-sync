"""Rate-limit auditing: three states that a policy inventory alone cannot tell apart.

The audit is where configured and observed meet without merging. Each finding carries the
configured evidence id *and* the observed evidence id, and each state is a different claim:

===================================  =====================================================
``NOT_CONFIGURED``                   traffic reached an API with no limit attached to it
``WITHIN_LIMIT``                     a limit exists and the observed volume is under it
``OVER_LIMIT``                       a limit exists and the observed volume is over it
``POLICY_NOT_ATTACHED``              a policy exists, is enabled, and protects nothing
===================================  =====================================================

An observation that arrives without an evidence id is refused and named, because a volume
nobody can point at is the kind of number this layer exists to replace.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .base import CONFIGURED, OBSERVED, ControlRefused, _norm

NOT_CONFIGURED = "NOT_CONFIGURED"
WITHIN_LIMIT = "WITHIN_LIMIT"
OVER_LIMIT = "OVER_LIMIT"
POLICY_NOT_ATTACHED = "POLICY_NOT_ATTACHED"
UNKNOWN = "UNKNOWN"

FINDING_STATES: tuple[str, ...] = (NOT_CONFIGURED, WITHIN_LIMIT, OVER_LIMIT,
                                   POLICY_NOT_ATTACHED, UNKNOWN)


def _traffic_rows(collector: Any, traffic: Iterable[Mapping[str, Any]] | None) -> list[Any]:
    rows = traffic if traffic is not None else collector.feed.get("traffic") or []
    return [row for row in rows if isinstance(row, Mapping)]


def audit_rate_limits(collector: Any,
                      traffic: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Audit one rate-limit collector against observed traffic.

    ``collector`` is a :class:`~.rate_limit.base.RateLimitCollector`; ``traffic`` rows are
    ``{"api", "requests", "window_seconds", "evidence_id"}``. When ``traffic`` is omitted the
    feed's own ``traffic`` section is used, so a collector and its observations travel
    together.
    """
    if not hasattr(collector, "attached_limits"):
        raise ControlRefused("NOT_A_RATE_LIMITER",
                             "audit_rate_limits() takes a RateLimitCollector; a limit "
                             "audit needs the limits as well as the traffic")
    attached = collector.attached_limits()
    findings: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []

    api_to_policy: dict[str, str] = {}
    for policy, row in attached.items():
        for api in row["apis"]:
            api_to_policy[api] = policy

    seen_apis: set[str] = set()
    for row in _traffic_rows(collector, traffic):
        api = _norm(row.get("api"))
        observed = row.get("requests")
        window = row.get("window_seconds") or 60
        evidence = _norm(row.get("evidence_id"))
        if not api:
            refusals.append({"code": "TRAFFIC_WITHOUT_API", "subject": dict(row),
                             "reason": "an observation that names no API cannot be audited"})
            continue
        if not evidence:
            refusals.append({"code": "OBSERVATION_WITHOUT_EVIDENCE", "subject": api,
                             "reason": "a request volume with no evidence id is a number "
                                       "nobody can point at; it is refused, not counted"})
            continue
        if observed is None:
            refusals.append({"code": "OBSERVATION_WITHOUT_VOLUME", "subject": api,
                             "reason": "the traffic row carries an API and no volume"})
            continue
        seen_apis.add(api)
        policy = api_to_policy.get(api)
        if not policy:
            findings.append({
                "api": api,
                "policy": None,
                "state": NOT_CONFIGURED,
                "expected": None,
                "observed": {"requests": observed, "window_seconds": window},
                "facts": [OBSERVED],
                "evidence_ids": [evidence],
                "reason": f"{api} carried traffic and no rate-limit policy is attached to "
                          "it; this is a decision the bank has not made, not a reading we "
                          "could not take",
            })
            continue
        limit = attached[policy]["limit"]
        configured = float(limit["limit"])
        configured_window = float(limit["window_seconds"] or 60)
        expected = configured * (float(window) / configured_window)
        over = float(observed) > expected
        findings.append({
            "api": api,
            "policy": policy,
            "state": OVER_LIMIT if over else WITHIN_LIMIT,
            "expected": {"requests": round(expected, 3),
                         "limit": configured, "window_seconds": configured_window},
            "observed": {"requests": observed, "window_seconds": window},
            "facts": [CONFIGURED, OBSERVED],
            "evidence_ids": [limit["evidence_id"], evidence],
            "reason": (f"{api} observed {observed} requests in {window}s against a "
                       f"configured {configured:g}/{configured_window:g}s "
                       f"({expected:g} expected); the two numbers are kept side by side"),
        })

    for policy, row in attached.items():
        if row["apis"]:
            continue
        if not row["limit"]["enabled"]:
            state_reason = (f"{policy} exists and is disabled; a disabled policy is a "
                            "decision, and the APIs it names are unprotected")
        else:
            state_reason = (f"{policy} is enabled, configured for "
                            f"{row['limit']['limit']}/{row['limit']['window_seconds']}s, and "
                            "is attached to no API: the policy exists, the coverage does not")
        findings.append({
            "api": None,
            "policy": policy,
            "state": POLICY_NOT_ATTACHED,
            "expected": {"limit": row["limit"]["limit"],
                         "window_seconds": row["limit"]["window_seconds"]},
            "observed": None,
            "facts": [CONFIGURED],
            "evidence_ids": [row["limit"]["evidence_id"]],
            "reason": state_reason,
        })

    summary = {state: 0 for state in FINDING_STATES}
    for finding in findings:
        summary[finding["state"]] += 1
    return {
        "control": "RATE_LIMIT",
        "vendor": getattr(collector, "vendor", None),
        "findings": sorted(findings, key=lambda item: (item["state"], str(item["api"]))),
        "summary": summary,
        "refusals": refusals,
        "apis_with_traffic": sorted(seen_apis),
        "policies": sorted(attached),
        "note": "NOT_CONFIGURED is a finding about a decision; UNKNOWN is a coverage gap, "
                "and this audit does not report the first as the second",
    }
