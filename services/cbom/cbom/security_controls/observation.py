"""Rate-limit observation: the counters, the window arithmetic, and what it refuses.

Guide 181 compared a configured limit with a traffic row a caller supplied. Two things were
wrong with that as an audit:

1. **the numbers came from the fixture.** A bank's question is "we served 900 requests in this
   minute — was that inside our policy?" and the answer has to come from the limiter's own
   counters or the gateway's access log, not from a spreadsheet row typed into a test;
2. **the window was assumed.** A fixed-window limiter (NGINX ``limit_req``, Kong's
   ``minute``) permits *N per aligned window*: at 100/min, a minute is at most 100. A sliding
   limiter permits *N in any rolling window*: at 100/min, 60 requests at 09:00:30 and 60 at
   09:01:00 are 120 in a rolling minute and legal under a fixed counter. Comparing an observed
   count against the wrong one of those produces a finding that is arithmetic, not evidence.

So this module adds three things and refuses a fourth:

* **an observation source** — the gateway's counters (:class:`CounterAPI`), the access log
  (:class:`AccessLog`), or a limiter's own violation records (:class:`LimitViolations`), each
  producing rows with an evidence id or nothing at all;
* **a window model** per policy — ``FIXED`` or ``SLIDING``, read from the device and never
  guessed;
* **a comparable expected value** — the same arithmetic the limiter performs;
* **refusal** — when the observed window cannot be aligned with the configured one (an
  unaligned sample for a fixed limiter, or a mismatched window length), the finding is
  ``INCOMPARABLE_WINDOW`` rather than ``OVER_LIMIT``. A verdict the data cannot support is the
  one thing an audit must not print.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Protocol

from .base import CONFIGURED, OBSERVED, ControlRefused, _norm

FIXED = "FIXED"
SLIDING = "SLIDING"
WINDOW_MODES: tuple[str, ...] = (FIXED, SLIDING)

#: finding states this module can produce. ``INCOMPARABLE_WINDOW`` is new in guide 182 and is
#: deliberately not folded into ``UNKNOWN``: the data arrived, and it does not describe the
#: same interval as the limit.
NOT_CONFIGURED = "NOT_CONFIGURED"
WITHIN_LIMIT = "WITHIN_LIMIT"
OVER_LIMIT = "OVER_LIMIT"
POLICY_NOT_ATTACHED = "POLICY_NOT_ATTACHED"
INCOMPARABLE_WINDOW = "INCOMPARABLE_WINDOW"
UNKNOWN = "UNKNOWN"

FINDING_STATES: tuple[str, ...] = (NOT_CONFIGURED, WITHIN_LIMIT, OVER_LIMIT,
                                   POLICY_NOT_ATTACHED, INCOMPARABLE_WINDOW, UNKNOWN)


def _moment(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Observation sources
# --------------------------------------------------------------------------- #

class ObservationSource(Protocol):
    """One method: the traffic rows this source can state, or none."""

    def observations(self) -> tuple[list[dict[str, Any]], dict[str, Any]]: ...


@dataclass
class CounterAPI:
    """The gateway's own counters, read through its read-only API.

    ``path`` answers a JSON object keyed by route or API name; ``counter_field`` says where the
    count lives inside each row. Nothing is computed from a name: a route the response does not
    mention is simply absent, and the audit reports the gap.
    """

    transport: Any
    path: str
    routes: tuple[str, ...] = ()
    counter_field: str = "requests"
    window_field: str = "window_seconds"
    captured_field: str = "since"
    default_window: int = 60

    def observations(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        result = self.transport.get(self.path)
        if not result.ok:
            return [], {"source": "counter-api", "state": result.state,
                        "reason": result.reason, "rows": 0}
        body = result.body
        rows: list[dict[str, Any]] = []
        records = _as_rows(body)
        for record in records:
            api = _norm(record.get("api") or record.get("route") or record.get("name"))
            if not api:
                continue
            count = record.get(self.counter_field)
            if count is None:
                continue
            window = record.get(self.window_field) or self.default_window
            rows.append({
                "api": api, "requests": float(count),
                "window_seconds": float(window),
                "window_mode": _norm(record.get("window_mode") or record.get("mode")).upper()
                or FIXED,
                "aligned": bool(record.get("aligned", False)),
                "captured_at": record.get(self.captured_field) or record.get("captured_at"),
                "evidence_id": _evidence("counter", api, record, result),
                "source": "counter-api",
            })
        return rows, {"source": "counter-api", "state": result.state, "rows": len(rows),
                      "missing_routes": sorted(set(self.routes) - {row["api"] for row in rows}),
                      "reason": None}


@dataclass
class AccessLog:
    """Gateway access records, counted into per-minute buckets.

    The log is read through the same read-only file transport as a sensor's events, so a
    gateway cannot be a new kind of connection. Only the request line's route and the
    timestamp are counted — no header, no cookie, no body is read, because the audit needs a
    number and not a request.
    """

    tail: Any
    window_seconds: int = 60
    route_field: str = "upstream"
    time_field: str = "time"

    def observations(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        records, detail = self.tail.read_lines()
        if detail.get("state") != "OK":
            return [], {"source": "access-log", "state": detail.get("state"),
                        "reason": detail.get("reason"), "rows": 0}
        buckets: dict[str, list[datetime]] = {}
        skipped = 0
        for record in records:
            api = _norm(record.get(self.route_field))
            moment = _moment(record.get(self.time_field))
            if not api or moment is None:
                skipped += 1
                continue
            buckets.setdefault(api, []).append(moment)
        rows: list[dict[str, Any]] = []
        for api, moments in sorted(buckets.items()):
            span = (max(moments) - min(moments)).total_seconds()
            # a bucket is only a window if the log spans one; otherwise the caller has a
            # partial minute and the audit must refuse to call it a rate
            rows.append({
                "api": api, "requests": float(len(moments)),
                "window_seconds": float(max(self.window_seconds, span or 0) or
                                        self.window_seconds),
                "window_mode": FIXED,
                "captured_at": min(moments).isoformat(),
                "evidence_id": _evidence("access-log", api,
                                         {"requests": len(moments),
                                          "first": min(moments).isoformat(),
                                          "last": max(moments).isoformat()}, None),
                "source": "access-log",
                "partial_window": bool(span and span < self.window_seconds),
            })
        return rows, {"source": "access-log", "state": "OK", "rows": len(rows),
                      "skipped_records": skipped, "reason": None}


@dataclass
class LimitViolations:
    """The limiter's own violation records — already a measurement, already in its window."""

    collector: Any

    def observations(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for violation in self.collector.violations():
            observed = violation.get("observed")
            if observed in (None, ""):
                continue
            rows.append({
                "api": violation.get("api") or violation.get("policy"),
                "requests": float(observed),
                "expected": violation.get("expected"),
                "window_seconds": float(self.collector.feed.get("window_seconds") or 60),
                "window_mode": _norm(self.collector.feed.get("window_mode")).upper()
                or FIXED,
                "captured_at": violation.get("at"),
                "evidence_id": violation["evidence_id"],
                "source": "limiter-violations",
            })
        return rows, {"source": "limiter-violations", "state": "OK", "rows": len(rows),
                      "reason": None}


def _as_rows(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return [dict(row) for row in body if isinstance(row, Mapping)]
    if isinstance(body, Mapping):
        for key in ("routes", "data", "results", "items", "counters"):
            value = body.get(key)
            if isinstance(value, list):
                return [dict(row) for row in value if isinstance(row, Mapping)]
            if isinstance(value, Mapping):
                return [{"api": name, **dict(row)} for name, row in value.items()
                        if isinstance(row, Mapping)]
    return []


def _evidence(kind: str, api: str, payload: Mapping[str, Any], result: Any) -> str:
    from .base import digest

    return f"EVID-OBS-{digest({'kind': kind, 'api': api, 'payload': payload}, 12)}"


# --------------------------------------------------------------------------- #
# Window arithmetic
# --------------------------------------------------------------------------- #

@dataclass
class WindowModel:
    """How one limiter actually counts, and what that permits in an observed window."""

    mode: str = FIXED
    limit: float = 0.0
    window_seconds: float = 60.0

    def __post_init__(self) -> None:
        self.mode = _norm(self.mode).upper() or FIXED
        if self.mode not in WINDOW_MODES:
            raise ControlRefused(
                "UNKNOWN_WINDOW_MODE",
                f"{self.mode} is not a window model; a fixed and a sliding counter permit "
                f"different traffic, so {', '.join(WINDOW_MODES)} are the only answers")

    def expected(self, observed_seconds: float,
                 *, aligned: bool = False) -> tuple[float, str]:
        """The requests this policy permits over the observed span, and how it was derived.

        The two models differ at exactly one place, and it is the place a naive audit gets
        wrong: **the boundary**. A fixed counter resets on an aligned instant, so a client can
        spend a full allowance at the end of one window and another at the start of the next —
        twice the configured rate inside one rolling window, entirely legal. A sliding counter
        has no boundary: *N* in any rolling window, ever.

        ``aligned`` says the observation is the counter's own closed window (the gateway
        reported "since 03:00:00, 60s"), in which case the boundary cannot be straddled and
        the allowance is the plain sum. An unaligned sample gets the boundary-tolerant bound,
        because calling a legal burst a breach is the failure mode that makes an audit
        untrustworthy.
        """
        span = float(observed_seconds or self.window_seconds)
        window = float(self.window_seconds or 60)
        if self.mode == FIXED:
            if aligned:
                whole = int(span // window) or 1
                remainder = span - whole * window
                return (self.limit * whole + (self.limit if remainder > 0 else 0),
                        f"{whole} aligned window(s)"
                        + (" plus a partial one" if remainder > 0 else ""))
            touched = int(span // window) + 1
            return (self.limit * touched,
                    f"at most {touched} aligned window(s) touched, so a boundary burst of "
                    f"{self.limit:g} per window is possible and is not a breach")
        # sliding: the rate is sustained, so the span permits its proportional share and no
        # more — this is why the same traffic can be legal under one model and not the other
        return (self.limit * max(1.0, span / window),
                f"rolling {self.limit:g} per {window:g}s, sustained over {span:g}s")

    def comparability(self, observed: Mapping[str, Any]) -> tuple[bool, str]:
        """Whether an observation describes this model's interval at all.

        Two ways it cannot. A span shorter than the policy's window is a *fragment*: it may be
        the quiet half or the busy half, and it can neither prove a breach nor a pass. And a
        span counted under a different window model permits different traffic at the same
        configured rate, so the two numbers are not the same measurement.
        """
        span = float(observed.get("window_seconds") or self.window_seconds)
        if observed.get("partial_window"):
            return False, ("the log spans less than the configured window, so the count is a "
                           "fragment and any verdict would be arithmetic on an incomplete "
                           "interval")
        if span < self.window_seconds and not observed.get("aligned"):
            return False, (f"the observation covers {span:g}s of a {self.window_seconds:g}s "
                           "window without being one of the counter's own closed windows; a "
                           "fragment can be the quiet half of a window as easily as the busy "
                           "one, so it is reported as incomparable rather than as a verdict")
        observed_mode = _norm(observed.get("window_mode")).upper()
        if observed_mode and observed_mode != self.mode:
            return False, (f"the limit counts {self.mode} and the observation counts "
                           f"{observed_mode}; the two permit different traffic, so a breach "
                           "cannot be claimed")
        return True, ""


# --------------------------------------------------------------------------- #
# The audit
# --------------------------------------------------------------------------- #

def audit_limits(collector: Any, *, source: ObservationSource | None = None,
                 traffic: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Audit one rate-limit collector against a real observation source.

    ``source`` is preferred and produces its own ``sources`` record, so the response says where
    each number came from and what it could not cover. ``traffic`` remains for a caller that
    already holds observations (a replay, a test) and is marked as such.
    """
    if not hasattr(collector, "attached_limits"):
        raise ControlRefused("NOT_A_RATE_LIMITER",
                             "audit_limits() takes a RateLimitCollector")
    attached = collector.attached_limits()
    findings: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []

    rows: list[dict[str, Any]] = []
    if source is not None:
        rows, detail = source.observations()
        sources.append(detail)
        if detail.get("state") not in (None, "OK"):
            refusals.append({"code": "OBSERVATION_SOURCE_UNAVAILABLE",
                             "subject": detail.get("source"),
                             "reason": detail.get("reason") or detail.get("state")})
    elif traffic is not None:
        rows = [dict(row) for row in traffic if isinstance(row, Mapping)]
        sources.append({"source": "caller-supplied", "rows": len(rows),
                        "state": "OK" if rows else "EMPTY",
                        "note": "the caller supplied these observations"})

    api_to_policy: dict[str, str] = {}
    for policy, row in attached.items():
        for api in row["apis"]:
            api_to_policy[api] = policy

    seen: set[str] = set()
    for row in rows:
        api = _norm(row.get("api"))
        evidence = _norm(row.get("evidence_id"))
        observed_requests = row.get("requests")
        if not api:
            refusals.append({"code": "TRAFFIC_WITHOUT_API", "subject": dict(row),
                             "reason": "an observation that names no API cannot be audited"})
            continue
        if not evidence:
            refusals.append({"code": "OBSERVATION_WITHOUT_EVIDENCE", "subject": api,
                             "reason": "a request volume with no evidence id is a number "
                                       "nobody can point at; it is refused, not counted"})
            continue
        if observed_requests is None:
            refusals.append({"code": "OBSERVATION_WITHOUT_VOLUME", "subject": api,
                             "reason": "the observation carries an API and no volume"})
            continue
        seen.add(api)
        policy = api_to_policy.get(api)
        if not policy:
            findings.append({
                "api": api, "policy": None, "state": NOT_CONFIGURED,
                "expected": None,
                "observed": {"requests": observed_requests,
                             "window_seconds": row.get("window_seconds")},
                "facts": [OBSERVED], "evidence_ids": [evidence],
                "source": row.get("source"),
                "reason": (f"{api} carried traffic (source: {row.get('source') or 'unnamed'}) "
                           "and no rate-limit policy is attached to it; this is a decision "
                           "the bank has not made, not a reading we could not take"),
            })
            continue
        limit = attached[policy]["limit"]
        model = WindowModel(mode=limit.get("window_mode") or FIXED,
                            limit=float(limit["limit"]),
                            window_seconds=float(limit["window_seconds"] or 60))
        observed_span = float(row.get("window_seconds") or model.window_seconds)
        comparable, why = model.comparability(row)
        aligned = bool(row.get("aligned"))
        expected, derivation = model.expected(observed_span, aligned=aligned)
        base = {
            "api": api, "policy": policy,
            "expected": {"requests": round(expected, 3), "limit": model.limit,
                         "window_seconds": model.window_seconds, "window_mode": model.mode,
                         "aligned": aligned, "derivation": derivation},
            "observed": {"requests": observed_requests, "window_seconds": observed_span,
                         "window_mode": row.get("window_mode") or None,
                         "source": row.get("source")},
            "facts": [CONFIGURED, OBSERVED],
            "evidence_ids": [limit["evidence_id"], evidence],
            "source": row.get("source"),
        }
        if not comparable:
            findings.append({**base, "state": INCOMPARABLE_WINDOW, "reason": why})
            continue
        over = float(observed_requests) > expected
        findings.append({**base,
                         "state": OVER_LIMIT if over else WITHIN_LIMIT,
                         "reason": (f"{api} observed {observed_requests:g} requests over "
                                    f"{observed_span:g}s against a {model.mode.lower()} "
                                    f"{model.limit:g}/{model.window_seconds:g}s policy "
                                    f"({expected:g} expected, {derivation}); the two numbers "
                                    "are kept side by side")})

    for policy, row in attached.items():
        if row["apis"]:
            continue
        findings.append({
            "api": None, "policy": policy, "state": POLICY_NOT_ATTACHED,
            "expected": {"limit": row["limit"]["limit"],
                         "window_seconds": row["limit"]["window_seconds"]},
            "observed": None, "facts": [CONFIGURED],
            "evidence_ids": [row["limit"]["evidence_id"]], "source": None,
            "reason": (f"{policy} is "
                       + ("enabled" if row["limit"]["enabled"] else "disabled")
                       + " and attached to no API: the policy exists, the coverage does not"),
        })

    summary = {state: 0 for state in FINDING_STATES}
    for finding in findings:
        summary[finding["state"]] += 1
    covered = sorted(api_to_policy)
    return {
        "control": "RATE_LIMIT",
        "vendor": getattr(collector, "vendor", None),
        "findings": sorted(findings, key=lambda item: (item["state"], str(item["api"]))),
        "summary": summary,
        "refusals": refusals,
        "sources": sources,
        "apis_with_traffic": sorted(seen),
        "unobserved_apis": [api for api in covered if api not in seen],
        "policies": sorted(attached),
        "window_models": {policy: (attached[policy]["limit"].get("window_mode") or FIXED)
                          for policy in sorted(attached)},
        "note": ("NOT_CONFIGURED is a finding about a decision, UNKNOWN is a coverage gap, "
                 "and INCOMPARABLE_WINDOW is an observation that does not describe the "
                 "policy's interval; the three are never reported as each other"),
    }


def observation_report(audit: Mapping[str, Any]) -> dict[str, Any]:
    """The one-line truth about coverage: what was measured, what was not, and why."""
    return {
        "sources": audit.get("sources") or [],
        "measured": audit.get("summary", {}).get(OVER_LIMIT, 0)
        + audit.get("summary", {}).get(WITHIN_LIMIT, 0),
        "incomparable": audit.get("summary", {}).get(INCOMPARABLE_WINDOW, 0),
        "unobserved": len(audit.get("unobserved_apis") or []),
        "refused": len(audit.get("refusals") or []),
        "statement": (
            f"{len(audit.get('apis_with_traffic') or [])} API(s) had a measured rate; "
            f"{len(audit.get('unobserved_apis') or [])} attached API(s) had no observation "
            "at all — a limit nobody measured is not a limit that held"),
    }
