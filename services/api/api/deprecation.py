"""API deprecation and sunset policy (gap-analysis §B: API maturity).

A deprecated endpoint is a promise, not a deletion. Clients get a
machine-readable lifecycle trail — RFC 8594 ``Deprecation``/``Sunset``
headers plus a ``Link: rel="successor-version"`` pointer — and a named
successor to move to. The policy refuses silent removals outright:

- a deprecation must name its **successor** (a removal without one strands
  its callers);
- a deprecation must carry a **reason** (a removal without one is a
  deletion wearing a policy's name);
- ``sunset_at`` cannot precede ``announced_at``;
- a route may be removed only **after** its sunset date, and only with the
  successor and reason in place.

The registry below holds the product's real withdrawn family — the
``/api/v1/enterprise/airgap/*`` transfer routes (withdrawn 2026-10-31,
commit ``ad7c3f59``: what they transferred could not be audited back to a
collector). They answer 410 with these headers so late callers learn where
to go instead of meeting silence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.utils import format_datetime

DEPRECATED = "DEPRECATED"
WITHDRAWN = "WITHDRAWN"
_LIFECYCLE_STATES: tuple[str, ...] = (DEPRECATED, WITHDRAWN)


@dataclass(frozen=True)
class DeprecationRecord:
    """One endpoint's deprecation lifecycle. Dates are ISO (YYYY-MM-DD)."""

    path: str
    state: str
    announced_at: str
    sunset_at: str
    successor: str          # what callers move to (human-readable)
    reason: str             # why it is going away
    successor_doc: str      # URI path used in the Link header

    def headers(self) -> dict[str, str]:
        """RFC 8594 lifecycle headers for this record."""
        sunset = date.fromisoformat(self.sunset_at)
        http_date = format_datetime(
            datetime(sunset.year, sunset.month, sunset.day,
                     tzinfo=timezone.utc), usegmt=True)
        return {
            "Deprecation": "true",
            "Sunset": http_date,
            "Link": f'<{self.successor_doc}>; rel="successor-version"',
        }


def register_deprecation(*, path: str, state: str, announced_at: str,
                         sunset_at: str, successor: str, reason: str,
                         successor_doc: str) -> DeprecationRecord:
    """Validate and build a lifecycle record. Silent removals are refused."""
    if not str(path or "").startswith("/"):
        raise ValueError("a deprecation record needs the endpoint path")
    if state not in _LIFECYCLE_STATES:
        raise ValueError(f"unknown lifecycle state {state!r}; "
                         f"expected one of {', '.join(_LIFECYCLE_STATES)}")
    if not str(successor or "").strip():
        raise ValueError(
            "a deprecated endpoint without a successor strands its callers")
    if not str(successor_doc or "").strip():
        raise ValueError("the successor needs a linkable document path")
    if not str(reason or "").strip():
        raise ValueError(
            "a deprecation without a reason is a silent removal: that is a "
            "deletion wearing a policy's name")
    try:
        announced = date.fromisoformat(str(announced_at))
        sunset = date.fromisoformat(str(sunset_at))
    except (TypeError, ValueError) as exc:
        raise ValueError("announced_at and sunset_at are ISO dates "
                         "(YYYY-MM-DD)") from exc
    if sunset < announced:
        raise ValueError("a sunset before its announcement is fiction")
    return DeprecationRecord(path=path, state=state, announced_at=str(announced_at),
                             sunset_at=str(sunset_at), successor=str(successor),
                             reason=str(reason), successor_doc=str(successor_doc))


def may_remove(record: DeprecationRecord, *, now: date) -> bool:
    """Removal is allowed only after the sunset date — and never without a
    successor and reason already on the record."""
    return (bool(record.successor) and bool(record.reason)
            and now > date.fromisoformat(record.sunset_at))


# ---- the product's real withdrawn family -----------------------------------

_AIRGAP_REASON = (
    "it moved live platform documents signed with a caller-supplied secret "
    "into an installation, and its import reported success without storing "
    "anything. Neither is an evidence path: what it transferred could not be "
    "audited back to a collector")
_AIRGAP_SUCCESSOR = ("cryptoscan bundle export --out DIR [--sign-key key.pem] "
                     "(verify: cryptoscan bundle verify DIR)")
_AIRGAP_DOC = "/docs/airgap-deployment.md"

#: Registered deprecations, keyed by path. Seeded from the real withdrawal
#: (2026-10-31, ``ad7c3f59``): announced and sunset on the withdrawal date —
#: the routes already answer 410 and keep their lifecycle headers so late
#: callers learn where to go.
DEPRECATIONS: dict[str, DeprecationRecord] = {
    path: register_deprecation(
        path=path, state=WITHDRAWN, announced_at="2026-10-31",
        sunset_at="2026-10-31", successor=_AIRGAP_SUCCESSOR,
        reason=_AIRGAP_REASON, successor_doc=_AIRGAP_DOC)
    for path in (
        "/api/v1/enterprise/airgap/bundle",
        "/api/v1/enterprise/airgap/export",
        "/api/v1/enterprise/airgap/import",
    )
}


def headers_for(path: str) -> dict[str, str]:
    """Lifecycle headers for a registered path; empty for live endpoints."""
    record = DEPRECATIONS.get(path)
    return record.headers() if record else {}
