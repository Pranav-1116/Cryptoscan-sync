"""Rate limiters: the limits that exist, the APIs they are attached to, and the breaches.

This is the control where "configured" and "real" diverge most often, so it is the one that
must keep the three facts apart and the three audit states distinct:

* ``NOT_CONFIGURED`` — an API with traffic and no policy;
* ``OVER_LIMIT`` — a configured limit and an observed volume, printed side by side;
* ``POLICY_NOT_ATTACHED`` — a policy that exists, is enabled, and protects nothing.

The collector reads. It never enforces a limit, never throttles a caller and never raises a
quota; :mod:`..audit` does the arithmetic, and the arithmetic keeps both evidence ids.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, OBSERVED, DeviceCollector

CONTROL = "RATE_LIMIT"

COLLECTS: tuple[str, ...] = (
    "configured_limits", "api_and_route_mappings", "violations", "expected_vs_configured",
    "attachment_state",
)
MUST_NOT: tuple[str, ...] = (
    "enforce_or_change_a_limit", "throttle_traffic", "raise_a_quota",
    "identify_an_individual_caller",
)


class RateLimitCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def limits(self) -> list[dict[str, Any]]:
        """One row per configured policy: the number, the window and where it applies."""
        limits: list[dict[str, Any]] = []
        for index, raw in enumerate(self._section_rows("limits"), start=1):
            limits.append({
                "policy": self._field(raw, "policy") or self._field(raw, "name"),
                "limit": self._field(raw, "limit"),
                "window_seconds": self._field(raw, "window_seconds")
                or self._field(raw, "window"),
                "scope": str(self._field(raw, "scope") or "IP").upper(),
                "enabled": bool(self._field(raw, "enabled", True)),
                "targets": list(self._field(raw, "targets") or []),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("LIMIT", index, raw),
            })
        return limits

    def mappings(self) -> list[dict[str, Any]]:
        """Policy → API attachment. ``POLICY_NOT_ATTACHED`` is decided from this table."""
        mappings: list[dict[str, Any]] = []
        for index, raw in enumerate(self._section_rows("mappings"), start=1):
            mappings.append({
                "policy": self._field(raw, "policy"),
                "api": self._field(raw, "api") or self._field(raw, "route"),
                "attached": bool(self._field(raw, "attached", True)),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("MAPPING", index, raw),
            })
        return mappings

    def violations(self) -> list[dict[str, Any]]:
        """Violations the limiter itself recorded — an observation, not a configuration."""
        return [{"policy": self._field(raw, "policy"),
                 "api": self._field(raw, "api") or self._field(raw, "route"),
                 "expected": self._field(raw, "expected") or self._field(raw, "limit"),
                 "observed": self._field(raw, "observed") or self._field(raw, "count"),
                 "at": self._field(raw, "at") or self._field(raw, "timestamp"),
                 "fact": OBSERVED,
                 "evidence_id": self.evidence.id_for("VIOLATION", index, raw)}
                for index, raw in enumerate(self._section_rows("violations"), start=1)]

    def attached_limits(self) -> dict[str, dict[str, Any]]:
        """The joined view the audit consumes: policy → limit → APIs it actually protects."""
        attached: dict[str, dict[str, Any]] = {}
        mappings_by_policy: dict[str, list[str]] = {}
        for mapping in self.mappings():
            if mapping["attached"]:
                mappings_by_policy.setdefault(str(mapping["policy"]), []).append(
                    str(mapping["api"]))
        for limit in self.limits():
            policy = str(limit["policy"])
            targets = sorted(set(mappings_by_policy.get(policy, []))
                             | {str(target) for target in limit["targets"]})
            attached[policy] = {"limit": limit, "apis": targets,
                                "attached": bool(targets)}
        return attached


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> RateLimitCollector:
    from .vendors import spec_for

    return RateLimitCollector(spec_for(vendor), feed)
