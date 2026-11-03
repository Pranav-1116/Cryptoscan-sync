"""SIEM: security events and their correlation references. We read the SIEM; it never reads us.

The SIEM is where the bank's own correlations live. CryptoScan takes two things from it — the
events, and the reference that ties an event to an investigation (correlation rule id, search
id, incident id) — because that reference is what lets a finding be argued with months later.
It writes nothing back: no notable event, no suppression, no response action.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import OBSERVED, DeviceCollector

CONTROL = "SIEM"

COLLECTS: tuple[str, ...] = ("security_events", "correlation_references", "rule_ids",
                             "incident_ids")
MUST_NOT: tuple[str, ...] = (
    "write_to_the_siem", "suppress_a_correlation", "run_a_response_action",
    "read_raw_log_content",
)


class SiemCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def security_events(self) -> list[dict[str, Any]]:
        return self.collect_security_events()

    def correlations(self) -> list[dict[str, Any]]:
        """The reference that makes an event auditable: rule, search and incident ids."""
        correlations: list[dict[str, Any]] = []
        for index, raw in enumerate(self._section_rows("correlations"), start=1):
            correlations.append({
                "rule_id": self._field(raw, "rule_id"),
                "search_id": self._field(raw, "search_id"),
                "incident_id": self._field(raw, "incident_id"),
                "detected_at": self._field(raw, "detected_at"),
                "entities": list(self._field(raw, "entities") or []),
                "fact": OBSERVED,
                "evidence_id": self.evidence.id_for("CORRELATION", index, raw),
            })
        return correlations

    def referenced_events(self) -> list[dict[str, Any]]:
        """Events that carry a correlation reference, with the reference kept alongside."""
        by_reference = {row["incident_id"]: row for row in self.correlations()
                        if row["incident_id"]}
        out: list[dict[str, Any]] = []
        for event in self.security_events():
            incident = (event.get("metadata") or {}).get("incident_id")
            out.append({**event, "correlation": by_reference.get(incident),
                        "correlated": bool(incident and incident in by_reference)})
        return out


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> SiemCollector:
    from .vendors import spec_for

    return SiemCollector(spec_for(vendor), feed)
