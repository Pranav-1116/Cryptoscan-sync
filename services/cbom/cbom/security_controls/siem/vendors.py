"""SIEM dialects: Splunk, Microsoft Sentinel, and an operator-declared platform."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "splunk": AdapterSpec(
        key="siem.splunk",
        control="SIEM",
        vendor="Splunk",
        product="Splunk Enterprise Security",
        operations=("QUERY", "SIEM_QUERY", "API_GET"),
        sections={"notables": "events", "correlations": "correlations"},
        aliases={"signature": ("rule_name", "search_name"), "src": ("src",),
                 "dst": ("dest",), "timestamp": ("_time",),
                 "incident_id": ("event_id", "notable_id"),
                 "rule_id": ("search_name",), "search_id": ("sid",)},
        event_kinds=("ALERT", "EVENT", "NOTABLE"),
        endpoints=("QUERY /services/search/jobs/export",),
        notes="a search job is a read; the same API can also create a notable event, which "
              "the adapter never does",
    ),
    "sentinel": AdapterSpec(
        key="siem.sentinel",
        control="SIEM",
        vendor="Microsoft",
        product="Microsoft Sentinel",
        operations=("SIEM_QUERY", "API_GET"),
        sections={"incidents": "events", "analytics_rules": "correlations"},
        aliases={"signature": ("AlertName",), "src": ("SourceIP",),
                 "dst": ("DestinationIP",), "timestamp": ("TimeGenerated",),
                 "incident_id": ("IncidentNumber",), "rule_id": ("AlertRuleId",)},
        event_kinds=("ALERT", "EVENT", "INCIDENT"),
        endpoints=("SIEM_QUERY /v1/workspaces/{id}/query",),
        notes="a KQL query is the read; incident updates are the write the adapter omits",
    ),
    "vendor": AdapterSpec(
        key="siem.vendor",
        control="SIEM",
        vendor="(declared by the operator)",
        product="SIEM",
        operations=("SIEM_QUERY",),
        sections={"events": "events", "correlations": "correlations"},
        aliases={},
        event_kinds=("ALERT", "EVENT"),
        endpoints=("SIEM_QUERY /",),
        notes="the query interface is the contract; the schema is the operator's to declare",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a SIEM dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
