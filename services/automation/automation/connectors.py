"""Outbound connectors: deliver automation runs to ITSM/SIEM systems.

Two mappers (ServiceNow incident, Splunk HEC event) and one thin, injectable
sender. The mappers are pure — AutomationRun.to_dict() in, provider payload
out. The sender takes a `poster` callable (default httpx.post) so tests never
open a socket, and it never raises into the automation engine: every outcome,
including "not configured", is returned honestly as a delivery result.

Configuration lives in platform settings (never in code):

    SERVICENOW_INSTANCE_URL   e.g. https://acme.service-now.com
    SERVICENOW_USER / SERVICENOW_PASSWORD
    SPLUNK_HEC_URL            e.g. https://splunk.acme.com:8088/services/collector/event
    SPLUNK_HEC_TOKEN
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

# ServiceNow severity: (impact, urgency), both 1..3 (1 = highest).
_TIER_TO_SNOW: dict[str, tuple[int, int]] = {
    "CRITICAL": (1, 1),
    "HIGH": (1, 2),
    "MEDIUM": (2, 2),
    "LOW": (3, 3),
}

# connector name -> metadata used by the status endpoint (names only)
CONNECTORS: dict[str, dict[str, Any]] = {
    "servicenow": {
        "label": "ServiceNow ITSM (incident per automation run)",
        "config": ["SERVICENOW_INSTANCE_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD"],
    },
    "splunk": {
        "label": "Splunk HEC (event per automation run)",
        "config": ["SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN"],
    },
}

CONNECTOR_NAMES = frozenset(CONNECTORS)


def _action_names(actions: Any) -> list[str]:
    out: list[str] = []
    for entry in actions or []:
        if isinstance(entry, dict):
            name = str(entry.get("action") or "").strip()
            if name:
                out.append(name)
        elif entry:
            out.append(str(entry))
    return out


# --------------------------------------------------------------------- mappers


def servicenow_incident_payload(run: dict[str, Any]) -> dict[str, Any]:
    """AutomationRun.to_dict() → ServiceNow incident body (table API).

    correlation_id is stable per run (cryptoscan:automation:<id>) so retries
    and replays dedupe on the ServiceNow side instead of stacking duplicates.
    """
    tier = str(run.get("recommended_tier") or "LOW").upper()
    impact, urgency = _TIER_TO_SNOW.get(tier, (2, 2))
    event_kind = str(run.get("event_kind") or "unknown")
    playbook = str(run.get("playbook") or "").strip()

    short = f"CryptoScan {event_kind}"
    if playbook:
        short += f" — playbook {playbook}"
    short += f" [{tier}]"

    lines = [
        f"Automation run {run.get('id') or '(unsaved)'} triggered by {run.get('triggered_by') or 'system'}.",
        f"Event: {event_kind}",
    ]
    if run.get("asset_id"):
        lines.append(f"Asset: {run['asset_id']}")
    auto = _action_names(run.get("auto_actions"))
    gated = _action_names(run.get("gated_actions"))
    if auto:
        lines.append("Auto actions: " + ", ".join(auto))
    if gated:
        lines.append("Approval-gated: " + ", ".join(gated))
    if run.get("needs_human"):
        lines.append("HUMAN REVIEW REQUIRED (needs_human=true)")
    lines.append("Detail: " + json.dumps(run, sort_keys=True, default=str))

    return {
        "short_description": short[:160],
        "description": "\n".join(lines)[:4000],
        "impact": impact,
        "urgency": urgency,
        "category": "Security",
        "subcategory": "Cryptography",
        "correlation_id": f"cryptoscan:automation:{run.get('id')}",
    }


def splunk_hec_payload(run: dict[str, Any], *, index: str = "",
                       source: str = "cryptoscan:automation",
                       now: float | None = None) -> dict[str, Any]:
    """AutomationRun.to_dict() → Splunk HTTP Event Collector body.

    The full run dict is the event; sourcetype stays fixed so customers can
    route/index it without content sniffing.
    """
    payload: dict[str, Any] = {
        "time": round(float(now if now is not None else time.time()), 3),
        "source": source,
        "sourcetype": "cryptoscan:automation",
        "event": run,
    }
    if index.strip():
        payload["index"] = index.strip()
    return payload


# --------------------------------------------------------------------- sender


def connector_status(config: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Per-connector readiness from a settings-shaped dict (values → booleans)."""
    out: dict[str, dict[str, Any]] = {}
    for name, meta in CONNECTORS.items():
        missing = [key for key in meta["config"] if not str(config.get(key) or "").strip()]
        out[name] = {"configured": not missing, "missing": missing}
    return out


def send(connector: str, payload: dict[str, Any], *, config: dict[str, str],
         poster: Callable[..., Any] | None = None) -> dict[str, Any]:
    """POST the payload to the connector. Never raises.

    Returns {ok, delivered, status_code, detail}; `detail` is a truncated
    response snippet or the exact reason nothing was sent.
    """
    readiness = connector_status(config).get(connector)
    if readiness is None:
        return {"ok": False, "delivered": False, "status_code": None,
                "detail": f"unknown connector '{connector}'"}
    if readiness["missing"]:
        return {"ok": False, "delivered": False, "status_code": None,
                "detail": "not configured — missing " + ", ".join(readiness["missing"])}
    poster_fn = poster or _httpx_post
    try:
        if connector == "servicenow":
            base = str(config["SERVICENOW_INSTANCE_URL"]).strip().rstrip("/")
            response = poster_fn(
                f"{base}/api/now/table/incident",
                json=payload,
                auth=(str(config["SERVICENOW_USER"]), str(config["SERVICENOW_PASSWORD"])),
                timeout=10.0,
            )
        else:
            response = poster_fn(
                str(config["SPLUNK_HEC_URL"]).strip(),
                json=payload,
                headers={"Authorization": f"Splunk {str(config['SPLUNK_HEC_TOKEN']).strip()}"},
                timeout=10.0,
            )
        code = int(getattr(response, "status_code", 0) or 0)
        try:
            detail = str(response.text)[:300]
        except Exception:
            detail = ""
        return {"ok": 200 <= code < 300, "delivered": 200 <= code < 300,
                "status_code": code, "detail": detail}
    except Exception as exc:
        return {"ok": False, "delivered": False, "status_code": None, "detail": str(exc)[:300]}


def _httpx_post(url: str, **kwargs: Any) -> Any:
    import httpx

    return httpx.post(url, **kwargs)
