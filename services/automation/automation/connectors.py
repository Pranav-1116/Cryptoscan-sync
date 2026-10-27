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

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from email.utils import format_datetime
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
    "jira": {
        "label": "Atlassian Jira (issue per automation run)",
        "config": ["JIRA_BASE_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"],
    },
    "sentinel": {
        "label": "Microsoft Sentinel (Log Analytics event per automation run)",
        "config": ["SENTINEL_WORKSPACE_ID", "SENTINEL_SHARED_KEY"],
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


def jira_issue_payload(run: dict[str, Any], *, project_key: str = "CRYPTO") -> dict[str, Any]:
    """AutomationRun.to_dict() → Jira Cloud REST v3 issue body.

    Description is Atlassian Document Format (v3 requirement); the tier maps
    to Jira priority names; labels carry the event kind for board filters.
    """
    tier = str(run.get("recommended_tier") or "LOW").upper()
    priority = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium"}.get(tier, "Low")
    event_kind = str(run.get("event_kind") or "unknown")
    playbook = str(run.get("playbook") or "").strip()

    summary = f"CryptoScan {event_kind} [{tier}]"
    if playbook:
        summary += f" — playbook {playbook}"

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
    text = "\n".join(lines)[:8000]

    return {
        "fields": {
            "project": {"key": project_key or "CRYPTO"},
            "issuetype": {"name": "Task"},
            "summary": summary[:250],
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": text}]}],
            },
            "priority": {"name": priority},
            "labels": ["cryptoscan", event_kind][:20],
        }
    }


# Microsoft Sentinel / Log Analytics Data Collector API (2016-04-01) — the
# SharedKey signature is built exactly as documented: base64(HMAC-SHA256(
# base64decode(key), string_to_sign)). Pure and deterministic so it can be
# unit-tested against a fixed date.
def _rfc1123(now: float | None = None) -> str:
    stamp = now if now is not None else time.time()
    return format_datetime(datetime.fromtimestamp(stamp, timezone.utc), usegmt=True)


def sentinel_string_to_sign(*, method: str = "POST", content_length: int = 0,
                            content_type: str = "application/json",
                            x_ms_date: str = "", resource: str = "/api/logs") -> str:
    return f"{method}\n{content_length}\n{content_type}\n{x_ms_date}\n{resource}"


def sentinel_shared_key_authorization(shared_key: str, *, string_to_sign: str) -> str:
    """Build the Authorization header value for the Data Collector API."""
    key_bytes = base64.b64decode(shared_key)
    signature = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    return f"SharedKey {signature}"


def sentinel_event_payload(run: dict[str, Any], *, now: float | None = None,
                           log_type: str = "CRYPTOSCAN_AUTOMATION") -> dict[str, Any]:
    """AutomationRun.to_dict() → Sentinel event body (flat record).

    Log Analytics ingests flat records; the run dict is flattened one level
    (lists/dicts serialized to JSON strings) and TimeGenerated is ISO 8601.
    """
    stamp = datetime.fromtimestamp(now if now is not None else time.time(), timezone.utc)
    flat: dict[str, Any] = {"TimeGenerated": stamp.isoformat()}
    for key, value in run.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            flat[key] = value
        else:
            flat[key] = json.dumps(value, sort_keys=True, default=str)
    return {"log_type": log_type, "record": flat}


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
        elif connector == "jira":
            base = str(config["JIRA_BASE_URL"]).strip().rstrip("/")
            project_key = str(config.get("JIRA_PROJECT_KEY") or "").strip() or "CRYPTO"
            response = poster_fn(
                f"{base}/rest/api/3/issue",
                json=jira_issue_payload(payload, project_key=project_key),
                auth=(str(config["JIRA_USER_EMAIL"]), str(config["JIRA_API_TOKEN"])),
                timeout=10.0,
            )
        elif connector == "sentinel":
            # Log Analytics Data Collector API: raw body + SharedKey HMAC auth.
            event = sentinel_event_payload(payload)
            body = json.dumps(event["record"]).encode("utf-8")
            workspace = str(config["SENTINEL_WORKSPACE_ID"]).strip()
            x_ms_date = _rfc1123()
            string_to_sign = sentinel_string_to_sign(
                content_length=len(body), x_ms_date=x_ms_date)
            response = poster_fn(
                f"https://{workspace}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-ms-date": x_ms_date,
                    "Log-Type": event["log_type"],
                    "Authorization": sentinel_shared_key_authorization(
                        str(config["SENTINEL_SHARED_KEY"]).strip(),
                        string_to_sign=string_to_sign),
                },
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
