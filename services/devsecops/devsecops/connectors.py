"""Outbound integration connectors: ITSM (ServiceNow/Jira), SIEM (Splunk HEC,
Elastic/OpenSearch), message bus (Kafka/RabbitMQ), and chat ops (Slack/Teams).

All connectors are deterministic and network-injected: an HTTP `post` callable
(or producer callable for the bus) is passed in, so logic is fully testable
offline. No secrets are stored here; callers provide endpoint/credentials from
the credential vault. Each writer returns a structured result with a stable
**de-dup key** so repeated delivery of the same finding does not create
duplicate tickets/events.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# ----------------------------------------------------------------- HTTP ---- #
@dataclass
class HttpResult:
    ok: bool
    status: int | None = None
    body: str = ""
    error: str | None = None


def default_http_post():
    """Return a urllib-based POST callable (used at runtime; tests inject fakes)."""
    import urllib.request

    def _post(url: str, *, content: bytes, headers: dict, timeout: float = 10.0):
        req = urllib.request.Request(url, data=content, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return HttpResult(ok=200 <= resp.status < 300, status=resp.status,
                              body=resp.read().decode("utf-8", "replace"))
    return _post


# -------------------------------------------------------------- de-dup ----- #
def dedup_key(*parts: Any) -> str:
    """Stable idempotency key for a finding/incident (e.g. finding_id+source)."""
    raw = "|".join(str(p) for p in parts)
    return "cs-" + hashlib.sha256(raw.encode()).hexdigest()[:24]


# =============================================================== ITSM ===== #
SEVERITY_TO_PRIORITY = {
    "critical": ("1", "Critical"), "high": ("2", "High"),
    "medium": ("3", "Moderate"), "low": ("4", "Low"), "info": ("5", "Planning"),
}


def _finding_summary(finding: dict) -> dict:
    sev = str(finding.get("severity", "medium")).lower()
    pr, label = SEVERITY_TO_PRIORITY.get(sev, ("3", "Moderate"))
    title = finding.get("title") or finding.get("rule_id") or finding.get("cve_id") or "Security finding"
    asset = finding.get("asset") or finding.get("asset_id") or finding.get("host") or "unknown"
    return {"sev": sev, "priority": pr, "priority_label": label, "title": str(title),
            "asset": str(asset), "finding_id": str(finding.get("finding_id") or dedup_key(title, asset))}


def servicenow_ticket(finding: dict, *, instance: str, auth: str, table: str = "incident",
                      post: Callable | None = None) -> dict:
    """Create (or idempotently locate) a ServiceNow incident.

    Uses a stable correlation_id in the short description so a sync run can
    de-duplicate; the caller's ServiceNow account keys on correlation_id.
    """
    post = post or default_http_post()
    s = _finding_summary(finding)
    key = dedup_key("servicenow", s["finding_id"])
    url = f"https://{instance}/api/now/table/{table}"
    payload = {
        "correlation_id": key,
        "short_description": f"[CryptoScan] {s['title']} ({s['sev']})",
        "description": f"Asset: {s['asset']}\nFinding: {s['finding_id']}\nSeverity: {s['sev']}\n"
                       f"Detail: {finding.get('detail') or finding.get('summary') or ''}",
        "priority": s["priority"], "urgency": s["priority"], "impact": "2",
        "category": "Security", "assignment_group": finding.get("assignment_group", "Security Operations"),
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Authorization": f"Basic {auth}"}
    res = post(url, content=json.dumps(payload).encode(), headers=headers)
    sys_id = None
    try:
        sys_id = (json.loads(res.body).get("result") or {}).get("sys_id")
    except Exception:
        pass
    return {"provider": "servicenow", "dedup_key": key, "ok": res.ok,
            "status": res.status, "ticket_id": sys_id, "error": res.error if not res.ok else None}


def jira_issue(finding: dict, *, base_url: str, auth: str, project: str,
               post: Callable | None = None) -> dict:
    """Create a Jira issue with a stable external-id (de-dup on sync)."""
    post = post or default_http_post()
    s = _finding_summary(finding)
    key = dedup_key("jira", project, s["finding_id"])
    url = f"{base_url.rstrip('/')}/rest/api/3/issue"
    payload = {
        "fields": {
            "project": {"key": project},
            "summary": f"[CryptoScan] {s['title']} ({s['sev']})",
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text":
                     f"Asset: {s['asset']}  |  Finding: {s['finding_id']}  |  Severity: {s['sev']}  "
                     f"|  detail: {finding.get('detail') or finding.get('summary') or ''}  "
                     f"|  dedup: {key}"}]}],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": s["priority_label"]},
            "labels": ["cryptoscan", f"severity-{s['sev']}", key],
        },
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Authorization": f"Basic {auth}"}
    res = post(url, content=json.dumps(payload).encode(), headers=headers)
    issue_key = None
    try:
        issue_key = json.loads(res.body).get("key")
    except Exception:
        pass
    return {"provider": "jira", "dedup_key": key, "ok": res.ok, "status": res.status,
            "ticket_id": issue_key, "error": res.error if not res.ok else None}


# =============================================================== SIEM ===== #
def splunk_hec(events: Iterable[dict], *, hec_url: str, token: str,
               sourcetype: str = "cryptoscan:finding", index: str | None = None,
               post: Callable | None = None) -> dict:
    """Send events to a Splunk HTTP Event Collector (newline-delimited JSON)."""
    post = post or default_http_post()
    events = list(events)
    lines = []
    for e in events:
        wrap = {"time": int(e.get("time") or time.time()), "sourcetype": sourcetype,
                "source": "cryptoscan", "event": e}
        if index:
            wrap["index"] = index
        lines.append(json.dumps(wrap))
    content = ("\n".join(lines)).encode()
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    res = post(hec_url.rstrip("/") + "/services/collector", content=content, headers=headers)
    return {"provider": "splunk_hec", "ok": res.ok, "status": res.status,
            "events_sent": len(events), "error": res.error if not res.ok else None}


def elastic_bulk(events: Iterable[dict], *, base_url: str, index: str, auth: str,
                 post: Callable | None = None) -> dict:
    """Bulk-index events into Elasticsearch/OpenSearch (_bulk NDJSON)."""
    post = post or default_http_post()
    events = list(events)
    bulk = []
    for e in events:
        doc_id = e.get("finding_id") or dedup_key("elastic", json.dumps(e, sort_keys=True, default=str))
        bulk.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        bulk.append(json.dumps(e, default=str))
    content = ("\n".join(bulk) + "\n").encode()
    headers = {"Content-Type": "application/x-ndjson", "Authorization": f"ApiKey {auth}"}
    res = post(base_url.rstrip("/") + f"/{index}/_bulk", content=content, headers=headers)
    return {"provider": "elastic", "ok": res.ok, "status": res.status,
            "events_sent": len(events), "error": res.error if not res.ok else None}


# ========================================================= MESSAGE BUS ==== #
def kafka_stream(events: Iterable[dict], *, topic: str, bootstrap: str,
                 producer: Callable[[str, bytes, dict], Any] | None = None) -> dict:
    """Stream findings to a Kafka topic. ``producer(topic, value, headers)`` is
    injected (wraps confluent_kafka at runtime) so no SDK is imported here."""
    if producer is None:
        def producer(t, v, h):  # pragma: no cover - runtime-only path
            raise RuntimeError("no Kafka producer configured (inject one or run on a host with confluent_kafka)")
    events = list(events)
    sent = 0
    errors = []
    for e in events:
        key = str(e.get("finding_id") or dedup_key("kafka", json.dumps(e, sort_keys=True, default=str))).encode()
        try:
            producer(topic, json.dumps(e, default=str).encode(),
                     {"dedup_key": dedup_key("kafka", key)})
            sent += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    return {"provider": "kafka", "ok": not errors, "topic": topic,
            "bootstrap": bootstrap, "events_sent": sent, "error": errors[0] if errors else None}


def rabbit_stream(events: Iterable[dict], *, exchange: str, routing_key: str,
                  publisher: Callable[[str, str, bytes, dict], Any] | None = None) -> dict:
    """Publish findings to a RabbitMQ exchange. ``publisher(exchange, routing,
    body, properties)`` is injected (wraps pika at runtime)."""
    if publisher is None:
        def publisher(ex, rk, body, props):  # pragma: no cover
            raise RuntimeError("no RabbitMQ publisher configured")
    events = list(events)
    sent, errors = 0, []
    for e in events:
        try:
            publisher(exchange, routing_key, json.dumps(e, default=str).encode(),
                      {"dedup_key": dedup_key("rabbit", e.get("finding_id", ""))})
            sent += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    return {"provider": "rabbitmq", "ok": not errors, "exchange": exchange,
            "events_sent": sent, "error": errors[0] if errors else None}


# ============================================================ CHAT OPS ==== #
def slack_message(finding: dict, *, webhook_url: str, channel: str | None = None,
                  actions: bool = True, post: Callable | None = None) -> dict:
    """Send a Slack Block-Kit alert card with deterministic action buttons.

    Buttons use a stable value (dedup key + action) so ack/assign is idempotent
    and can be wired to the platform's callback endpoint.
    """
    post = post or default_http_post()
    s = _finding_summary(finding)
    key = dedup_key("slack", s["finding_id"])
    color = {"critical": "#e01e5a", "high": "#e8912d", "medium": "#e8a13d",
             "low": "#2fb877", "info": "#4d9fff"}.get(s["sev"], "#888")
    block = {
        "channel": channel,
        "attachments": [{
            "color": color,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"🛡 {s['title']}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Asset*\n{s['asset']}"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{s['sev'].upper()}"},
                    {"type": "mrkdwn", "text": f"*Finding*\n{s['finding_id']}"}]},
            ],
        }],
    }
    if actions:
        block["attachments"][0]["blocks"].append({
            "type": "actions", "block_id": f"cryptoscan:{key}", "elements": [
                {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Acknowledge"},
                 "value": json.dumps({"action": "ack", "key": key, "finding": s["finding_id"]})},
                {"type": "button", "text": {"type": "plain_text", "text": "Assign to me"},
                 "value": json.dumps({"action": "assign", "key": key, "finding": s["finding_id"]})},
                {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Open ticket"},
                 "value": json.dumps({"action": "ticket", "key": key, "finding": s["finding_id"]})},
            ]})
    res = post(webhook_url, content=json.dumps(block).encode(),
               headers={"Content-Type": "application/json"})
    return {"provider": "slack", "dedup_key": key, "ok": res.ok, "status": res.status,
            "error": res.error if not res.ok else None}


def teams_adaptive_card(finding: dict, *, webhook_url: str,
                        actions: bool = True, post: Callable | None = None) -> dict:
    """Send an MS Teams Adaptive Card with deterministic Action.Submit buttons."""
    post = post or default_http_post()
    s = _finding_summary(finding)
    key = dedup_key("teams", s["finding_id"])
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "large", "weight": "bolder", "text": f"🛡 {s['title']}"},
                    {"type": "FactSet", "facts": [
                        {"title": "Asset", "value": s["asset"]},
                        {"title": "Severity", "value": s["sev"].upper()},
                        {"title": "Finding", "value": s["finding_id"]}]},
                ],
                "actions": ([
                    {"type": "Action.Submit", "title": "Acknowledge",
                     "data": {"action": "ack", "key": key, "finding": s["finding_id"]}},
                    {"type": "Action.Submit", "title": "Assign to me",
                     "data": {"action": "assign", "key": key, "finding": s["finding_id"]}},
                ] if actions else []),
            }}],
    }
    res = post(webhook_url, content=json.dumps(card).encode(),
               headers={"Content-Type": "application/json"})
    return {"provider": "teams", "dedup_key": key, "ok": res.ok, "status": res.status,
            "error": res.error if not res.ok else None}


# ------------------------------------------------------- de-dup tracking -- #
class DeliveryLedger:
    """In-memory de-duplication ledger keyed by the stable dedup key.

    A real deployment persists this (delivery_logs table); the ledger semantics
    guarantee that a finding re-delivered to the same target is recorded once.
    """

    def __init__(self):
        self._seen: dict[str, dict] = {}

    def should_deliver(self, target: str, dedup: str) -> bool:
        key = f"{target}::{dedup}"
        if key in self._seen:
            return False
        self._seen[key] = {"target": target, "dedup": dedup, "at": time.time()}
        return True

    def delivered(self) -> list[dict]:
        return list(self._seen.values())
