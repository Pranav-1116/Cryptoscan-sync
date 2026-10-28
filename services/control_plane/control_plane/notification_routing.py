"""Notification catalog and tenant-exact routing, shared by API and drains."""
from __future__ import annotations

import json

from sqlalchemy import select

from db.models.app_setting import AppSetting
from db.tenancy import current_tenant

ROUTING_SETTING_KEY = "notification.routing.v1"

#: Canonical event-class catalog the console exposes. ids/names/severity are
#: product config served live by the control plane; only the per-channel
#: boolean routing map is persisted per tenant (overlaid on these defaults).
CHANNELS = ("inApp", "email", "webhook", "siem")


def _ev(id_: str, name: str, severity: str, channels: dict[str, bool]) -> dict:
    return {"id": id_, "name": name, "severity": severity,
            "channels": {c: bool(channels.get(c, False)) for c in CHANNELS}}


CATALOG: list[dict] = [
    _ev("critical_crypto_change", "Critical crypto change", "CRITICAL",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("new_asset", "New asset discovered", "LOW",
        {"inApp": True, "email": False, "webhook": False, "siem": True}),
    _ev("new_certificate", "New certificate", "MEDIUM",
        {"inApp": True, "email": True, "webhook": False, "siem": True}),
    _ev("pqc_risk_change", "PQC risk change", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("crypto_drift", "Crypto drift", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("scanner_failure", "Scanner failure", "CRITICAL",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("cloud_change", "Cloud change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": True, "siem": True}),
    _ev("vendor_change", "Vendor change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": False, "siem": False}),
    _ev("hardware_change", "Hardware change", "MEDIUM",
        {"inApp": True, "email": False, "webhook": True, "siem": True}),
    _ev("compliance_failure", "Compliance failure", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    # §5 (round 76): verification outcomes are now a routable class —
    # VERIFIED / PARTIAL / FAILED / REGRESSION / INCONCLUSIVE land in the
    # in-app feed (GET /notifications/feed) and can be routed outward.
    _ev("remediation_verification", "Remediation verification outcome", "HIGH",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    # spec 94 §17-§18: a detected estate change is a first-class routable class, so
    # "Payment API AES-256-GCM: OBSERVED -> SUPPORTED" can reach a SIEM or a webhook
    # instead of waiting for someone to open the console
    _ev("estate_change", "Estate change detected", "WARNING",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    # losing a plane is not a change to read: everything under it is UNKNOWN
    _ev("estate_coverage_lost", "Estate coverage lost", "CRITICAL",
        {"inApp": True, "email": True, "webhook": True, "siem": True}),
    _ev("remediation_task", "Remediation task lifecycle", "MEDIUM",
        {"inApp": True, "email": False, "webhook": False, "siem": False}),
]

#: emitted platform event_type → catalog class id. Only defensible pairs
#: are mapped — an emitted type with no entry here is NOT force-fit into
#: a class; it stays visible in the events stream, just unrouted. This
#: map is the single authority the in-app feed consults.
EVENT_CLASS_MAP = {
    "remediation.task_verified": "remediation_verification",
    "remediation.task_created": "remediation_task",
    "remediation.task_accepted": "remediation_task",
    "remediation.task_completed": "remediation_task",
    "remediation.drift_tasks_created": "remediation_task",
    "evidence.chain_broken": "compliance_failure",
    "estate.change.detected": "estate_change",
    "estate.coverage.lost": "estate_coverage_lost",
}


CHANNEL_KINDS = {"siem": ("siem", "soar"), "webhook": ("itsm", "cmdb")}


def routing_key() -> str:
    owner = current_tenant()
    suffix = "platform" if owner is None else f"tenant:{owner}"
    return f"{ROUTING_SETTING_KEY}:{suffix}"


def routing_row(session):
    owner = current_tenant()
    row = session.execute(select(AppSetting).where(
        AppSetting.key == routing_key(), AppSetting.tenant_id == owner)).scalar_one_or_none()
    if row is None:
        # Read only this tenant's legacy key; never inherit the platform's
        # operational routing (the general ORM guard also exposes NULL rows).
        row = session.execute(select(AppSetting).where(
            AppSetting.key == ROUTING_SETTING_KEY, AppSetting.tenant_id == owner)).scalar_one_or_none()
    return row


def save_routing(session, value, *, user):
    row = routing_row(session)
    if row is None:
        row = AppSetting(key=routing_key(), tenant_id=current_tenant())
        session.add(row)
    row.key = routing_key()
    row.value = json.dumps(value, allow_nan=False)
    row.updated_by = user
    session.flush()


def merged_routing(session) -> tuple[list[dict], bool]:
    row = routing_row(session)
    persisted = json.loads(row.value) if row is not None else []
    if not isinstance(persisted, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("id"), str)
        or not isinstance(item.get("channels", {}), dict)
        or any(type(value) is not bool for value in item.get("channels", {}).values())
        for item in persisted
    ):
        # Corrupt configuration must not enable default outbound routing.
        raise ValueError("invalid stored notification routing")
    by_id = {item["id"]: item for item in persisted}
    merged = []
    for entry in CATALOG:
        overrides = by_id.get(entry["id"], {}).get("channels", {})
        merged.append({**entry, "channels": {c: overrides.get(c, entry["channels"][c]) for c in CHANNELS}})
    known = {e["id"] for e in CATALOG}
    for item in persisted:
        if item["id"] not in known:
            merged.append({"id": item["id"], "name": item.get("name", item["id"]),
                           "severity": item.get("severity", "INFO"),
                           "channels": {c: item.get("channels", {}).get(c, False) for c in CHANNELS}})
    return merged, bool(persisted)
