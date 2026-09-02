"""External integration logic — CMDB, ITSM, SIEM/SOAR, air-gapped transfer.

Deterministic adapters/protocols for the enterprise ecosystem. These modules
define the contracts and the deterministic transforms; actual network calls
to ServiceNow/Splunk/etc. are injected by the deployed adapters and are
represented here by provider metadata so on-prem/offline deployments still
function (air-gapped doctrine).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

# ---------------------------------------------------------------------- CMDB
CMDB_PROVIDERS = ("servicenow", "cmdb_ci", "excel", "csv", "manual", "other")


def canonical_cmdb_key(record: dict) -> str:
    """Stable key for identity resolution: prefer strong identifiers."""
    for k in ("serial_number", "serial", "hardware_uuid", "instance_id", "asset_tag"):
        if record.get(k):
            return f"{k}:{record[k]}".lower()
    for k in ("fqdn", "hostname", "ip_address", "name"):
        if record.get(k):
            return f"{k}:{record[k]}".lower()
    return "unresolved"


def resolve_cmdb_assets(cmdb_records: list[dict], discovered: list[dict]) -> dict:
    """Resolve discovered assets against CMDB inventory -> matched/new/stale.

    cmdb_records: keyed attributes incl. owner/business_unit/criticality.
    discovered: keyed identifiers (see canonical_cmdb_key).
    Returns match stats and ownership enrichment for matched assets.
    """
    cmdb_index = {canonical_cmdb_key(r): r for r in cmdb_records}
    matched, unmatched_new, enriched = [], [], []
    for d in discovered:
        key = canonical_cmdb_key(d)
        if key in cmdb_index:
            matched.append(key)
            rec = cmdb_index[key]
            enriched.append({
                "discovered": d,
                "owner": rec.get("owner"), "business_unit": rec.get("business_unit"),
                "criticality": rec.get("criticality"), "application": rec.get("application"),
                "data_classification": rec.get("data_classification"),
                "cmdb_ci": rec.get("ci_id") or rec.get("id"),
            })
        else:
            unmatched_new.append(d)
    discovered_keys = {canonical_cmdb_key(d) for d in discovered}
    stale = [k for k in cmdb_index if k not in discovered_keys]
    return {
        "matched": len(matched), "new_unmatched": len(unmatched_new),
        "cmdb_stale": len(stale), "enriched": enriched,
        "new_assets": unmatched_new,
    }


# ---------------------------------------------------------------------- ITSM
ITSM_PROVIDERS = ("servicenow", "jira", "azure_devops", "manual", "other")
TICKET_STATES = ("open", "triaged", "assigned", "in_progress", "in_migration",
                 "validation", "resolved", "closed", "reopened")


def ticket_state_machine(current: str, action: str) -> str:
    """Deterministic ticket lifecycle. Returns new state; invalid => same."""
    transitions = {
        "open": {"triage": "triaged", "assign": "assigned"},
        "triaged": {"assign": "assigned"},
        "assigned": {"start": "in_progress"},
        "in_progress": {"migrate": "in_migration"},
        "in_migration": {"validate": "validation"},
        "validation": {"pass": "resolved", "fail": "reopened"},
        "reopened": {"start": "in_progress"},
        "resolved": {"close": "closed", "reopen": "reopened"},
        "closed": {"reopen": "reopened"},
    }
    return transitions.get(current, {}).get(action, current)


# ------------------------------------------------------------------ SIEM/SOC
SIEM_PROVIDERS = ("splunk", "sentinel", "chronicle", "qradar", "cef_syslog", "webhook")

#: event categories the SOC ingests (24/7).
SIEM_EVENT_CATEGORIES = ("alert", "finding", "asset_change", "crypto_change",
                         "certificate_change", "drift", "risk_change")


def to_cef(event: dict) -> str:
    """Map a ZELNX event to CEF (Common Event Format) for SIEM ingestion."""
    sev = str(event.get("severity", "info")).lower()
    cef_sev = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}.get(sev, 1)
    return (
        f"CEF:0|ZELNX|Cryptoscan|1.0|{event.get('category', 'finding')}|"
        f"{event.get('name', 'event')}|{cef_sev}|"
        f"cs1Label=asset cs1={event.get('asset', '')} "
        f"cs2Label=sector cs2={event.get('sector', '')} "
        f"cs3Label=detail cs3={str(event.get('detail', ''))[:200]}"
    )


def normalize_siem_events(events: list[dict], provider: str) -> list[dict]:
    out = []
    for e in events:
        cat = e.get("category", "finding")
        if cat not in SIEM_EVENT_CATEGORIES:
            continue
        out.append({"provider": provider, "category": cat, "cef": to_cef(e),
                    "timestamp": e.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    "payload": e})
    return out


# ------------------------------------------------------- air-gapped transfer
def sign_package(payload: bytes, secret: bytes) -> str:
    """HMAC-SHA256 signature for a signed export/import package."""
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_package(payload: bytes, signature: str, secret: bytes) -> bool:
    expected = sign_package(payload, secret)
    return hmac.compare_digest(expected, signature)


def build_signed_export(doc: dict, secret: str) -> dict:
    """Wrap evidence/findings for controlled transfer out of an air-gapped
    environment: canonical JSON + content hash + HMAC signature."""
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode()
    content_hash = hashlib.sha256(canonical).hexdigest()
    signature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()
    return {"format": "zelnx-signed-export/v1", "content_hash": content_hash,
            "signature": signature, "document": doc}


def load_signed_export(package: dict, secret: str) -> dict:
    """Verify + unwrap a signed import. Raises ValueError on tampering."""
    canonical = json.dumps(package.get("document", {}), sort_keys=True,
                           separators=(",", ":"), default=str).encode()
    if hashlib.sha256(canonical).hexdigest() != package.get("content_hash"):
        raise ValueError("content hash mismatch — package tampered or corrupt")
    if not verify_package(canonical, package.get("signature", ""), secret.encode()):
        raise ValueError("invalid signature — untrusted package")
    return package["document"]
