"""ITSM/SIEM connectors — pure payload mappers and the injectable sender."""

from __future__ import annotations

import json
from types import SimpleNamespace

from automation.connectors import (
    CONNECTORS,
    connector_status,
    send,
    servicenow_incident_payload,
    splunk_hec_payload,
)

RUN = {
    "id": "run-123",
    "event_kind": "agent_offline",
    "asset_id": "asset-9",
    "auto_actions": [{"action": "targeted_rescan", "risk": "LOW"}],
    "gated_actions": [{"action": "create_ticket", "risk": "HIGH"}],
    "matched_rules": [{"rule_id": "r1"}],
    "playbook": "pb_telecom_nf_down",
    "needs_human": False,
    "recommended_tier": "CRITICAL",
    "triggered_by": "event-bus:telecom-scanner",
    "governance_ref": None,
    "executed_at": None,
}


# --------------------------------------------------------------------- mappers


def test_servicenow_payload_maps_tier_to_impact_urgency():
    payload = servicenow_incident_payload(RUN)
    assert payload["impact"] == 1 and payload["urgency"] == 1  # CRITICAL
    assert "CryptoScan agent_offline" in payload["short_description"]
    assert "pb_telecom_nf_down" in payload["short_description"]
    assert "[CRITICAL]" in payload["short_description"]
    assert payload["correlation_id"] == "cryptoscan:automation:run-123"
    assert payload["category"] == "Security" and payload["subcategory"] == "Cryptography"
    description = payload["description"]
    assert "Asset: asset-9" in description
    assert "targeted_rescan" in description and "create_ticket" in description
    assert len(payload["short_description"]) <= 160


def test_servicenow_payload_tiers_and_honest_defaults():
    medium = servicenow_incident_payload({**RUN, "recommended_tier": "MEDIUM", "id": None})
    assert (medium["impact"], medium["urgency"]) == (2, 2)
    assert medium["correlation_id"].endswith("None")  # unsaved run — still stable shape
    low = servicenow_incident_payload({**RUN, "recommended_tier": "LOW"})
    assert (low["impact"], low["urgency"]) == (3, 3)
    human = servicenow_incident_payload({**RUN, "needs_human": True})
    assert "HUMAN REVIEW REQUIRED" in human["description"]
    blank = servicenow_incident_payload({})
    assert blank["short_description"].startswith("CryptoScan unknown")


def test_splunk_payload_shape():
    payload = splunk_hec_payload(RUN, index="crypto", now=1_700_000_000.0)
    assert payload["time"] == 1_700_000_000.0
    assert payload["sourcetype"] == "cryptoscan:automation"
    assert payload["index"] == "crypto"
    assert payload["event"]["event_kind"] == "agent_offline"
    default = splunk_hec_payload(RUN)
    assert "index" not in default
    assert isinstance(default["time"], float)


# --------------------------------------------------------------------- status


def test_connector_status_reports_missing_names_only():
    status = connector_status({})
    assert status["servicenow"] == {"configured": False,
                                    "missing": ["SERVICENOW_INSTANCE_URL", "SERVICENOW_USER",
                                                "SERVICENOW_PASSWORD"]}
    assert status["splunk"]["configured"] is False
    full = connector_status({k: "x" for k in (
        "SERVICENOW_INSTANCE_URL", "SERVICENOW_USER", "SERVICENOW_PASSWORD",
        "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN")})
    assert all(entry["configured"] for entry in full.values())
    assert set(CONNECTORS) == {"servicenow", "splunk"}


# ---------------------------------------------------------------------- send


def _ok_poster(status_code=201, text='{"sys_id": "abc"}'):
    captured = {}

    def poster(url, *, json=None, headers=None, auth=None, timeout=None):
        captured.update({"url": url, "json": json, "headers": headers,
                         "auth": auth, "timeout": timeout})
        return SimpleNamespace(status_code=status_code, text=text)

    poster.captured = captured
    return poster


def test_send_servicenow_happy_path():
    poster = _ok_poster()
    config = {"SERVICENOW_INSTANCE_URL": "https://acme.service-now.com/",
              "SERVICENOW_USER": "svc-cryptoscan", "SERVICENOW_PASSWORD": "pw",
              "SPLUNK_HEC_URL": "", "SPLUNK_HEC_TOKEN": ""}
    result = send("servicenow", servicenow_incident_payload(RUN), config=config, poster=poster)
    assert result["ok"] is True and result["delivered"] is True
    assert result["status_code"] == 201
    assert poster.captured["url"] == "https://acme.service-now.com/api/now/table/incident"
    assert poster.captured["auth"] == ("svc-cryptoscan", "pw")
    assert json.loads(json.dumps(poster.captured["json"]))["correlation_id"].startswith("cryptoscan:")


def test_send_splunk_uses_hec_token_header():
    poster = _ok_poster(status_code=200, text='{"text": "Success"}')
    config = {"SERVICENOW_INSTANCE_URL": "", "SERVICENOW_USER": "", "SERVICENOW_PASSWORD": "",
              "SPLUNK_HEC_URL": "https://splunk.acme.com:8088/services/collector/event",
              "SPLUNK_HEC_TOKEN": "hec-token"}
    result = send("splunk", splunk_hec_payload(RUN), config=config, poster=poster)
    assert result["delivered"] is True
    assert poster.captured["headers"] == {"Authorization": "Splunk hec-token"}


def test_send_is_honest_about_config_and_failures():
    config = {}
    result = send("servicenow", {}, config=config, poster=_ok_poster())
    assert result["delivered"] is False
    assert "SERVICENOW_INSTANCE_URL" in result["detail"]

    assert send("carrier-pigeon", {}, config={})["detail"] == "unknown connector 'carrier-pigeon'"

    def boom(url, **kwargs):
        raise ConnectionError("splunk unreachable")

    config = {"SERVICENOW_INSTANCE_URL": "", "SERVICENOW_USER": "", "SERVICENOW_PASSWORD": "",
              "SPLUNK_HEC_URL": "https://splunk.acme.com:8088", "SPLUNK_HEC_TOKEN": "t"}
    result = send("splunk", {}, config=config, poster=boom)
    assert result["ok"] is False and result["status_code"] is None
    assert "splunk unreachable" in result["detail"]

    result = send("splunk", {}, config=config, poster=_ok_poster(status_code=403, text="forbidden"))
    assert result["ok"] is False and result["status_code"] == 403
