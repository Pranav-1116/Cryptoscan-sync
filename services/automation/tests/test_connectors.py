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
        "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN",
        "JIRA_BASE_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY",
        "SENTINEL_WORKSPACE_ID", "SENTINEL_SHARED_KEY")})
    assert all(entry["configured"] for entry in full.values())
    assert set(CONNECTORS) == {"servicenow", "splunk", "jira", "sentinel"}


# ---------------------------------------------------------------------- send


def _ok_poster(status_code=201, text='{"sys_id": "abc"}'):
    captured = {}

    def poster(url, *, json=None, headers=None, auth=None, timeout=None, data=None):
        captured.update({"url": url, "json": json, "headers": headers,
                         "auth": auth, "timeout": timeout, "data": data})
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


# ---------------------------------------------------------------- jira/sentinel


def test_jira_payload_adf_and_priority():
    from automation.connectors import jira_issue_payload

    payload = jira_issue_payload(RUN, project_key="SECOPS")
    fields = payload["fields"]
    assert fields["project"] == {"key": "SECOPS"}
    assert fields["issuetype"] == {"name": "Task"}
    assert "CryptoScan agent_offline" in fields["summary"]
    assert "[CRITICAL]" in fields["summary"] and len(fields["summary"]) <= 250
    assert fields["priority"] == {"name": "Highest"}
    description = fields["description"]
    assert description["type"] == "doc" and description["version"] == 1
    text = description["content"][0]["content"][0]["text"]
    assert "Asset: asset-9" in text and "create_ticket" in text
    assert fields["labels"] == ["cryptoscan", "agent_offline"]
    # tier → priority ladder
    for tier, expected in (("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")):
        got = jira_issue_payload({**RUN, "recommended_tier": tier})["fields"]["priority"]
        assert got == {"name": expected}


def test_sentinel_string_to_sign_is_the_documented_format():
    from automation.connectors import sentinel_string_to_sign

    assert sentinel_string_to_sign(
        content_length=17, x_ms_date="Mon, 11 Sep 2026 00:00:00 GMT") == \
        "POST\n17\napplication/json\nMon, 11 Sep 2026 00:00:00 GMT\n/api/logs"


def test_sentinel_shared_key_signature_is_hmac_over_decoded_key():
    import base64 as b64
    import hashlib
    import hmac as hmac_mod

    from automation.connectors import sentinel_shared_key_authorization

    shared_key = b64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    string_to_sign = "POST\n17\napplication/json\nMon, 11 Sep 2026 00:00:00 GMT\n/api/logs"
    header = sentinel_shared_key_authorization(shared_key, string_to_sign=string_to_sign)
    assert header.startswith("SharedKey ")
    expected_sig = b64.b64encode(hmac_mod.new(
        b64.b64decode(shared_key), string_to_sign.encode(), hashlib.sha256).digest()).decode()
    assert header == f"SharedKey {expected_sig}"


def test_sentinel_event_flattens_for_log_analytics():
    from automation.connectors import sentinel_event_payload

    event = sentinel_event_payload(RUN, now=1_700_000_000.0)
    assert event["log_type"] == "CRYPTOSCAN_AUTOMATION"
    record = event["record"]
    assert record["TimeGenerated"].startswith("2023-11-14T22:13:20")
    assert record["event_kind"] == "agent_offline"          # scalar passes through
    assert record["auto_actions"].startswith("[")           # nested → JSON string
    assert record["governance_ref"] is None


def test_send_jira_posts_adf_with_basic_auth():
    poster = _ok_poster(status_code=201, text='{"key": "CRYPTO-1"}')
    config = {"JIRA_BASE_URL": "https://acme.atlassian.net/", "JIRA_USER_EMAIL": "svc@acme.com",
              "JIRA_API_TOKEN": "token", "JIRA_PROJECT_KEY": "SECOPS",
              "SERVICENOW_INSTANCE_URL": "", "SERVICENOW_USER": "", "SERVICENOW_PASSWORD": "",
              "SPLUNK_HEC_URL": "", "SPLUNK_HEC_TOKEN": "",
              "SENTINEL_WORKSPACE_ID": "", "SENTINEL_SHARED_KEY": ""}
    result = send("jira", RUN, config=config, poster=poster)
    assert result["delivered"] is True and result["status_code"] == 201
    assert poster.captured["url"] == "https://acme.atlassian.net/rest/api/3/issue"
    assert poster.captured["auth"] == ("svc@acme.com", "token")
    assert poster.captured["json"]["fields"]["project"] == {"key": "SECOPS"}


def test_send_sentinel_signs_the_request():
    poster = _ok_poster(status_code=200, text='{"authorization": "ok"}')
    config = {"SENTINEL_WORKSPACE_ID": "ws0123456789abcdef", "SENTINEL_SHARED_KEY": "a2V5MTIzNDU2Nzg5MGFiY2RlZg==",
              "SERVICENOW_INSTANCE_URL": "", "SERVICENOW_USER": "", "SERVICENOW_PASSWORD": "",
              "SPLUNK_HEC_URL": "", "SPLUNK_HEC_TOKEN": "",
              "JIRA_BASE_URL": "", "JIRA_USER_EMAIL": "", "JIRA_API_TOKEN": "", "JIRA_PROJECT_KEY": ""}
    result = send("sentinel", RUN, config=config, poster=poster)
    assert result["delivered"] is True
    assert poster.captured["url"].startswith(
        "https://ws0123456789abcdef.ods.opinsights.azure.com/api/logs?api-version=2016-04-01")
    headers = poster.captured["headers"]
    assert headers["Authorization"].startswith("SharedKey ")
    assert headers["Log-Type"] == "CRYPTOSCAN_AUTOMATION"
    assert "x-ms-date" in headers
    assert b"agent_offline" in poster.captured["data"]


def test_new_connectors_report_missing_config_honestly():
    status = connector_status({})
    assert status["jira"]["configured"] is False
    assert set(status["jira"]["missing"]) == {"JIRA_BASE_URL", "JIRA_USER_EMAIL",
                                              "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"}
    assert status["sentinel"]["configured"] is False
    result = send("jira", {}, config={}, poster=_ok_poster())
    assert result["delivered"] is False and "JIRA_BASE_URL" in result["detail"]
