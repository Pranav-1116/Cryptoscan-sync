"""Tests for ABAC enforcement helpers and real outbound webhook delivery."""

from __future__ import annotations

from control_plane.abac import (
    action_for_method,
    authorize_request,
    effective_scopes,
    filter_rows,
    scope_from_payload,
)
from control_plane.delivery import (
    build_payload,
    credential_secret,
    deliver,
    deliver_to_all,
    integration_matches,
)


# ----------------------------------------------------------------- ABAC
def test_action_for_method_maps_verbs():
    assert action_for_method("GET", "/api/v1/findings") == "read"
    assert action_for_method("POST", "/api/v1/policies") == "write"
    assert action_for_method("PATCH", "/api/v1/scans/x") == "write"
    assert action_for_method("POST", "/api/v1/scans/trigger") == "scan"
    assert action_for_method("POST", "/api/v1/scans/runtime-findings") == "scan"
    assert action_for_method("POST", "/api/v1/control/orchestrator/dispatch") == "scan"


def test_scope_from_payload_prefers_order_and_aliases():
    scope = scope_from_payload(
        {"region": "eu"},  # query
        {"bu": "payments", "env": "prod", "hostname": "lb-1"},  # body aliases
        {"business_unit": "should-not-win"},  # headers (later)
    )
    assert scope.region == "eu"
    assert scope.business_unit == "payments"
    assert scope.environment == "prod"
    assert scope.asset_id == "lb-1"


def test_scope_ignores_blank_values():
    scope = scope_from_payload({"region": "", "env": "  "}, {"region": "us"})
    assert scope.region == "us"
    assert scope.environment is None


def test_authorize_request_fail_closed_without_grants():
    allowed, reason = authorize_request(
        [], username="bob", roles=["readonly"], method="GET",
        path="/api/v1/findings", scope=scope_from_payload({"region": "eu"}),
    )
    assert allowed is False
    assert "fail-closed" in reason


def test_authorize_request_allows_matching_scope_and_denies_outside():
    grants = [{
        "subject": "bob", "subject_type": "user", "actions": ["read"],
        "effect": "allow", "is_active": True, "region": "eu",
    }]
    ok, _ = authorize_request(
        grants, username="bob", roles=["readonly"], method="GET", path="",
        scope=scope_from_payload({"region": "eu", "bu": "payments"}),
    )
    assert ok is True
    # region mismatch -> denied (fail-closed, no matching grant)
    ok2, reason2 = authorize_request(
        grants, username="bob", roles=["readonly"], method="GET", path="",
        scope=scope_from_payload({"region": "us"}),
    )
    assert ok2 is False
    assert "grant" in reason2 or "denied" in reason2


def test_authorize_request_explicit_deny_overrides_allow():
    grants = [
        {"subject": "bob", "subject_type": "user", "actions": ["*"],
         "effect": "allow", "is_active": True, "region": "eu"},
        {"subject": "bob", "subject_type": "user", "actions": ["*"],
         "effect": "deny", "is_active": True, "region": "eu", "environment": "prod"},
    ]
    ok, _ = authorize_request(
        grants, username="bob", roles=[], method="GET", path="",
        scope=scope_from_payload({"region": "eu", "environment": "prod"}),
    )
    assert ok is False
    ok2, _ = authorize_request(
        grants, username="bob", roles=[], method="GET", path="",
        scope=scope_from_payload({"region": "eu", "environment": "dev"}),
    )
    assert ok2 is True


def test_authorize_request_role_subject():
    grants = [{"subject": "auditor", "subject_type": "role", "actions": ["read"],
               "effect": "allow", "is_active": True, "region": "eu"}]
    ok, _ = authorize_request(
        grants, username="someone", roles=["auditor"], method="GET", path="",
        scope=scope_from_payload({"region": "eu"}),
    )
    assert ok is True


def test_residency_blocks_disallowed_region():
    grants = [{"subject": "*", "subject_type": "user", "actions": ["*"],
               "effect": "allow", "is_active": True}]
    tenant = {"is_active": True, "processing_regions": ["eu"]}
    ok, reason = authorize_request(
        grants, username="bob", roles=[], method="GET", path="",
        scope=scope_from_payload({"region": "us"}), tenant=tenant,
    )
    assert ok is False and "residency" in reason


def test_filter_rows_hides_out_of_scope_and_keeps_reference_data():
    grants = [{"subject": "bob", "subject_type": "user", "actions": ["read"],
               "effect": "allow", "is_active": True, "region": "eu"}]
    rows = [
        {"id": "1", "region": "eu", "asset": "a"},      # visible
        {"id": "2", "region": "us", "asset": "b"},      # hidden
        {"id": "3", "algorithm": "RSA-2048"},           # reference data -> visible
    ]
    visible, hidden = filter_rows(grants, rows, username="bob", roles=["readonly"])
    ids = {r["id"] for r in visible}
    assert ids == {"1", "3"}
    assert hidden == 1


def test_effective_scopes_lists_only_own_active_allows():
    grants = [
        {"subject": "bob", "subject_type": "user", "actions": ["read"],
         "effect": "allow", "is_active": True, "region": "eu"},
        {"subject": "bob", "subject_type": "user", "actions": ["read"],
         "effect": "deny", "is_active": True, "region": "us"},          # deny excluded
        {"subject": "alice", "subject_type": "user", "actions": ["*"],
         "effect": "allow", "is_active": True, "region": "us"},         # other user
        {"subject": "bob", "subject_type": "user", "actions": ["read"],
         "effect": "allow", "is_active": False, "region": "apac"},      # inactive
    ]
    scopes = effective_scopes(grants, username="bob", roles=[])
    assert len(scopes) == 1
    assert scopes[0]["region"] == "eu"


# ------------------------------------------------------------- delivery
def _integ(**kw):
    base = {"id": "int-1", "kind": "siem", "provider": "webhook",
            "name": "soc", "enabled": True, "endpoint": "https://soc.example/hook"}
    base.update(kw)
    return base


def test_integration_matches_by_event_prefix():
    siem = _integ(kind="siem")
    itsm = _integ(kind="itsm")
    assert integration_matches(siem, "siem.finding") is True
    assert integration_matches(siem, "itsm.ticket_created") is False
    assert integration_matches(itsm, "itsm.ticket_created") is True
    assert integration_matches(_integ(enabled=False), "siem.finding") is False
    assert integration_matches(siem, "scan.tls") is False


def test_build_payload_json_webhook_signed(monkeypatch):
    monkeypatch.setenv("ZELNX_WEBHOOK_SECRET", "s3cret")
    integ = _integ(provider="webhook")
    body, shaped = build_payload(integ, {"event_type": "siem.finding",
                                         "payload": {"severity": "high", "asset": "h1"}})
    assert isinstance(body, dict)
    assert shaped["headers"]["X-ZELNX-Signature"].startswith("sha256=")
    assert shaped["signature"]


def test_build_payload_splunk_uses_hec_auth(monkeypatch):
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "tok-123")
    integ = _integ(provider="splunk")
    body, shaped = build_payload(integ, {"event_type": "siem.alert", "payload": {}})
    assert body["sourcetype"] == "zelnx:sec" and "event" in body
    assert shaped["headers"]["Authorization"] == "Splunk tok-123"


def test_build_payload_cef_syslog_is_raw_string():
    integ = _integ(provider="cef_syslog")
    body, shaped = build_payload(integ, {"event_type": "siem.finding",
                                         "payload": {"severity": "critical", "asset": "h1"}})
    assert isinstance(body, str) and body.startswith("CEF:0|ZELNX|Cryptoscan")
    assert shaped["headers"]["Content-Type"] == "text/plain"


def test_build_payload_itsm_ticket_shape():
    integ = _integ(kind="itsm", provider="jira")
    body, _ = build_payload(integ, {"event_type": "itsm.ticket_created",
                                    "payload": {"ticket": {"id": "t1"}, "severity": "high"}})
    assert body["source"] == "zelnx" and body["ticket"]["id"] == "t1"


def test_credential_secret_resolution_order(monkeypatch):
    monkeypatch.delenv("ZELNX_WEBHOOK_SECRET", raising=False)
    assert credential_secret(None, "webhook") is None
    monkeypatch.setenv("ZELNX_WEBHOOK_SECRET_INT_9", "scoped")
    assert credential_secret("int-9", "webhook") == "scoped"


def test_deliver_no_endpoint_is_skipped_not_fabricated():
    res = deliver(_integ(endpoint=None), {"event_type": "siem.finding", "payload": {}})
    assert res.status == "skipped"
    assert res.attempts == 0 and "endpoint" in (res.error or "")


def test_deliver_success_records_delivered():
    calls = []

    def fake_post(url, *, content, headers, timeout):
        calls.append((url, content, headers))
        return 200, "ok"

    res = deliver(_integ(), {"event_type": "siem.finding", "payload": {"severity": "low"}},
                  post=fake_post, sleep=lambda _s: None)
    assert res.status == "delivered"
    assert res.attempts == 1 and res.http_status == 200
    assert calls and calls[0][0] == "https://soc.example/hook"


def test_deliver_retries_on_5xx_then_succeeds():
    seq = [503, 503, 202]

    def fake_post(url, *, content, headers, timeout):
        return seq.pop(0), "resp"

    res = deliver(_integ(), {"event_type": "siem.finding", "payload": {}},
                  post=fake_post, sleep=lambda _s: None, max_attempts=4, backoff_base=0.0)
    assert res.status == "delivered"
    assert res.attempts == 3


def test_deliver_4xx_not_retried():
    attempts = {"n": 0}

    def fake_post(url, *, content, headers, timeout):
        attempts["n"] += 1
        return 400, "bad request"

    res = deliver(_integ(), {"event_type": "siem.finding", "payload": {}},
                  post=fake_post, sleep=lambda _s: None, max_attempts=4, backoff_base=0.0)
    assert res.status == "failed" and res.http_status == 400
    assert attempts["n"] == 1  # not retriable


def test_deliver_network_error_retries_then_fails():
    def fake_post(url, *, content, headers, timeout):
        raise ConnectionError("connection refused")

    res = deliver(_integ(), {"event_type": "siem.finding", "payload": {}},
                  post=fake_post, sleep=lambda _s: None, max_attempts=3, backoff_base=0.0)
    assert res.status == "failed" and res.attempts == 3
    assert "connection refused" in (res.error or "")


def test_deliver_to_all_fans_only_matching():
    delivered_to = []

    def fake_post(url, *, content, headers, timeout):
        delivered_to.append(url)
        return 200, "ok"

    integs = [
        _integ(id="siem-1", kind="siem", endpoint="https://siem/h"),
        _integ(id="itsm-1", kind="itsm", endpoint="https://itsm/h"),
        _integ(id="off", kind="siem", enabled=False, endpoint="https://off/h"),
    ]
    results = deliver_to_all(integs, {"event_type": "siem.finding", "payload": {}},
                             post=fake_post, sleep=lambda _s: None)
    assert len(results) == 1
    assert results[0].integration_id == "siem-1" and results[0].status == "delivered"
    assert delivered_to == ["https://siem/h"]
