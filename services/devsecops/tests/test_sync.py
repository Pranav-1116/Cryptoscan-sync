"""Tests for bidirectional ITSM sync (17), native SIEM indexers (18),
event streaming (19), and inbound chat actions (20). Deterministic, no network."""
import json
import pytest

from devsecops.connectors import dedup_key, HttpResult
from devsecops import sync
from devsecops.sync import (TicketSync, FindingState, splunk_hec_with_ack,
                            elastic_bulk_with_retry, EventStream, apply_chat_action,
                            verify_slack_request, verify_teams_token)


def _http(ok=True, status=200, body="", error=None):
    return HttpResult(ok=ok, status=status, body=body, error=error)


# ------------------------------------------------------------------- 17 ---- #
def test_servicenow_pull_reconciles_status_assignee_comment():
    finding = "FIND-1"
    states = {finding: FindingState(finding_id=finding, status="OPEN")}
    key = dedup_key("servicenow", finding)
    remote = {"result": [{
        "sys_id": "abc123", "correlation_id": key, "state": "3",
        "assigned_to": {"display_value": "Jane Analyst"},
        "work_notes": f"[code]<div>note</div>{'x'*0}",
    }]}
    # ServiceNow returns comments via work_notes_list typically; simulate comment field
    remote["result"][0]["work_notes_list"] = [{"sys_id": "w1", "user_name": "jane", "value": "on it"}]
    get = lambda url, headers=None: _http(body=json.dumps(remote))
    ts = TicketSync(get=get)
    out = ts.pull_servicenow(states, instance="x.service-now.com", auth="YWRtaW46")
    assert out[0]["action"] == "RECONCILED"
    st = states[finding]
    assert st.status == "IN_PROGRESS"
    assert st.assignee == "Jane Analyst"
    assert st.tickets["servicenow"] == "abc123"
    assert any(c["source"] == "servicenow" for c in st.comments)


def test_jira_pull_matches_by_label_and_ignores_unknown():
    finding = "FIND-2"
    states = {finding: FindingState(finding_id=finding)}
    key = dedup_key("jira", finding)
    body = {"issues": [
        {"key": "SEC-9", "fields": {
            "labels": [key, "cryptoscan"],
            "status": {"name": "In Progress"},
            "assignee": {"displayName": "Bob"},
            "comment": {"comments": [{"id": "c1", "author": {"displayName": "Bob"},
                                      "body": "looking"}]}}},
        {"key": "SEC-10", "fields": {"labels": ["cs-deadbeef"],
                                     "status": {"name": "Done"}, "assignee": {}, "comment": {}}},
    ]}
    get = lambda url, headers=None: _http(body=json.dumps(body))
    ts = TicketSync(get=get)
    out = ts.pull_jira(states, base_url="https://j.example", auth="x")
    actions = {o.get("ticket_id"): o.get("action") for o in out}
    assert actions["SEC-9"] == "RECONCILED"
    assert actions["SEC-10"] == "NO_MATCH"
    assert states[finding].status == "IN_PROGRESS"
    assert states[finding].assignee == "Bob"
    assert states[finding].tickets["jira"] == "SEC-9"


def test_sync_comment_idempotent_on_repeat_pull():
    finding = "FIND-3"
    states = {finding: FindingState(finding_id=finding)}
    key = dedup_key("servicenow", finding)
    remote = {"result": [{"sys_id": "s1", "correlation_id": key, "state": "2",
                          "work_notes_list": [{"sys_id": "w1", "user_name": "j", "value": "n"}]}]}
    get = lambda url, headers=None: _http(body=json.dumps(remote))
    ts = TicketSync(get=get)
    ts.pull_servicenow(states, instance="x", auth="y")
    ts.pull_servicenow(states, instance="x", auth="y")
    sn_comments = [c for c in states[finding].comments if c["source"] == "servicenow"]
    assert len(sn_comments) == 1


def test_remote_does_not_silently_reopen_resolved():
    st = FindingState(finding_id="F", status="RESOLVED")
    # a stale remote "OPEN" must not move a RESOLVED finding backwards
    assert TicketSync._is_remote_newer(st, "OPEN") is False
    assert TicketSync._is_remote_newer(st, "CLOSED") is True


# ------------------------------------------------------------------- 18 ---- #
def test_splunk_hec_indexer_ack_success():
    calls = []
    def post(url, content, headers):
        calls.append(url)
        if url.endswith("/services/collector?channel=cryptoscan-idx"):
            return _http(body=json.dumps({"code": 0, "ackId": 42}))
        return _http(body=json.dumps({"acks": {"42": True}}))
    out = splunk_hec_with_ack([{"finding_id": "a"}], hec_url="https://splunk", token="t", post=post)
    assert out["ok"] is True
    assert out["indexer_ack"] is True
    assert out["ack_id"] == 42


def test_splunk_hec_retries_then_succeeds():
    attempts = {"n": 0}
    def post(url, content, headers):
        if "collector/ack" in url:
            return _http(body=json.dumps({"acks": {"7": True}}))
        attempts["n"] += 1
        if attempts["n"] < 3:
            return _http(ok=False, status=503, error="busy")
        return _http(body=json.dumps({"code": 0, "ackId": 7}))
    out = splunk_hec_with_ack([{"finding_id": "a"}], hec_url="https://splunk", token="t", post=post)
    assert out["ok"] is True
    assert attempts["n"] == 3


def test_splunk_hec_permanent_error_fails_closed():
    post = lambda *a, **k: _http(ok=False, status=401, error="unauthorized")
    out = splunk_hec_with_ack([{"finding_id": "a"}], hec_url="https://splunk", token="bad", post=post)
    assert out["ok"] is False and out["status"] == 401


def test_elastic_bulk_reports_item_errors():
    body = {"errors": True, "items": [
        {"index": {"_id": "ok1", "status": 201}},
        {"index": {"_id": "bad2", "status": 400, "error": {"type": "mapper_parsing_exception",
                                                           "reason": "bad field"}}},
    ]}
    post = lambda *a, **k: _http(body=json.dumps(body))
    out = elastic_bulk_with_retry([{"finding_id": "ok1"}, {"finding_id": "bad2"}],
                                  base_url="https://es", index="findings", auth="k", post=post)
    assert out["ok"] is False
    assert out["events_sent"] == 1
    assert out["item_errors"][0]["type"] == "mapper_parsing_exception"


def test_elastic_bulk_retries_on_503():
    n = {"n": 0}
    def post(*a, **k):
        n["n"] += 1
        if n["n"] == 1:
            return _http(ok=False, status=503, error="overloaded")
        return _http(body=json.dumps({"errors": False, "items": [{"index": {"status": 201}}]}))
    out = elastic_bulk_with_retry([{"finding_id": "x"}], base_url="https://es",
                                  index="i", auth="k", post=post)
    assert out["ok"] is True and n["n"] == 2


# ------------------------------------------------------------------- 19 ---- #
def test_event_stream_tracks_offsets_and_resumes():
    delivered = []
    def transport(topic, value, headers):
        delivered.append((topic, json.loads(value), headers))
    stream = EventStream(transport=transport, topic="cryptoscan.findings")
    r1 = stream.publish([{"finding_id": "a"}, {"finding_id": "b"}])
    assert r1["ok"] and r1["committed_offset"] == 1
    assert stream.resume_offset() == 2
    r2 = stream.publish([{"finding_id": "c"}])
    assert r2["committed_offset"] == 2
    assert [h["offset"] for _, _, h in delivered] == ["0", "1", "2"]


def test_event_stream_stops_at_failure_keeping_contiguous_offsets():
    def transport(topic, value, headers):
        if headers["offset"] == "1":
            raise RuntimeError("broker down")
    stream = EventStream(transport=transport)
    r = stream.publish([{"finding_id": "a"}, {"finding_id": "b"}, {"finding_id": "c"}])
    assert r["ok"] is False and r["events_sent"] == 1
    assert stream.resume_offset() == 1  # next publish resumes at the failed offset


# ------------------------------------------------------------------- 20 ---- #
def test_slack_signature_verification():
    import hmac, hashlib
    secret = "8f7..."
    ts = "1700000000"
    body = json.dumps({"type": "block_actions"}).encode()
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body,
                           hashlib.sha256).hexdigest()
    assert verify_slack_request(signing_secret=secret, timestamp=ts, body=body, signature=sig)
    assert not verify_slack_request(signing_secret="wrong", timestamp=ts, body=body, signature=sig)
    assert not verify_slack_request(signing_secret=secret, timestamp=ts, body=b"tampered", signature=sig)


def test_teams_token_tenant_binding():
    good = {"iss": "https://login.microsoftonline.com/tenant-123/v2.0",
            "tid": "tenant-123", "aud": "api://cryptoscan", "azp": "app-abc"}
    assert verify_teams_token(tenant_id="tenant-123", audience="api://cryptoscan",
                              token_claims=good, expected_app_id="app-abc")
    bad = dict(good, tid="tenant-999")
    assert not verify_teams_token(tenant_id="tenant-123", audience="api://cryptoscan",
                                  token_claims=bad, expected_app_id="app-abc")
    assert not verify_teams_token(tenant_id="t", audience="a", token_claims={}, expected_app_id="x")


def test_chat_ack_action_advances_and_is_idempotent():
    st = FindingState(finding_id="FIND-9", status="OPEN")
    key = dedup_key("slack", "FIND-9")
    r1 = apply_chat_action(st, action="ack", key=key, actor="u1")
    assert r1["ok"] and st.status == "ACKNOWLEDGED"
    r2 = apply_chat_action(st, action="ack", key=key, actor="u1")
    assert r2["idempotent"] is True


def test_chat_assign_sets_assignee():
    st = FindingState(finding_id="FIND-10", status="OPEN")
    key = dedup_key("teams", "FIND-10")
    r = apply_chat_action(st, action="assign", key=key, actor="analyst@corp")
    assert r["ok"] and st.assignee == "analyst@corp" and st.status == "ASSIGNED"


def test_chat_action_rejects_wrong_key_and_unknown_action():
    st = FindingState(finding_id="FIND-11")
    bad = apply_chat_action(st, action="ack", key="cs-" + "0"*24, actor="attacker")
    assert bad["ok"] is False and st.status == "OPEN"
    invalid = apply_chat_action(st, action="delete_everything",
                                key=dedup_key("slack", "FIND-11"), actor="x")
    assert invalid["ok"] is False
