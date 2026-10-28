"""KMS *usage* from the provider's audit trail (spec 67 §21; spec 93 §13).

The distinction this file protects: a key *spec* is capability ("it could do
AES-256"), a CloudTrail record is use ("this principal encrypted with it, 41 times,
yesterday"). The collector must never slide from one to the other, and a denied
audit read must never look like "no keys were used".
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from api import estate_discovery, estate_kms

CONFIG = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "session_token": None,
    "region": "eu-west-1",
    "endpoint": "https://aws.test",
    "source": "INJECTED",
}
NOW = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
KEY = "arn:aws:kms:eu-west-1:111122223333:key/8f2c1b40-aaaa-bbbb-cccc-1234567890ab"
ROLE = "arn:aws:sts::111122223333:assumed-role/payments-api/abc"


def _event(operation: str, key_id: str = KEY, principal: str = ROLE, when: str = "2026-04-01T09:15:00Z",
           source_ip: str = "10.20.10.11") -> dict:
    detail = {
        "eventName": operation,
        "eventTime": when,
        "eventSource": "kms.amazonaws.com",
        "requestParameters": {"keyId": key_id, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"},
        "userIdentity": {"type": "AssumedRole", "arn": principal,
                         "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::111122223333:role/payments-api"}}},
        "sourceIPAddress": source_ip,
    }
    return {
        "EventId": f"evt-{operation}-{when}",
        "EventName": operation,
        "EventTime": when,
        "EventSource": "kms.amazonaws.com",
        "Username": principal,
        "Resources": [{"ResourceType": "AWS::KMS::Key", "ResourceName": key_id}],
        "CloudTrailEvent": json.dumps(detail),
    }


def _transport(pages: list[dict], *, deny: bool = False, seen: list[dict] | None = None):
    """A CloudTrail double: one page per entry in ``pages``."""
    queue = list(pages)

    def transport(method, url, headers, body, timeout):
        if seen is not None:
            seen.append({"url": url, "headers": dict(headers), "body": json.loads(body)})
        if deny:
            return 403, b'{"__type":"AccessDeniedException","message":"not authorized"}'
        page = queue.pop(0) if queue else {"Events": []}
        return 200, json.dumps(page).encode()

    return transport


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_no_credentials_is_not_attempted():
    with pytest.raises(estate_kms.PlaneNotConfigured):
        estate_kms.kms_config({})

    def boom(_db, **_kwargs):
        raise estate_kms.PlaneNotConfigured("no aws credentials")

    report = estate_discovery.run(None, persist=False, collectors={"KMS": boom})
    kms = next(item for item in report["collectors"] if item["plane"] == "KMS")
    assert kms["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in kms["impact"]


# --------------------------------------------------------------------------- #
# reading usage
# --------------------------------------------------------------------------- #
def test_a_call_request_is_a_signed_cloudtrail_lookup_for_kms():
    seen: list[dict] = []
    estate_kms.collect_kms_usage(None, transport=_transport([{"Events": []}], seen=seen),
                                 config=CONFIG, now=NOW, window_hours=12)
    assert len(seen) == 1
    call = seen[0]
    assert call["url"] == "https://aws.test/"
    assert call["headers"]["x-amz-target"] == (
        "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
    )
    assert call["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
    assert call["body"]["LookupAttributes"] == [
        {"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}
    ]
    assert call["body"]["EndTime"] - call["body"]["StartTime"] == 12 * 3600


def test_usage_events_become_audit_observed_evidence():
    events = [
        _event("Encrypt"), _event("Decrypt"), _event("GenerateDataKey"),
        _event("DescribeKey"),   # administration is not usage
        _event("CreateGrant"),   # nor is a grant
    ]
    result = estate_kms.collect_kms_usage(None, transport=_transport([{"Events": events}]),
                                          config=CONFIG, now=NOW)
    assert result["usage_observed"] == 1
    record = result["evidence"][0]
    assert record["evidence_type"] == "AUDIT_OBSERVED"
    assert record["confidence"] == "HIGH"
    assert record["layer"] == "KMS"
    assert record["facts"]["usage_state"] == "OBSERVED"
    assert record["facts"]["operations"] == {"Decrypt": 1, "Encrypt": 1, "GenerateDataKey": 1}
    assert record["facts"]["call_count"] == 3
    assert record["facts"]["principals"] == {ROLE: 3}
    assert record["facts"]["source_ips"] == ["10.20.10.11"]
    assert record["facts"]["window"]["hours"] == 24
    assert "not capability" in record["facts"]["claim"]


def test_the_principal_is_linked_to_the_key_by_an_observed_edge():
    result = estate_kms.collect_kms_usage(None, transport=_transport([{"Events": [_event("Encrypt")]}]),
                                          config=CONFIG, now=NOW)
    assert len(result["relationships"]) == 1
    edge = result["relationships"][0]
    assert edge["predicate"] == "uses"
    assert edge["basis"] == "RUNTIME_OBSERVATION"
    assert edge["attributes"]["observed"] is True
    assert edge["attributes"]["claim"] == "OBSERVED"
    assert edge["evidence_ids"], "an observed edge must cite the audit record"

    types = {asset["type"] for asset in result["assets"]}
    assert {"KMS_KEY", "SERVICE"} == types


def test_the_window_is_stated_and_a_no_event_window_says_not_observed():
    result = estate_kms.collect_kms_usage(None, transport=_transport([{"Events": []}]),
                                          config=CONFIG, now=NOW, window_hours=6)
    assert result["evidence"] == []
    assert result["usage_observed"] == 0
    assert result["window"]["hours"] == 6
    assert "NOT_OBSERVED_IN_WINDOW" in " ".join(result["limitations"])
    assert "not proof the keys are unused" in " ".join(result["limitations"])


def test_pagination_is_followed_and_a_cap_is_reported():
    page_one = {"Events": [_event("Encrypt")], "NextToken": "t1"}
    page_two = {"Events": [_event("Decrypt", when="2026-04-01T10:00:00Z")]}
    result = estate_kms.collect_kms_usage(None, transport=_transport([page_one, page_two]),
                                          config=CONFIG, now=NOW)
    assert result["evidence"][0]["facts"]["call_count"] == 2
    assert result["evidence"][0]["facts"]["first_observed"] == "2026-04-01T09:15:00Z"
    assert result["evidence"][0]["facts"]["last_observed"] == "2026-04-01T10:00:00Z"

    capped = dict(page_one)
    result = estate_kms.collect_kms_usage(None, transport=_transport([capped, page_two]),
                                          config=CONFIG, now=NOW, max_events=1)
    assert "cap was reached" in " ".join(result["limitations"])
    assert "PARTIAL" in " ".join(result["limitations"])


def test_two_keys_are_kept_apart():
    other = "arn:aws:kms:eu-west-1:111122223333:key/other-key"
    events = [_event("Encrypt"), _event("Encrypt", key_id=other, principal="arn:aws:iam::1:role/other")]
    result = estate_kms.collect_kms_usage(None, transport=_transport([{"Events": events}]),
                                          config=CONFIG, now=NOW)
    assert result["usage_observed"] == 2
    facts = {record["facts"]["key_short_id"]: record["facts"] for record in result["evidence"]}
    assert set(facts) == {"8f2c1b40-aaaa-bbbb-cccc-1234567890ab", "other-key"}
    assert facts["other-key"]["principals"] == {"arn:aws:iam::1:role/other": 1}


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #
def test_denied_audit_read_is_partial_not_zero_usage():
    result = estate_kms.collect_kms_usage(None, transport=_transport([], deny=True), config=CONFIG, now=NOW)
    assert result["evidence"] == []
    assert result["blocked"] and "cloudtrail" in result["blocked"][0]
    assert "NOT_OBSERVED, not zero" in " ".join(result["limitations"])

    outcome = estate_discovery._collect("KMS", lambda _db, **_: result, None)
    assert outcome["status"] == "PARTIAL"
    assert "NOT_OBSERVED" in outcome["impact"]


def test_a_broken_audit_response_is_a_failure_with_a_reason():
    def broken(*_args, **_kwargs):
        return 200, b"<html>not json</html>"

    result = estate_kms.collect_kms_usage(None, transport=broken, config=CONFIG, now=NOW)
    assert result["blocked"]
    assert "unparseable JSON" in result["blocked"][0]
