"""KMS/HSM key inventory: metadata only, and three answers kept apart."""

from __future__ import annotations

from datetime import date

from cbom import kms_collectors as kc

KEY = {"key_ref": "arn:aws:kms:eu-west-1:111:key/PAY-SIGN-001", "algorithm": "RSA",
       "key_size": 2048, "purpose": "SIGNATURE", "provider": "AWS_KMS",
       "location": "eu-west-1", "status": "ENABLED", "created_at": "2024-01-01",
       "evidence_id": "KMS-EVID-001"}


# --------------------------------------------------------------------------- #
# records


def test_a_key_row_becomes_metadata_without_material():
    body = kc.key_records_from_kms([KEY])
    record = body["records"][0]
    assert record["key_ref"] == KEY["key_ref"]
    assert record["private_material"] == "NOT STORED"
    assert record["usable"] is True
    assert body["statement"].endswith("metadata only")


def test_provider_aliases_are_accepted():
    body = kc.key_records_from_kms([{"key_id": "k-1", "alias": None,
                                     "algorithm": "AES", "key_size_bits": 256,
                                     "provider": "GCP_KMS", "status": "ACTIVE",
                                     "evidence_id": "E-1"}])
    record = body["records"][0]
    assert record["key_ref"] == "k-1" and record["key_size"] == 256
    assert record["ignored_fields"] == ["alias"]


def test_a_row_with_key_material_is_refused():
    body = kc.key_records_from_kms([{**KEY, "private_key_pem": "-----BEGIN-----"}])
    assert body["records"] == []
    assert "never material" in body["refused"][0]["reason"]


def test_a_row_with_no_reference_is_refused():
    body = kc.key_records_from_kms([{"algorithm": "RSA", "provider": "AWS_KMS"}])
    assert body["refused"] and "key_ref" in body["refused"][0]["reason"]


def test_one_bad_row_does_not_hide_the_rest():
    body = kc.key_records_from_kms([{"algorithm": "RSA"}, KEY])
    assert len(body["records"]) == 1 and len(body["refused"]) == 1


def test_a_declared_provider_is_marked_declared():
    body = kc.key_records_from_kms([{**KEY, "provider": ""}])
    assert body["records"][0]["provider"] == "UNKNOWN"
    assert body["records"][0]["provider_declared_only"] is True


def test_a_unknown_state_key_is_not_usable():
    body = kc.key_records_from_kms([{**KEY, "status": "PENDING_DELETION"}])
    assert body["records"][0]["usable"] is False


# --------------------------------------------------------------------------- #
# configured vs used


def _records(**overrides):
    return kc.key_records_from_kms([{**KEY, **overrides}])["records"]


def test_an_enabled_key_is_configured_and_nothing_more():
    body = kc.usage_events_from_keys(_records())
    assert body["configured"] == 1 and body["operated"] == 0
    assert body["events"][0]["class"] == "CONFIGURED"
    assert "a configured key is not usage" in body["statement"]


def test_a_recorded_operation_is_runtime_evidence():
    body = kc.usage_events_from_keys(_records(), [
        {"key_ref": KEY["key_ref"], "operation": "sign", "evidence_id": "HSM-EVID-001",
         "observed_at": "2026-11-02T10:00:00Z"}])
    assert body["operated"] == 1
    operation = next(event for event in body["events"]
                     if event["class"] == "RUNTIME_OBSERVED")
    assert operation["operation"] == "SIGN"
    assert operation["algorithm"] == "RSA"


def test_a_disabled_key_is_not_a_configured_key():
    body = kc.usage_events_from_keys(_records(status="DISABLED"))
    assert body["configured"] == 0
    assert "not a usable configured key" in body["refused"][0]["reason"]


def test_an_inventory_row_without_an_evidence_id_is_refused():
    body = kc.usage_events_from_keys(_records(evidence_id=None))
    assert body["events"] == [] and body["refused"]


def test_an_operation_on_an_unknown_key_is_refused():
    body = kc.usage_events_from_keys(_records(), [
        {"key_ref": "HSM://nowhere", "operation": "SIGN", "evidence_id": "E-1",
         "observed_at": "2026-11-02"}])
    assert body["operated"] == 0
    assert "inventory is incomplete" in body["refused"][0]["reason"]


def test_an_operation_missing_its_evidence_is_refused():
    body = kc.usage_events_from_keys(_records(), [
        {"key_ref": KEY["key_ref"], "operation": "SIGN"}])
    assert body["operated"] == 0
    assert "evidence_id" in body["refused"][0]["reason"]


def test_the_events_feed_the_usage_profile():
    records = _records()
    built = kc.usage_events_from_keys(records, [
        {"key_ref": KEY["key_ref"], "operation": "SIGN", "evidence_id": "HSM-EVID-001",
         "observed_at": "2026-11-02T10:00:00Z"}])
    from cbom import usage_evidence as ue

    profile = ue.usage_profile({"algorithm": "RSA", "parameters": {"key_size": 2048}},
                               built["events"])
    assert profile["usage"] == "OBSERVED"
    assert profile["layers"]["config"]["observed"] is True
    assert profile["layers"]["runtime"]["observed"] is True
    assert profile["confidence"] == "HIGH"


# --------------------------------------------------------------------------- #
# posture


def test_posture_counts_algorithms_providers_and_statuses():
    body = kc.posture(_records(), as_of=date(2026, 11, 2))
    assert body["keys"] == 1
    assert body["by_algorithm"] == {"RSA": 1}
    assert body["by_provider"] == {"AWS_KMS": 1}
    assert body["by_status"] == {"ENABLED": 1}


def test_a_weak_rsa_key_is_reported():
    body = kc.posture(_records(key_size=1024), as_of=date(2026, 11, 2))
    assert body["weak_keys"][0]["key_size"] == 1024
    assert "1 weak" in body["statement"]


def test_a_short_curve_is_reported():
    body = kc.posture(_records(algorithm="EC", curve="P-192", key_size=None),
                      as_of=date(2026, 11, 2))
    assert body["weak_keys"][0]["curve"] == "P-192"


def test_rotation_overdue_is_measured_against_the_policy_age():
    body = kc.posture(_records(created_at="2024-01-01"), as_of=date(2026, 11, 2),
                      max_age_days=365)
    assert body["rotation_overdue"][0]["key_ref"] == KEY["key_ref"]
    assert body["rotation_overdue"][0]["age_days"] > 365


def test_a_recent_rotation_clears_the_overdue_list():
    body = kc.posture(_records(rotated_at="2026-06-01"), as_of=date(2026, 11, 2))
    assert body["rotation_overdue"] == []


def test_a_key_with_no_dates_has_an_unknown_age_not_a_fresh_one():
    body = kc.posture(_records(created_at=None), as_of=date(2026, 11, 2))
    assert body["unknown_age"] == [KEY["key_ref"]]
    assert body["rotation_overdue"] == []


def test_an_unknown_provider_is_kept_and_flagged():
    body = kc.key_records_from_kms([{**KEY, "provider": "ACME_VAULT"}])
    record = body["records"][0]
    assert record["provider"] == "ACME_VAULT" and record["provider_unknown"] is True
    known = kc.key_records_from_kms([KEY])["records"][0]
    assert known["provider_unknown"] is False
