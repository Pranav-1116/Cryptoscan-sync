"""ZELNX §20 drift detection + §21 event-driven monitoring."""

from __future__ import annotations


from cloud_scanner.enterprise.drift import (
    APPROVED,
    EXPECTED,
    HIGH_RISK,
    UNEXPECTED,
    classify_drift,
    detect_drift,
)
from cloud_scanner.enterprise.event_monitor import (
    CloudCbom,
    CloudEventMonitor,
    CloudEventNormalizer,
)


# ------------------------------------------------------------------ §20 drift


def test_drift_detects_certificate_change():
    before = {"cert-1": {"serial": "AA", "valid_to": "2030-01-01"}}
    after = {"cert-1": {"serial": "BB", "valid_to": "2032-01-01"}}
    result = detect_drift(before, after)
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.kind == "CERTIFICATE_CHANGED"
    assert obs.classification == UNEXPECTED
    assert obs.alert is True


def test_drift_detects_rotation_disabled_as_high_risk():
    before = {"k1": {"rotation_enabled": True}}
    after = {"k1": {"rotation_enabled": False}}
    result = detect_drift(before, after)
    obs = result.observations[0]
    assert obs.kind == "KMS_KEY_ROTATION_DISABLED"
    assert obs.classification == HIGH_RISK
    assert obs.alert is True


def test_drift_detects_encryption_disabled_as_high_risk():
    result = detect_drift(
        {"b1": {"encryption_enabled": True}},
        {"b1": {"encryption_enabled": False}},
    )
    assert result.observations[0].kind == "ENCRYPTION_DISABLED"
    assert result.observations[0].classification == HIGH_RISK


def test_drift_detects_tls_policy_change():
    result = detect_drift(
        {"e1": {"tls_version": "TLSv1.3"}},
        {"e1": {"tls_version": "TLSv1.2"}},
    )
    assert result.observations[0].kind == "TLS_POLICY_CHANGED"
    assert result.observations[0].classification == UNEXPECTED


def test_drift_detects_new_public_endpoint():
    result = detect_drift({}, {"e1": {"provider": "aws", "tls_version": "TLSv1.3"}})
    obs = result.observations[0]
    assert obs.kind == "NEW_PUBLIC_ENDPOINT"
    assert obs.classification == HIGH_RISK  # new public surface


def test_drift_detects_new_account():
    result = detect_drift({}, {"acct-9": {"provider": "aws", "account_id": "acct-9"}})
    assert result.observations[0].kind == "NEW_CLOUD_ACCOUNT"


def test_drift_detects_key_permission_change():
    result = detect_drift(
        {"k1": {"permissions": ["Encrypt"]}},
        {"k1": {"permissions": ["Encrypt", "PutKeyPolicy"]}},
    )
    assert result.observations[0].kind == "KEY_PERMISSION_CHANGED"
    assert result.observations[0].classification == HIGH_RISK


def test_drift_detects_new_algorithm():
    result = detect_drift(
        {"k1": {"algorithm": "RSA"}},
        {"k1": {"algorithm": "ML-KEM-768"}},
    )
    assert result.observations[0].kind == "NEW_CRYPTO_ALGORITHM"
    assert result.observations[0].classification == UNEXPECTED


def test_drift_approved_and_expected_classifications():
    result = detect_drift(
        {"k1": {"rotation_enabled": True}},
        {"k1": {"rotation_enabled": False}},
        approved_changes={("KMS_KEY_ROTATION_DISABLED", "k1")},
        expected_changes={("TLS_POLICY_CHANGED", "e1")},
    )
    obs = result.observations[0]
    assert obs.classification == APPROVED
    assert obs.alert is False


def test_classify_drift_rules():
    assert classify_drift("CERTIFICATE_CHANGED") == UNEXPECTED
    assert classify_drift("CERTIFICATE_CHANGED", expected=True) == EXPECTED
    assert classify_drift("CERTIFICATE_CHANGED", approved=True) == APPROVED
    assert classify_drift("ENCRYPTION_DISABLED") == HIGH_RISK
    assert classify_drift("NEW_PUBLIC_ENDPOINT") == HIGH_RISK
    assert classify_drift("KMS_KEY_ROTATION_DISABLED") == HIGH_RISK
    assert classify_drift("KEY_PERMISSION_CHANGED") == HIGH_RISK


def test_drift_no_change_returns_empty():
    assert detect_drift({"a": {"v": 1}}, {"a": {"v": 1}}).observations == []
    assert detect_drift({}, {}).observations == []


def test_drift_summary_counts():
    result = detect_drift(
        {"k1": {"rotation_enabled": True}},
        {"k1": {"rotation_enabled": False}},
    )
    summary = result.summary()
    assert summary["drift"] == 1
    assert summary["by_classification"][HIGH_RISK] == 1
    assert summary["alerts"] == 1


# ------------------------------------------------------------------ §21 events


def test_event_normalizer_shapes_provider_events():
    normalizer = CloudEventNormalizer()
    event = normalizer.normalize({
        "provider": "aws", "event_type": "kms", "event_id": "evt-1",
        "resource": "arn:aws:kms:key-1", "account": "111", "region": "us-east-1",
        "occurred_at": "2026-08-30T10:00:00Z",
        "details": {"keyState": "Disabled"},
    })
    assert event is not None
    assert event.provider == "aws"
    assert event.event_type == "KMS_KEY_CHANGE"  # mapped from aws.kms
    assert event.resource == "arn:aws:kms:key-1"
    assert event.crypto_relevant is True


def test_event_normalizer_skips_unknown_shape():
    normalizer = CloudEventNormalizer()
    assert normalizer.normalize({}) is None
    assert normalizer.normalize({"provider": "aws"}) is None
    assert normalizer.normalize({"event_type": "kms"}) is None


def test_event_normalizer_crypto_relevance():
    normalizer = CloudEventNormalizer()
    assert normalizer.normalize({
        "provider": "aws", "event_type": "kms",
        "resource": "k1", "details": {"x": 1},
    }).crypto_relevant is True
    assert normalizer.normalize({
        "provider": "aws", "event_type": "ec2", "resource": "i-1",
        "details": {"state": "running"},
    }).crypto_relevant is False


def test_cloud_cbom_upsert_and_revisions():
    cbom = CloudCbom()
    normalizer = CloudEventNormalizer()
    event = normalizer.normalize({
        "provider": "aws", "event_type": "kms", "resource": "k1",
        "details": {"keyState": "Enabled"},
    })
    entry1 = cbom.upsert(event)
    entry2 = cbom.upsert(event)
    # upsert returns the live entry — same object, revision increments
    assert entry2.revision == 2
    assert entry1 is entry2
    assert cbom.count() == 1
    assert cbom.summary()["events_applied"] == 2


def test_event_monitor_full_pipeline():
    monitor = CloudEventMonitor()
    result = monitor.process([
        {"provider": "aws", "event_type": "kms", "resource": "k1",
         "details": {"rotation_enabled": False}},
        {"provider": "aws", "event_type": "ec2", "resource": "i-1",
         "details": {"state": "running"}},  # not crypto relevant
    ])
    assert len(result.events) == 2
    assert len(result.changes) == 1
    assert len(result.cbom_updates) == 1
    assert result.policy_evaluations  # compliance ran over the CBOM
    assert len(result.drift.observations) == 1
    drift = result.drift.observations[0]
    assert drift.kind == "KMS_KEY_ROTATION_DISABLED"
    assert drift.classification == HIGH_RISK
    assert drift.alert is True


def test_event_monitor_approved_change_not_alerted():
    monitor = CloudEventMonitor()
    result = monitor.process(
        [{"provider": "aws", "event_type": "kms", "resource": "k1",
          "details": {"rotation_enabled": False}}],
        approved_changes={("KMS_KEY_ROTATION_DISABLED", "k1")},
    )
    assert result.drift.observations[0].classification == APPROVED
    assert result.drift.observations[0].alert is False


def test_event_monitor_sinks_receive_changes():
    received = []

    def sink(change):
        received.append(change)

    monitor = CloudEventMonitor(sinks=[sink])
    monitor.process([{"provider": "aws", "event_type": "kms", "resource": "k1",
                      "details": {"keyState": "Disabled"}}])
    assert received
    assert received[0]["resource"] == "k1"


def test_event_monitor_certificate_change_drift():
    monitor = CloudEventMonitor()
    result = monitor.process([
        {"provider": "gcp", "event_type": "certificatemanager", "resource": "cert-1",
         "details": {"serial": "S1"}},
        {"provider": "gcp", "event_type": "certificatemanager", "resource": "cert-1",
         "details": {"serial": "S2"}},
    ])
    drift = result.drift.observations
    assert any(obs.kind == "CERTIFICATE_CHANGED" for obs in drift)


def test_event_monitor_to_dict_shape():
    monitor = CloudEventMonitor()
    result = monitor.process([{"provider": "aws", "event_type": "kms", "resource": "k1",
                               "details": {"x": 1}}])
    payload = result.to_dict()
    assert set(payload) == {"events", "changes", "cbom_updates", "policy_evaluations", "drift",
                            "drift_summary"}
    assert payload["drift_summary"]["drift"] == 1
