"""Privacy engine tests — classification, redaction, data minimization, private-key refusal."""

from __future__ import annotations

from privacy.classify import DataClass, classify_value
from privacy.policy import PrivacyPolicy, build_policy
from privacy.redact import RedactionEngine


def test_classify_value():
    assert classify_value("password", "hunter2") is DataClass.RESTRICTED
    assert classify_value("api_key", "AKIA123456") is DataClass.RESTRICTED
    assert classify_value("algorithm", "RSA-2048") is DataClass.PUBLIC
    assert classify_value("certificate_subject", "CN=bank.com") is DataClass.SENSITIVE
    assert classify_value("payload", "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----") is DataClass.RESTRICTED


def test_redaction_drops_private_key_and_stores_metadata():
    eng = RedactionEngine(PrivacyPolicy())
    obs = {
        "asset": "router-001", "source": "network", "observation_type": "crypto",
        "algorithm": "RSA-2048", "key_size": 2048,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        "password": "hunter2",
    }
    res = eng.process(obs)
    assert res.private_key_detected is True
    assert res.should_store is False                      # never store the key
    assert "private_key" in res.dropped_fields
    assert res.observation.get("dropped_private_key") is True
    assert res.alerts and "PRIVATE_KEY_DETECTED:private_key" in res.alerts
    # the stored metadata keeps algorithm/key_size/fingerprint: no key material
    stored = {k: v for k, v in res.observation.items()}
    assert "algorithm" in stored
    if "private_key" in stored:
        assert "PRIVATE KEY" not in str(stored["private_key"])


def test_redaction_masks_sensitive_but_keeps_public():
    eng = RedactionEngine(PrivacyPolicy())
    obs = {"asset": "server-20", "source": "network", "observation_type": "crypto",
           "email": "alice@bank.com", "algorithm": "ECDSA", "hostname": "server-20",
           "password": "s3cret"}
    res = eng.process(obs)
    # password is restricted -> dropped
    assert "password" in res.dropped_fields
    # email is sensitive -> masked (or tokenized) or dropped by minimization
    stored_email = res.observation.get("email")
    assert stored_email is None or any(c in str(stored_email) for c in ("*", "tok_"))
    # algorithm (on the crypto data-minimization allowlist) survives
    assert res.observation.get("algorithm") == "ECDSA"


def test_data_minimization_allowlist():
    eng = RedactionEngine(PrivacyPolicy(data_minimization=True))
    res = eng.process({"asset": "router-001", "source": "network",
                       "observation_type": "asset", "extra_unneeded": "spam",
                       "full_config": "router running-config", "model": "ISR4451"})
    # extra_unneeded / full_config are not on the crypto/apps allowlist -> dropped
    assert "extra_unneeded" in res.dropped_fields or "extra_unneeded" not in res.observation
    assert "full_config" not in res.observation


def test_payload_limit_truncates():
    # masking disabled so an over-long value is truncated rather than masked
    eng = RedactionEngine(PrivacyPolicy(collect_private_keys=False, max_payload_bytes=20,
                                        mask_sensitive_fields=False))
    res = eng.process({"asset": "a", "source": "network", "observation_type": "asset",
                       "name": "x" * 500})
    assert res.truncated_payload is True
    assert len(str(res.observation.get("name", ""))) <= 120


def test_build_policy_sector_defaults():
    pol = build_policy(sector="banking")
    assert pol.privacy.collect_private_keys is False
    assert pol.scan.mode == "read-only"
    assert pol.privacy.retention_days == 180
    # unknown keys ignored
    pol2 = build_policy({"nonsense": True}, {"unused": 1})
    assert pol2.scan.intensity in ("off", "low", "medium", "high")


def test_apply_sector_overrides_never_loosens():
    from privacy.policy import apply_sector_overrides
    base = build_policy({"max_connections": 1000, "mode": "controlled_active"},
                        {"collect_private_keys": False})
    bank = apply_sector_overrides(base, "banking")
    # a stricter profile clamps numeric caps downward and keeps read-only mode
    assert bank.scan.max_connections < 1000
    assert bank.privacy.collect_private_keys is False


def test_sanitize_snapshot_drops_private_key_and_secret():
    from privacy.engine import sanitize_snapshot
    from privacy.policy import PrivacyPolicy

    snap = {"results": {"n": {"data": {"findings": [
        {"asset": "db", "private_key": "-----BEGIN RSA PRIVATE KEY-----\nAA", "algorithm": "RSA"},
        {"asset": "app", "secret": "AKIAIOSFODNN7EXAMPLE"},
    ]}}}}
    pol = PrivacyPolicy(collect_private_keys=False, collect_secrets=False, data_minimization=False)
    san, report = sanitize_snapshot(snap, pol)
    f0 = san["results"]["n"]["data"]["findings"][0]
    f1 = san["results"]["n"]["data"]["findings"][1]
    assert f0.get("private_key") is None
    assert f0.get("algorithm") == "RSA"
    assert f1.get("secret") is None
    assert report.private_key_detected is True
    assert any("private_key" in d for d in report.dropped)
    assert any("secret" in d for d in report.dropped)


def test_sanitize_snapshot_masks_pii():
    from privacy.engine import sanitize_snapshot
    from privacy.policy import PrivacyPolicy

    snap = {"results": {"n": {"data": {"findings": [
        {"asset": "app", "email": "ops@bank.com", "host": "10.0.0.1"},
    ]}}}}
    pol = PrivacyPolicy(collect_pii=False, data_minimization=False)
    san, _ = sanitize_snapshot(snap, pol)
    f = san["results"]["n"]["data"]["findings"][0]
    assert f["email"].startswith("op***")
    assert f["host"] == "10.0.0.1"


def test_sanitize_snapshot_data_minimization_keep_allowlist():
    from privacy.engine import sanitize_snapshot
    from privacy.policy import PrivacyPolicy

    snap = {"results": {"n": {"data": {"findings": [
        {"asset": "cert", "observation_type": "crypto", "algorithm": "AES",
         "key_size": 256, "password": "p@ss"},
    ]}}}}
    pol = PrivacyPolicy(data_minimization=True)
    san, _ = sanitize_snapshot(snap, pol)
    f = san["results"]["n"]["data"]["findings"][0]
    # allowlist keeps asset/observation_type/algorithm/key_size; drops password
    assert f.get("algorithm") == "AES"
    assert f.get("password") is None


def test_sanitize_snapshot_private_key_collect_allowed_keeps_when_opted_in():
    from privacy.engine import sanitize_snapshot
    from privacy.policy import PrivacyPolicy

    snap = {"results": {"n": {"data": {"findings": [
        {"asset": "db", "private_key": "-----BEGIN PRIVATE KEY-----\nAA"},
    ]}}}}
    pol = PrivacyPolicy(collect_private_keys=True, data_minimization=False)
    san, _ = sanitize_snapshot(snap, pol)
    assert san["results"]["n"]["data"]["findings"][0].get("private_key") is not None
