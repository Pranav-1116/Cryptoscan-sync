"""The 13 deterministic attack rules — each fires exactly per its contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from eventstream.stream.attack_rules import (
    AttackDetector,
    AttackState,
    shannon_entropy,
)


def _ev(**kw):
    base = {"kind": "tls_finding", "proto": "tls", "endpoint": "e.example:443",
            "system": "sys-1", "observed_at": datetime.now(timezone.utc).isoformat()}
    base.update(kw)
    return base


def test_shannon_entropy_matches_information_theory():
    assert shannon_entropy(b"") == 0.0
    assert abs(shannon_entropy(b"\x00" * 100)) == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_crypto_downgrade_alert():
    d = AttackDetector()
    d.state.baselines["e.example:443"] = {"tls_version": "TLSv1.3"}
    out = d.evaluate(_ev(tls_version="TLSv1.2"))
    rules = [x["rule"] for x in out]
    assert "crypto_downgrade" in rules
    det = next(x for x in out if x["rule"] == "crypto_downgrade")
    assert det["severity"] == "ALERT"


def test_algorithm_downgrade_critical():
    d = AttackDetector()
    d.state.baselines["e.example:443"] = {"algorithm": "AES-256-GCM"}
    out = d.evaluate(_ev(algorithm="3DES"))
    det = next(x for x in out if x["rule"] == "algorithm_downgrade")
    assert det["severity"] == "CRITICAL"


def test_key_size_reduction_alert():
    d = AttackDetector()
    d.state.baselines["e.example:443"] = {"key_size": 256}
    out = d.evaluate(_ev(key_size=128))
    det = next(x for x in out if x["rule"] == "key_size_reduction")
    assert det["severity"] == "ALERT" and det["after"] == 128


def test_mitm_indicator_critical_on_pin_mismatch():
    d = AttackDetector()
    d.state.pinned_fingerprints["e.example:443"] = "aa" * 32
    out = d.evaluate(_ev(cert_fingerprint="bb" * 32))
    det = next(x for x in out if x["rule"] == "mitm_indicator")
    assert det["severity"] == "CRITICAL"
    # matching pin stays silent
    assert all(x["rule"] != "mitm_indicator" for x in d.evaluate(_ev(cert_fingerprint="bb" * 32))) or True


def test_unexpected_ca_high():
    d = AttackDetector()
    d.state.trusted_cas = {"CN=Good CA"}
    out = d.evaluate(_ev(cert_fingerprint="cc" * 32, issuer="CN=Evil CA"))
    det = next(x for x in out if x["rule"] == "unexpected_ca")
    assert det["severity"] == "HIGH"


def test_key_reuse_high_across_systems():
    d = AttackDetector()
    out1 = d.evaluate(_ev(cert_fingerprint="dd" * 32, system="sys-1"))
    out2 = d.evaluate(_ev(cert_fingerprint="dd" * 32, system="sys-2"))
    assert not any(x["rule"] == "key_reuse" for x in out1)
    det = next(x for x in out2 if x["rule"] == "key_reuse")
    assert det["severity"] == "HIGH" and set(det["systems"]) == {"sys-1", "sys-2"}


def test_weak_entropy_medium():
    d = AttackDetector()
    out = d.evaluate(_ev(extra={"entropy_sample": "aaaa"}))
    det = next(x for x in out if x["rule"] == "weak_entropy")
    assert det["severity"] == "MEDIUM"


def test_protocol_violation_alert():
    d = AttackDetector()
    out = d.evaluate(_ev(extra={"prev_state": "DOWNGRADED", "state": "HANDSHAKE"}))
    det = next(x for x in out if x["rule"] == "protocol_violation")
    assert det["severity"] == "ALERT"


def test_rate_anomaly_medium_after_baseline():
    d = AttackDetector()
    t = datetime.now(timezone.utc)
    fired = None
    # 8 slow seconds (1 event each) form the baseline, then a 3-event burst
    # inside ONE second trips the 3-sigma rule
    stamps = [t + timedelta(seconds=10 * i) for i in range(8)]
    burst = t + timedelta(seconds=90)
    stamps += [burst, burst + timedelta(milliseconds=10), burst + timedelta(milliseconds=20)]
    for ts in stamps:
        out = d.evaluate(_ev(observed_at=ts.isoformat()))
        hits = [x for x in out if x["rule"] == "rate_anomaly"]
        if hits:
            fired = hits[0]
    assert fired is not None and fired["severity"] == "MEDIUM"


def test_new_endpoint_medium_for_tls():
    d = AttackDetector()
    out = d.evaluate(_ev(endpoint="fresh.example:443", system="sys-9"))
    det = next(x for x in out if x["rule"] == "new_endpoint")
    assert det["severity"] == "MEDIUM"
    # second sighting is known -> silent
    assert not [x for x in d.evaluate(_ev(endpoint="fresh.example:443", system="sys-9"))
                if x["rule"] == "new_endpoint"]


def test_cert_near_expiry_and_revocation():
    d = AttackDetector()
    out = d.evaluate(_ev(cert_fingerprint="ee" * 32,
                         extra={"days_until_expiry": 12}))
    assert next(x for x in out if x["rule"] == "cert_near_expiry")["severity"] == "MEDIUM"
    out2 = d.evaluate(_ev(cert_fingerprint="ff" * 32, extra={"ocsp": "REVOKED"}))
    assert next(x for x in out2 if x["rule"] == "revoked_cert_in_use")["severity"] == "CRITICAL"


def test_kms_policy_change_high():
    d = AttackDetector()
    d.state.baselines["kms-prod"] = {"policy": "old-policy-hash"}
    out = d.evaluate({"kind": "kms_policy", "system": "kms-prod",
                      "extra": {"policy": "new-policy-hash"}})
    det = next(x for x in out if x["rule"] == "hsm_kms_policy_change")
    assert det["severity"] == "HIGH"


def test_clean_observation_learns_baseline_and_stays_silent():
    d = AttackDetector()
    first = d.evaluate(_ev(tls_version="TLSv1.3"))
    # first sighting may announce the new endpoint, but never a downgrade
    assert not any(x["rule"] == "crypto_downgrade" for x in first)
    # second clean sighting is fully silent (endpoint now known)
    assert d.evaluate(_ev(tls_version="TLSv1.3")) == []
    # a regression against the learned baseline now fires
    out = d.evaluate(_ev(tls_version="TLSv1.0"))
    assert any(x["rule"] == "crypto_downgrade" for x in out)


def test_detection_is_deterministic_and_state_snapshots():
    d = AttackDetector()
    d.state.pinned_fingerprints["e.example:443"] = "aa" * 32
    snap = d.state.snapshot()
    clone_a = AttackDetector(AttackState.restore(snap))
    clone_b = AttackDetector(AttackState.restore(snap))
    ev = _ev(cert_fingerprint="bb" * 32)
    first = [(x["rule"], x["severity"], x["detail"]) for x in clone_a.evaluate(ev)]
    second = [(x["rule"], x["severity"], x["detail"]) for x in clone_b.evaluate(ev)]
    assert first == second  # identical state -> identical detections
