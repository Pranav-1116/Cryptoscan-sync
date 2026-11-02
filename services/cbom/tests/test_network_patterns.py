"""Review item 19: several network changes, one pattern, never an attack."""

from __future__ import annotations

import pytest

from cbom import network_patterns as np

PAYMENTS = {
    "host": "payments.bank.example", "port": 443, "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1",
    "certificate": {"fingerprint_sha256": "aa11", "issuer": "BANK-ICA-01"},
}
DOWNGRADED = {**PAYMENTS, "tls_version": "1.2",
              "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-9",
              "certificate": {"fingerprint_sha256": "cc33", "issuer": "BANK-ICA-09"}}
PARTNER = {"host": "partner.bank.example", "port": 443, "tls_version": "1.2",
           "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "NET-2"}
NEW = {"host": "new.bank.example", "port": 9443, "tls_version": "1.3",
       "evidence_id": "NET-10"}
PROCESS = {"process": "/usr/local/bin/openssl", "pid": 9182,
           "host": "payments.bank.example", "evidence_id": "RT-1",
           "observed_at": "2026-11-02T00:00:00Z"}


def _comparison(before, after):
    from cbom import nbom_history as nh

    return nh.compare(nh.snapshot(before, taken_at="2026-11-01T00:00:00Z"),
                      nh.snapshot(after, taken_at="2026-11-02T00:00:00Z"))


def _window(before=None, after=None, processes=None):
    return np.signals(_comparison(before or [PAYMENTS], after or [DOWNGRADED]),
                      processes=processes)


def test_the_reviews_four_signals_are_derived_from_a_snapshot_comparison():
    window = _window(after=[DOWNGRADED, NEW], processes=[PROCESS])
    assert window["counts"] == {"CERTIFICATE_MUTATION": 1, "CIPHER_DOWNGRADE": 1,
                                "NEW_ENDPOINT": 1, "NEW_PROCESS": 1,
                                "TLS_DOWNGRADE": 1, "TRUST_PATH_CHANGE": 1}
    assert {signal["source"] for signal in window["signals"]} == {"NETWORK", "RUNTIME"}


def test_the_four_signals_become_one_pattern_classified_suspicious_activity():
    result = np.correlate(_window(after=[DOWNGRADED, NEW], processes=[PROCESS]))
    combined = [pattern for pattern in result["patterns"]
                if pattern["name"] == "CORRELATED_PATTERN"]
    assert len(combined) == 1
    assert combined[0]["level"] == 2
    assert combined[0]["classification"] == "SUSPICIOUS_ACTIVITY"
    assert combined[0]["coinciding_signals"] == sorted(np.REVIEW_SIGNALS)
    assert "SUSPICIOUS_ACTIVITY" in result["statement"]


def test_no_pattern_ever_says_attack_or_incident():
    import json

    result = np.correlate(_window(after=[DOWNGRADED, NEW], processes=[PROCESS]))
    body = json.dumps(result["patterns"]).lower()
    for phrase in ("attack detected", "compromise confirmed", "attacker identified"):
        assert phrase not in body
    assert "SECURITY_INCIDENT" in result["never"]
    assert all(pattern["level"] <= np.MAX_LEVEL for pattern in result["patterns"])


def test_every_pattern_states_what_it_does_not_prove():
    result = np.correlate(_window(after=[DOWNGRADED, NEW], processes=[PROCESS]))
    assert result["patterns"]
    for pattern in result["patterns"]:
        assert any("attacked" in line for line in pattern["not_proven"])
        assert any("compromised" in line for line in pattern["not_proven"])
        assert any("who did it" in line.lower() for line in pattern["not_proven"])
        assert "not a finding of compromise" in result["statement"]


def test_an_upgrade_is_a_change_and_not_a_signal():
    upgraded = {**PAYMENTS, "tls_version": "1.2", "evidence_id": "NET-0"}
    window = np.signals(_comparison([upgraded], [PAYMENTS]))
    assert window["signals"] == []
    assert any("upgrade" in item["reason"].lower() for item in window["skipped"])
    assert np.correlate(window)["patterns"] == []


def test_a_certificate_replacement_alone_is_not_a_combination():
    window = np.signals(_comparison([PAYMENTS], [{**PAYMENTS,
                                                  "certificate": {
                                                      "fingerprint_sha256": "zz99",
                                                      "issuer": "BANK-ICA-01"}}]))
    result = np.correlate(window)
    names = {pattern["name"] for pattern in result["patterns"]}
    assert "CORRELATED_PATTERN" not in names
    assert "TRUST_PATH_SHIFT" not in names
    assert "NETWORK_CRYPTO_REGRESSION" in names


def test_a_new_listener_and_a_new_process_alone_are_ordinary_operations():
    window = np.signals(_comparison([PAYMENTS], [PAYMENTS, NEW]), processes=[PROCESS])
    result = np.correlate(window)
    assert result["patterns"][0]["name"] == "NEW_EXPOSURE"
    assert result["patterns"][0]["level"] == 1
    assert "CORRELATED_PATTERN" not in {pattern["name"] for pattern in result["patterns"]}


def test_a_downgrade_and_a_replaced_certificate_on_one_endpoint_is_a_trust_path_shift():
    result = np.correlate(_window())
    shift = [pattern for pattern in result["patterns"]
             if pattern["name"] == "TRUST_PATH_SHIFT"]
    assert shift and shift[0]["subjects"] == ["payments.bank.example:443"]
    assert "renewal and an interception look the same" in " ".join(
        shift[0]["not_proven"])


def test_a_downgrade_on_one_endpoint_and_a_new_listener_elsewhere_are_not_one_path():
    result = np.correlate(_window(after=[DOWNGRADED, NEW]))
    shift = [pattern for pattern in result["patterns"]
             if pattern["name"] == "TRUST_PATH_SHIFT"]
    assert len(shift) == 1
    assert shift[0]["subjects"] == ["payments.bank.example:443"]


def test_signals_outside_the_window_are_not_correlated():
    from datetime import datetime, timedelta, timezone

    comparison = _comparison([PAYMENTS], [DOWNGRADED, NEW])
    anchor = datetime(2026, 11, 2, tzinfo=timezone.utc)
    late = {**NEW, "endpoint": "later.bank.example:443"}
    comparison["changes"].append({**comparison["changes"][0],
                                  "endpoint": late["endpoint"],
                                  "kind": "ENDPOINT_ADDED"})
    window = np.signals(comparison)
    assert window["window"]["seconds"] == np.DEFAULT_WINDOW_SECONDS
    assert len(window["signals"]) == len(comparison["changes"])
    assert window["window"]["to"].startswith("2026-11-02")
    assert (datetime.fromisoformat(window["window"]["to"]) - anchor
            ) < timedelta(minutes=1)


def test_an_undated_signal_cannot_be_correlated():
    comparison = _comparison([PAYMENTS], [DOWNGRADED])
    for change in comparison["changes"]:
        change.pop("observed_at", None)
    comparison["after"]["taken_at"] = None
    window = np.signals(comparison)
    assert window["signals"] == []
    assert window["undated"] == len(comparison["changes"])
    assert np.correlate(window)["patterns"] == []


def test_a_collection_gap_is_a_blind_spot_not_a_signal():
    blind = {**PAYMENTS, "observed": False}
    window = np.signals(_comparison([PAYMENTS], [blind]))
    assert window["blind_spots"] == ["payments.bank.example:443"]
    assert "COLLECTION_STATUS_CHANGED" not in {signal["change_kind"]
                                              for signal in window["signals"]}
    result = np.correlate(window)
    assert "window is not complete" in result["statement"]


def test_a_window_that_is_not_a_window_is_refused():
    with pytest.raises(ValueError, match="not a"):
        np.correlate({"signals": []})
    with pytest.raises(ValueError, match="not a"):
        np.correlate({"schema": "cryptoscan.nbom-history/1", "signals": []})


def test_the_summary_counts_patterns_by_name_and_reports_the_blind_spots():
    result = np.correlate(_window(after=[DOWNGRADED, NEW], processes=[PROCESS]))
    body = np.summary(result)
    assert body["patterns"] == len(result["patterns"])
    assert body["by_name"]["CORRELATED_PATTERN"] == 1
    assert body["worst"] == "SUSPICIOUS_ACTIVITY"
    assert body["not_proven"]
    assert body["statement"] == result["statement"]


def test_a_new_process_is_bound_to_the_endpoint_it_was_seen_on():
    window = np.signals(_comparison([PAYMENTS], [PAYMENTS]), processes=[PROCESS])
    row = window["signals"][0]
    assert row["signal"] == "NEW_PROCESS" and row["source"] == "RUNTIME"
    assert row["subject"] == "payments.bank.example"
    assert row["after"] == "/usr/local/bin/openssl (pid 9182)"
    assert row["evidence_ids"] == ["RT-1"]


def test_an_endpoint_lost_is_a_signal_but_not_a_weakening():
    window = np.signals(_comparison([PAYMENTS, PARTNER], [PAYMENTS]))
    assert [signal["signal"] for signal in window["signals"]] == ["ENDPOINT_LOST"]
    result = np.correlate(window)
    assert "NETWORK_CRYPTO_REGRESSION" not in {p["name"] for p in result["patterns"]}
    assert result["patterns"][0]["level"] == 1
