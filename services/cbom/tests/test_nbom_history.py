"""NBOM history: snapshots, changes, and the subset that is a regression.

Review items 18 and 21 ask for the same machinery for two purposes: a change list
that is complete, and a regression list that is short, evidenced on both sides, and
explicit about what it does not prove.
"""

from __future__ import annotations

import pytest

from cbom import nbom_history as nh

PAYMENTS = {
    "host": "payments.bank.example", "port": 443, "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "sni": "payments.bank.example",
    "alpn": "h2", "evidence_id": "NET-1",
    "certificate": {"fingerprint_sha256": "aa11", "issuer": "BANK-ICA-01",
                    "not_after": "2027-01-01", "public_key_algorithm": "ECDSA",
                    "public_key_size": 256},
}
PARTNER = {
    "host": "partner.bank.example", "port": 443, "tls_version": "1.2",
    "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "NET-2",
    "certificate": {"fingerprint_sha256": "bb22", "issuer": "PARTNER-CA"},
}


def _snap(rows, taken_at="2026-11-01T00:00:00Z", collector="scanner"):
    return nh.snapshot(rows, taken_at=taken_at, collector=collector)


def _pair(after_rows):
    return nh.compare(_snap([PAYMENTS, PARTNER]),
                      _snap(after_rows, taken_at="2026-11-02T00:00:00Z"))


def _kinds(comparison):
    return {change["kind"] for change in comparison["changes"]}


# --------------------------------------------------------------------------- #
# snapshots


def test_a_snapshot_normalises_and_hashes():
    body = _snap([PAYMENTS, PARTNER])
    assert body["hash"] and len(body["hash"]) == 64
    assert [entry["identity"] for entry in body["endpoints"]] == [
        "partner.bank.example:443", "payments.bank.example:443"]


def test_the_same_state_in_a_different_order_hashes_the_same():
    first = _snap([PAYMENTS, PARTNER])
    second = _snap([PARTNER, PAYMENTS])
    assert first["hash"] == second["hash"]


def test_new_evidence_does_not_make_a_new_state():
    again = {**PAYMENTS, "evidence_id": "NET-99"}
    assert _snap([PAYMENTS, PARTNER])["hash"] == _snap([again, PARTNER])["hash"]


def test_a_changed_protocol_makes_a_new_state():
    changed = {**PAYMENTS, "tls_version": "1.2"}
    assert _snap([PAYMENTS])["hash"] != _snap([changed])["hash"]


def test_a_protocol_name_is_normalised_before_hashing():
    spelled = {**PAYMENTS, "tls_version": "TLSv1.3"}
    assert _snap([spelled])["hash"] == _snap([PAYMENTS])["hash"]


def test_the_snapshot_keeps_provenance_outside_the_digest():
    entry = _snap([PAYMENTS])["endpoints"][0]
    assert entry["evidence_ids"] == ["NET-1"]
    assert "NET-1" not in entry["digest"]


def test_two_observations_of_one_endpoint_are_refused_not_merged():
    with pytest.raises(ValueError, match="appears twice"):
        _snap([PAYMENTS, {**PAYMENTS, "tls_version": "1.2"}])


def test_an_endpoint_without_a_host_is_refused():
    with pytest.raises(ValueError, match="needs a host"):
        _snap([{"port": 443, "tls_version": "1.3"}])


def test_an_endpoint_that_is_not_an_object_is_refused():
    with pytest.raises(ValueError, match="must be an object"):
        _snap(["payments:443"])


def test_the_endpoint_form_of_the_host_is_understood():
    entry = _snap([{"endpoint": "Payments.Bank.Example:8443", "tls_version": "1.3"}])
    assert entry["endpoints"][0]["identity"] == "payments.bank.example:8443"
    assert entry["endpoints"][0]["port"] == 8443


# --------------------------------------------------------------------------- #
# the change list


def test_identical_snapshots_say_so_instead_of_listing_nothing():
    body = _snap([PAYMENTS, PARTNER])
    comparison = nh.compare(body, body)
    assert comparison["identical"] is True
    assert comparison["changes"] == []
    assert "same hash" in comparison["statement"]


def test_a_downgraded_protocol_is_a_high_severity_change():
    comparison = _pair([{**PAYMENTS, "tls_version": "1.2"}, PARTNER])
    change = [item for item in comparison["changes"]
              if item["kind"] == "TLS_VERSION_CHANGED"][0]
    assert change["severity"] == "HIGH" and change["direction"] == "DOWNGRADE"
    assert change["before"] == "TLS1.3" and change["after"] == "TLS1.2"


def test_an_upgraded_protocol_is_a_change_but_not_a_downgrade():
    comparison = _pair([PAYMENTS, {**PARTNER, "tls_version": "1.3"}])
    change = [item for item in comparison["changes"]
              if item["kind"] == "TLS_VERSION_CHANGED"][0]
    assert change["direction"] == "UPGRADE" and change["severity"] == "INFO"
    assert comparison["downgrades"] == 0


def test_a_smaller_bulk_cipher_is_a_downgrade_even_on_the_same_version():
    comparison = _pair([{**PAYMENTS, "cipher_suite": "TLS_AES_128_GCM_SHA256"}, PARTNER])
    change = [item for item in comparison["changes"]
              if item["kind"] == "CIPHER_SUITE_CHANGED"][0]
    assert change["direction"] == "DOWNGRADE" and change["severity"] == "HIGH"
    assert "smaller key" in change["detail"]


def test_a_stronger_suite_is_not_a_downgrade():
    comparison = _pair([PAYMENTS, {**PARTNER,
                                   "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256"}])
    change = [item for item in comparison["changes"]
              if item["kind"] == "CIPHER_SUITE_CHANGED"][0]
    assert change["direction"] == "DOWNGRADE"  # 256 → 128 is smaller
    stronger = _pair([{**PAYMENTS, "cipher_suite": "TLS_CHACHA20_POLY1305_SHA256"}, PARTNER])
    change = [item for item in stronger["changes"]
              if item["kind"] == "CIPHER_SUITE_CHANGED"][0]
    assert change["direction"] == "CHANGE" and change["severity"] == "LOW"


def test_a_suite_moving_into_a_weak_class_is_a_downgrade():
    comparison = _pair([{**PAYMENTS,
                         "cipher_suite": "ECDHE-RSA-AES128-SHA"}, PARTNER])
    change = [item for item in comparison["changes"]
              if item["kind"] == "CIPHER_SUITE_CHANGED"][0]
    assert change["direction"] == "DOWNGRADE"
    assert "SHA1" in change["detail"]


def test_the_hash_in_a_suite_name_is_not_a_key_size():
    assert nh._suite_strength("ECDHE-RSA-AES128-GCM-SHA256")["key_bits"] == 128
    assert nh._suite_strength("TLS_AES_256_GCM_SHA384")["key_bits"] == 256
    assert nh._suite_strength("TLS_CHACHA20_POLY1305_SHA256")["key_bits"] == 256


def test_a_replaced_certificate_and_a_new_issuer_are_both_reported():
    comparison = _pair([{**PAYMENTS,
                         "certificate": {**PAYMENTS["certificate"],
                                         "fingerprint_sha256": "cc33",
                                         "issuer": "BANK-ICA-02"}}, PARTNER])
    kinds = _kinds(comparison)
    assert {"CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED"} <= kinds


def test_an_endpoint_that_disappeared_is_a_change_not_a_conclusion():
    comparison = _pair([PAYMENTS])
    change = [item for item in comparison["changes"]
              if item["kind"] == "ENDPOINT_REMOVED"][0]
    assert "decommissioned, or it stopped answering" in change["detail"]
    assert change["evidence_after"] == []


def test_a_new_listener_is_reported_as_a_change_needing_an_owner():
    comparison = _pair([PAYMENTS, PARTNER,
                        {"host": "new.bank.example", "port": 8443,
                         "tls_version": "1.3", "evidence_id": "NET-5"}])
    change = [item for item in comparison["changes"]
              if item["kind"] == "ENDPOINT_ADDED"][0]
    assert change["severity"] == "INFO"
    assert "needs an owner" in change["detail"]


def test_a_port_move_is_one_endpoint_moving_not_a_disappearance_and_an_arrival():
    comparison = _pair([{**PAYMENTS, "port": 8443, "alpn": "http/1.1"}, PARTNER])
    kinds = _kinds(comparison)
    assert {"PORT_CHANGED", "ALPN_CHANGED"} <= kinds
    assert "ENDPOINT_REMOVED" not in kinds and "ENDPOINT_ADDED" not in kinds
    moved = [item for item in comparison["changes"] if item["kind"] == "PORT_CHANGED"][0]
    assert moved["before"] == 443 and moved["after"] == 8443


def test_a_changed_sni_is_low_severity_but_not_ignored():
    comparison = _pair([{**PAYMENTS, "sni": "other.bank.example"}, PARTNER])
    change = [item for item in comparison["changes"] if item["kind"] == "SNI_CHANGED"][0]
    assert change["severity"] == "LOW"


def test_every_change_carries_the_evidence_from_both_sides():
    comparison = _pair([{**PAYMENTS, "tls_version": "1.2", "evidence_id": "NET-9"},
                        PARTNER])
    change = [item for item in comparison["changes"]
              if item["kind"] == "TLS_VERSION_CHANGED"][0]
    assert change["evidence_before"] == ["NET-1"]
    assert change["evidence_after"] == ["NET-9"]


def test_a_snapshot_of_the_wrong_schema_is_refused():
    with pytest.raises(ValueError, match="not a cryptoscan.nbom-history"):
        nh.compare({"schema": "something-else"}, _snap([PAYMENTS]))


# --------------------------------------------------------------------------- #
# the regression


def test_the_review_example_is_one_high_finding_with_both_signals():
    comparison = _pair([{**PAYMENTS, "tls_version": "1.2",
                         "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
                         "evidence_id": "NET-9"}, PARTNER])
    regressed = nh.regression(comparison)
    assert len(regressed["findings"]) == 1
    finding = regressed["findings"][0]
    assert finding["finding"] == "NETWORK_CRYPTO_REGRESSION"
    assert finding["severity"] == "HIGH"
    assert finding["signals"] == ["TLS_VERSION_CHANGED", "CIPHER_SUITE_CHANGED"]
    assert finding["evidence_before"] == ["NET-1"]
    assert finding["evidence_after"] == ["NET-9"]
    assert finding["observed_at"] == "2026-11-02T00:00:00Z"


def test_a_regression_names_what_is_not_proven_and_never_calls_it_an_attack():
    finding = nh.regression(_pair([{**PAYMENTS, "tls_version": "1.2"}, PARTNER])
                            )["findings"][0]
    assert "that the endpoint is compromised" in finding["not_proven"]
    assert "not a conclusion" in finding["statement"]
    lowered = finding["statement"].lower()
    assert "attack detected" not in lowered
    assert "compromise confirmed" not in lowered


def test_an_upgrade_alone_produces_no_regression():
    comparison = _pair([PAYMENTS, {**PARTNER, "tls_version": "1.3"}])
    regressed = nh.regression(comparison)
    assert regressed["findings"] == []
    assert "0 NETWORK_CRYPTO_REGRESSION" in regressed["statement"]


def test_a_new_endpoint_alone_produces_no_regression():
    comparison = _pair([PAYMENTS, PARTNER,
                        {"host": "new.bank.example", "port": 8443,
                         "tls_version": "1.3"}])
    assert nh.regression(comparison)["findings"] == []


def test_affected_systems_travel_when_a_mapping_is_supplied(self=None):
    comparison = nh.compare(
        _snap([PAYMENTS]), _snap([{**PAYMENTS, "tls_version": "1.2"}],
                                 taken_at="2026-11-02T00:00:00Z"),
        systems={"payments.bank.example:443": ["Payments API", "Payments System"]})
    finding = nh.regression(comparison)["findings"][0]
    assert finding["affected_systems"] == ["Payments API", "Payments System"]


def test_a_certificate_rotation_is_a_regression_finding_of_medium_severity():
    comparison = _pair([{**PAYMENTS,
                         "certificate": {**PAYMENTS["certificate"],
                                         "fingerprint_sha256": "cc33"}}, PARTNER])
    finding = nh.regression(comparison)["findings"][0]
    assert finding["signals"] == ["CERTIFICATE_CHANGED"]
    assert finding["severity"] == "MEDIUM"
    assert "confirm the rotation" in finding["next_action"]


# --------------------------------------------------------------------------- #
# history


def test_a_timeline_compares_each_consecutive_pair():
    first = _snap([PAYMENTS], "2026-11-01T00:00:00Z")
    second = _snap([{**PAYMENTS, "tls_version": "1.2"}], "2026-11-02T00:00:00Z")
    third = _snap([{**PAYMENTS, "tls_version": "1.2"}], "2026-11-03T00:00:00Z")
    body = nh.timeline([first, second, third])
    assert body["snapshots"] == 3 and len(body["periods"]) == 2
    assert body["periods"][0]["identical"] is False
    assert body["periods"][1]["identical"] is True
    assert body["regressions"] == 1
    assert body["worst"] == "HIGH"


def test_a_timeline_of_one_snapshot_has_no_periods():
    body = nh.timeline([_snap([PAYMENTS])])
    assert body["periods"] == []
    assert "no regression" in body["statement"]


def test_the_summary_says_whether_anything_moved_the_wrong_way():
    comparison = _pair([{**PAYMENTS, "tls_version": "1.2"}, PARTNER])
    summary = nh.summary(comparison)
    assert summary["identical"] is False
    assert summary["regressions"] == 1 and summary["worst"] == "HIGH"
    assert "NETWORK_CRYPTO_REGRESSION" in summary["statement"]
