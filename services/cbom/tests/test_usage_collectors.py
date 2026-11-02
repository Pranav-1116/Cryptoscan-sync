"""Collectors: what the platform already stores, turned into CBOM evidence."""

from __future__ import annotations

from cbom import usage_collectors as uc

PROBE = {
    "endpoint": "payments.bank.example:443", "status": "OK",
    "crypto": {"tls_version": "TLS1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
    "observed_on": "External LB", "scan_run_id": "run-7",
    "certificates": [{
        "subject": "payments.bank.example", "issuer": "Bank Internal CA",
        "serial_number": "cert-9281", "public_key_algorithm": "ECDSA",
        "public_key_size": 256, "signature_algorithm": "ECDSA-SHA256",
        "not_after": "2027-01-01T00:00:00Z",
    }],
}


# --------------------------------------------------------------------------- #
# cipher suites


def test_a_tls13_suite_names_its_bulk_algorithm_and_hash():
    facts = uc.algorithms_from_cipher_suite("TLS_AES_256_GCM_SHA384")
    roles = {fact["algorithm"]: fact["role"] for fact in facts}
    assert roles == {"AES-256-GCM": "BULK", "SHA-384": "HASH"}
    assert next(f for f in facts if f["algorithm"] == "AES-256-GCM")["parameters"] == {
        "key_size": 256, "mode": "GCM"}


def test_a_tls12_suite_adds_signature_and_key_exchange():
    facts = uc.algorithms_from_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    roles = {fact["algorithm"]: fact["role"] for fact in facts}
    assert roles == {"AES-128-GCM": "BULK", "ECDHE": "KEY_EXCHANGE", "RSA": "SIGNATURE",
                     "SHA-256": "HASH"}


def test_an_unknown_suite_invents_nothing():
    assert uc.algorithms_from_cipher_suite("TLS_FUTURE_MAGIC_999") == []
    assert uc.algorithms_from_cipher_suite("") == []


def test_the_longest_token_wins():
    facts = uc.algorithms_from_cipher_suite("TLS_CHACHA20_POLY1305_SHA256")
    assert [fact["algorithm"] for fact in facts] == ["CHACHA20-POLY1305", "SHA-256"]


# --------------------------------------------------------------------------- #
# network probes


def test_a_completed_handshake_becomes_network_evidence():
    body = uc.network_events_from_probes([PROBE], scan_run_id="run-7")
    assert body["statement"].startswith("2 algorithm fact(s) from 1 completed handshake(s)")
    assert {event["class"] for event in body["events"]} == {"NETWORK_OBSERVED"}
    assert {event["evidence_id"] for event in body["events"]} == {"net:run-7:payments.bank.example:443"}
    assert {event["purpose"] for event in body["events"]} == {"TLS"}


def test_an_unprobed_endpoint_observes_nothing():
    body = uc.network_events_from_probes([{**PROBE, "status": "TIMEOUT"}])
    assert body["events"] == [] and body["refused"]
    assert "no handshake completed" in body["refused"][0]["reason"]


def test_a_handshake_with_no_suite_is_not_algorithm_evidence():
    probe = {**PROBE, "crypto": {"tls_version": "TLS1.3"}}
    body = uc.network_events_from_probes([probe])
    assert body["events"] == []
    assert "no negotiated suite" in body["refused"][0]["reason"]


def test_network_evidence_without_a_scan_run_or_id_is_refused():
    probe = {k: v for k, v in PROBE.items() if k != "scan_run_id"}
    body = uc.network_events_from_probes([probe])
    assert body["events"] == [] and body["refused"]


def test_a_probe_yields_a_certificate_and_a_hop():
    body = uc.network_events_from_probes([PROBE], scan_run_id="run-7")
    certificate = body["certificates"][0]
    assert certificate["certificate"]["category"] == "CERTIFICATE"
    assert certificate["application_operation_proven"] is False
    hop = body["hops"][0]
    assert hop["endpoint"] == "payments.bank.example:443"
    assert hop["tls_version"] == "TLS1.3" and hop["evidence_id"]


# --------------------------------------------------------------------------- #
# static findings


def test_a_finding_with_its_evidence_row_is_a_static_observation():
    body = uc.static_events_from_assets([{
        "algorithm": "AES", "key_size": 256, "mode": "GCM", "purpose": "ENCRYPTION",
        "file_path": "src/signing.py", "line_number": 42, "evidence_ids": ["EVID-001"]}])
    assert len(body["events"]) == 1
    event = body["events"][0]
    assert (event["class"], event["evidence_id"]) == ("STATIC_OBSERVED", "EVID-001")
    assert event["parameters"] == {"key_size": 256, "mode": "GCM"}
    assert event["location"] == "src/signing.py:42"


def test_a_finding_without_an_evidence_row_is_refused():
    body = uc.static_events_from_assets([{"algorithm": "RSA", "file_path": "a.py"}])
    assert body["events"] == []
    assert "no evidence row" in body["refused"][0]["reason"]


def test_a_finding_with_no_algorithm_is_refused():
    body = uc.static_events_from_assets([{"evidence_ids": ["E-1"]}])
    assert body["refused"]


# --------------------------------------------------------------------------- #
# runtime operations


def _operation(**overrides):
    row = {"operation": "EVP_EncryptInit_ex", "algorithm": "AES-256-GCM",
           "key_size": 256, "mode": "GCM", "evidence_id": "RUNTIME-92821",
           "observed_at": "2026-11-02T10:42:11Z", "process": "payments-api[9182]",
           "purpose": "TLS"}
    row.update(overrides)
    return row


def test_a_recorded_operation_is_runtime_evidence():
    body = uc.runtime_events_from_operations([_operation()])
    event = body["events"][0]
    assert (event["class"], event["evidence_id"]) == ("RUNTIME_OBSERVED", "RUNTIME-92821")
    assert event["parameters"] == {"key_size": 256, "mode": "GCM"}
    assert event["location"] == "payments-api[9182]"


def test_an_operation_without_an_evidence_id_is_a_claim():
    body = uc.runtime_events_from_operations([_operation(evidence_id=None)])
    assert body["events"] == []
    assert "evidence_id" in body["refused"][0]["reason"]


def test_an_operation_without_a_timestamp_is_a_claim():
    body = uc.runtime_events_from_operations([_operation(observed_at=None)])
    assert body["refused"] and "observed_at" in body["refused"][0]["reason"]


def test_a_process_with_no_operation_is_not_runtime_evidence():
    body = uc.runtime_events_from_operations([{"process": "payments-api",
                                               "evidence_id": "E-1",
                                               "observed_at": "2026-11-02"}])
    assert body["refused"] and "operation" in body["refused"][0]["reason"]


# --------------------------------------------------------------------------- #
# profiles from collected events


def test_network_alone_is_high_and_says_which_layers_are_missing():
    body = uc.network_events_from_probes([PROBE], scan_run_id="run-7")
    report = uc.profiles(body["events"])
    by_name = {row["asset"]["algorithm"]: row for row in report["profiles"]}
    assert by_name["AES-256-GCM"]["confidence"] == "HIGH"
    assert by_name["AES-256-GCM"]["usage"] == "OBSERVED"
    assert by_name["AES-256-GCM"]["roles"] == ["BULK"]
    assert by_name["AES-256-GCM"]["locations"] == ["payments.bank.example:443"]
    assert set(report["unobserved_layers"]) == {"static", "config", "runtime"}
    assert "absent collector" in report["statement"]


def test_static_and_runtime_lift_confidence_above_one_collector():
    report = uc.profiles([
        {"class": "STATIC_OBSERVED", "evidence_id": "S-1", "algorithm": "AES-256-GCM"},
        {"class": "RUNTIME_OBSERVED", "evidence_id": "R-1", "algorithm": "AES-256-GCM"},
    ])
    profile = report["profiles"][0]
    assert profile["confidence"] == "HIGH"
    assert profile["usage"] == "OBSERVED"
    assert profile["layers"]["static"]["observed"] is True
    assert profile["evidence_ids"] == ["R-1", "S-1"]


def test_all_three_observers_reach_very_high():
    report = uc.profiles([
        {"class": "STATIC_OBSERVED", "evidence_id": "S-1", "algorithm": "AES-256-GCM"},
        {"class": "RUNTIME_OBSERVED", "evidence_id": "R-1", "algorithm": "AES-256-GCM"},
        {"class": "NETWORK_OBSERVED", "evidence_id": "N-1", "algorithm": "AES-256-GCM"},
    ])
    assert report["profiles"][0]["confidence"] == "VERY_HIGH"
    assert report["unobserved_layers"] == ["config"]


def test_imported_only_stays_a_candidate_in_the_collected_profile():
    report = uc.profiles([{"class": "IMPORTED", "evidence_id": "SBOM-1",
                           "algorithm": "AES-256"}])
    profile = report["profiles"][0]
    assert profile["usage"] == "CANDIDATE_ONLY" and profile["confidence"] == "LOW"


def test_an_end_to_end_collection_keeps_every_source_apart():
    network = uc.network_events_from_probes([PROBE], scan_run_id="run-7")["events"]
    static = uc.static_events_from_assets([{
        "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
        "file_path": "src/tls.py", "line_number": 12, "evidence_ids": ["EVID-001"]}])["events"]
    runtime = uc.runtime_events_from_operations([_operation()])["events"]
    report = uc.profiles(network + static + runtime)
    profile = next(row for row in report["profiles"]
                   if row["asset"]["algorithm"] == "AES-256-GCM")
    evidence = set(profile["evidence_ids"])
    assert "net:run-7:payments.bank.example:443" in evidence
    assert {"EVID-001", "RUNTIME-92821"} <= evidence
    assert profile["confidence"] == "VERY_HIGH"


def test_an_openssl_suite_name_keeps_its_bulk_cipher():
    """``ECDHE-RSA-AES128-GCM-SHA256`` is the commonest TLS 1.2 suite on a load
    balancer, and tokenises to ``AES128_GCM`` — which no underscore term covered,
    so the network layer used to report the signature, the key exchange and the
    hash while silently losing the cipher that actually protects the data."""
    facts = {fact["algorithm"]: fact for fact
             in uc.algorithms_from_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")}
    assert facts["AES-128-GCM"]["parameters"] == {"key_size": 128, "mode": "GCM"}
    assert facts["AES-128-GCM"]["role"] == "BULK"
    assert set(facts) == {"AES-128-GCM", "SHA-256", "ECDHE", "RSA"}


def test_the_two_iana_forms_agree():
    for suite, algorithm in (("TLS_AES_256_GCM_SHA384", "AES-256-GCM"),
                             ("AES256-GCM-SHA384", "AES-256-GCM"),
                             ("TLS_AES_128_GCM_SHA256", "AES-128-GCM")):
        assert algorithm in {fact["algorithm"]
                             for fact in uc.algorithms_from_cipher_suite(suite)}
