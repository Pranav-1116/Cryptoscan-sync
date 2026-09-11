"""Telecom scanner engines — registry, classification, realtime, rollup.

The classification rules carry the policy (3GPP TS 33.210/33.501, NIST
SP 800-52r2, IR 8547); these tests pin them so a probe-format change can
never silently flip a verdict's severity. Honesty rules are first-class:
unknown ≠ pass, unknown ≠ fail.
"""
from __future__ import annotations

import pytest

from telecom_scanner.classify import classify_target
from telecom_scanner.realtime import evaluate_changes, summarize_events
from telecom_scanner.registry import (
    NF_CATALOG,
    normalize_carrier,
    normalize_target,
    validate_plmn,
)
from telecom_scanner.rollup import posture_rollup

_CARRIER = normalize_carrier({"code": "de-telekom", "name": "Deutsche Telekom",
                              "country": "DE", "plmn": "262-01",
                              "legal_entity": "dt-group"})


def _target(nf_id="amf-prod-01", nf_type="amf", endpoint="sba.example:443",
            carrier="de-telekom", environment="production"):
    return normalize_target({"nf_id": nf_id, "nf_type": nf_type, "endpoint": endpoint,
                             "carrier_code": carrier, "environment": environment})


def _probe(**overrides):
    probe = {
        "status": "OK",
        "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
                   "key_exchange": "X25519"},
        "certificates": [{"expiry_status": "VALID", "days_until_expiry": 200,
                          "is_self_signed": False, "key_size": 3072, "key_type": "rsa",
                          "signature_algorithm": "sha256WithRSAEncryption",
                          "not_after": "2027-03-01T00:00:00+00:00"}],
        "chain_validation": {"is_valid": True, "errors": []},
    }
    probe.update(overrides)
    return probe


# ---------------------------------------------------------------- registry

def test_plmn_shapes():
    assert validate_plmn("262-01") == {"mcc": "262", "mnc": "01"}
    assert validate_plmn("405:874") == {"mcc": "405", "mnc": "874"}
    assert validate_plmn("405874") == {"mcc": "405", "mnc": "874"}
    for bad in ("", "26-1", "262-1", "abc-de", "2621234"):
        with pytest.raises(ValueError):
            validate_plmn(bad)


def test_carrier_and_target_normalization():
    carrier = normalize_carrier({"code": "Airtel-IN ", "name": "Bharti Airtel",
                                 "country": "in", "plmn": "405874",
                                 "legal_entity": "bharti-group"})
    assert carrier["code"] == "airtel-in" and carrier["plmn"] == "405-874"
    with pytest.raises(ValueError):
        normalize_carrier({"code": "x", "name": "Too short code", "country": "de", "plmn": "262-01"})
    with pytest.raises(ValueError):
        normalize_carrier({"code": "ok-code", "name": "Ok Carrier", "country": "DEU", "plmn": "262-01"})
    target = normalize_target({"nf_id": "SEPP-Prod.01", "nf_type": "sepp",
                               "endpoint": "host.example:443", "carrier_code": "de-telekom"})
    assert target["nf_id"] == "sepp-prod.01" and target["endpoint"] == "host.example:443"
    for bad in ({"nf_id": "a", "nf_type": "amf", "endpoint": "h:443"},
                {"nf_id": "ok-id", "nf_type": "webserver", "endpoint": "h:443"},
                {"nf_id": "ok-id", "nf_type": "amf", "endpoint": "no-port"},
                {"nf_id": "ok-id", "nf_type": "amf", "endpoint": "bad host:99999"},
                {"nf_id": "ok-id", "nf_type": "amf", "endpoint": "h:443", "environment": "chaos"}):
        with pytest.raises(ValueError):
            normalize_target(bad)


def test_nf_catalog_covers_international_5g_epc_ims_transport():
    for nf in ("amf", "smf", "upf", "ausf", "udm", "nrf", "sepp",
               "mme", "hss", "pcscf", "ipsecgw", "sbc", "siggw", "gnbcu"):
        assert nf in NF_CATALOG, nf
    assert NF_CATALOG["ipsecgw"]["transport"] == "ipsec"
    assert all(spec["transport"] in ("tls", "ipsec") for spec in NF_CATALOG.values())


# ---------------------------------------------------------------- classify

def test_healthy_sba_nf_is_tls_ok_with_pqc_detection():
    probe = _probe()
    probe["crypto"]["key_exchange"] = "X25519MLKEM768"
    verdict = classify_target(_target(), probe)
    assert verdict["status"] == "TLS_OK"
    codes = {f["code"] for f in verdict["findings"]}
    assert "tls.no_tls13" not in codes
    assert "pqc.hybrid_kem" in codes
    assert verdict["pqc_kex"] == ["x25519mlkem768"]
    assert verdict["score"] == 100 and verdict["severity"] in ("info", "ok")


def test_obsolete_tls_and_weak_cipher_are_critical():
    probe = _probe(crypto={"tls_version": "TLSv1", "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"})
    verdict = classify_target(_target(), probe)
    codes = {f["code"]: f for f in verdict["findings"]}
    assert codes["tls.version_obsolete"]["severity"] == "critical"
    assert "33.210" in codes["tls.version_obsolete"]["ref"]
    assert codes["cipher.weak"]["severity"] == "critical"
    assert verdict["severity"] == "critical" and verdict["score"] <= 20


def test_certificate_rules():
    base = _probe()
    base["certificates"][0].update({"expiry_status": "EXPIRED", "days_until_expiry": -3,
                                    "signature_algorithm": "sha1WithRSAEncryption",
                                    "is_self_signed": True, "key_size": 1024})
    verdict = classify_target(_target(), base)
    by_code = {f["code"]: f["severity"] for f in verdict["findings"]}
    assert by_code["cert.expired"] == "critical"
    assert by_code["cert.sig_weak"] == "critical"
    assert by_code["cert.self_signed"] == "high"
    assert by_code["cert.key_weak"] == "critical"

    soon = _probe()
    soon["certificates"][0].update({"expiry_status": "EXPIRING_SOON", "days_until_expiry": 21})
    assert {f["code"]: f["severity"] for f in classify_target(_target(), soon)["findings"]}["cert.expiring"] == "medium"
    crit = _probe()
    crit["certificates"][0].update({"expiry_status": "EXPIRING_CRITICAL", "days_until_expiry": 5})
    assert {f["code"]: f["severity"] for f in classify_target(_target(), crit)["findings"]}["cert.expiring"] == "high"


def test_unreachable_is_critical_for_mission_planes_and_high_elsewhere():
    down = classify_target(_target(nf_type="amf"), {"status": "TIMEOUT"})
    assert down["severity"] == "critical" and down["status"] == "UNREACHABLE"
    edge = classify_target(_target(nf_type="gnbcu", carrier="de-telekom"), {"status": "PORT_CLOSED"})
    assert edge["severity"] == "high"


def test_tls_refused_means_no_tls_on_tls_bearing_nf():
    verdict = classify_target(_target(nf_type="siggw"), {"status": "TLS_ERROR"})
    assert verdict["status"] == "NO_TLS"
    assert {f["code"] for f in verdict["findings"]} >= {"tls.refused"}


def test_sepp_unprotected_is_named_as_roaming_exposure():
    verdict = classify_target(_target(nf_type="sepp"), {"status": "TLS_ERROR"})
    sepp = [f for f in verdict["findings"] if f["code"] == "sepp.roaming_unprotected"]
    assert sepp and sepp[0]["severity"] == "critical" and "33.501" in sepp[0]["ref"]


def test_ipsec_gateway_is_honestly_unknown_without_ingest():
    verdict = classify_target(_target(nf_type="ipsecgw", endpoint="za.example:500"), None)
    assert verdict["status"] == "IPSEC_UNKNOWN"
    codes = {f["code"] for f in verdict["findings"]}
    assert "ipsec.ingest_required" in codes
    assert verdict["score"] == 100  # absence of evidence is not scored as failure

    ike = classify_target(_target(nf_type="ipsecgw", endpoint="za.example:500"),
                          {"ike": {"ike_version": "IKEv1", "dh_groups": ["2", "14"], "encryption": "3DES"}})
    by_code = {f["code"] for f in ike["findings"]}
    assert {"ipsec.ikev1", "ipsec.dh_weak", "ipsec.enc_weak"} <= by_code
    assert ike["severity"] == "critical"
    ok = classify_target(_target(nf_type="ipsecgw", endpoint="za.example:500"),
                         {"ike": {"ike_version": "IKEv2", "dh_groups": ["14", "19"], "encryption": "AESGCM"}})
    assert ok["severity"] == "info"


def test_fingerprint_is_stable_shape_for_realtime_diffs():
    v = classify_target(_target(), _probe())
    status, codes, not_after = str(v["fingerprint"]).split("|")
    assert status == "TLS_OK" and not_after.startswith("2027-03-01")


# ---------------------------------------------------------------- realtime

def test_first_pass_is_quiet_unless_already_critical():
    ok = classify_target(_target(), _probe())
    assert evaluate_changes(None, [ok]) == []
    bad = classify_target(_target(), {"status": "TLS_ERROR"})
    events = evaluate_changes(None, [bad])
    assert [e["kind"] for e in events] == ["TELECOM_FINDING"]
    assert events[0]["severity"] == "critical"


def test_lost_and_recovered_and_findings_changed():
    ok = classify_target(_target(), _probe())
    down = classify_target(_target(), {"status": "TIMEOUT"})
    lost = evaluate_changes({"amf-prod-01": ok}, [down])
    assert [(e["kind"], e["severity"]) for e in lost] == [("TELECOM_REACHABILITY_LOST", "critical")]

    recovered = evaluate_changes({"amf-prod-01": down}, [ok])
    kinds = [e["kind"] for e in recovered]
    assert "TELECOM_RECOVERED" in kinds

    weak = _probe()
    weak["crypto"]["tls_version"] = "TLSv1.1"
    weak_verdict = classify_target(_target(), weak)
    changed = evaluate_changes({"amf-prod-01": ok}, [weak_verdict])
    event = [e for e in changed if e["kind"] == "TELECOM_FINDINGS_CHANGED"][0]
    assert "tls.version_obsolete" in event["gained"]
    assert event["severity"] == "critical"


def test_cert_expiring_transition_fires_once():
    soon = _probe()
    soon["certificates"][0].update({"expiry_status": "EXPIRING_SOON", "days_until_expiry": 25,
                                    "not_after": "2026-10-01T00:00:00+00:00"})
    v = classify_target(_target(), soon)
    valid = classify_target(_target(), _probe())
    fired = evaluate_changes({"amf-prod-01": valid}, [v])
    kinds = [(e["kind"], e["severity"]) for e in fired]
    assert ("TELECOM_CERT_EXPIRING", "medium") in kinds
    again = evaluate_changes({"amf-prod-01": v}, [classify_target(_target(), soon)])
    assert "TELECOM_CERT_EXPIRING" not in [e["kind"] for e in again]


def test_summarize_events_counts_by_kind():
    counts = summarize_events([{"kind": "TELECOM_FINDING"}, {"kind": "TELECOM_FINDING"},
                               {"kind": "TELECOM_RECOVERED"}])
    assert counts == {"TELECOM_FINDING": 2, "TELECOM_RECOVERED": 1}


# ---------------------------------------------------------------- rollup

def _carriers():
    fr = normalize_carrier({"code": "fr-orange", "name": "Orange", "country": "FR",
                            "plmn": "208-01", "legal_entity": "dt-group"})
    return {"de-telekom": _CARRIER, "fr-orange": fr}


def test_rollup_totals_carriers_countries():
    ok = classify_target(_target(), _probe())
    down = classify_target(_target(nf_id="amf-prod-02"), {"status": "TIMEOUT"})
    sepp = classify_target(_target(nf_id="sepp-01", nf_type="sepp"), {"status": "TLS_ERROR"})
    roll = posture_rollup([ok, down, sepp], _carriers())
    assert roll["totals"]["targets"] == 3
    assert roll["totals"]["critical"] == 2
    assert roll["totals"]["unreachable"] == 1
    assert roll["by_carrier"]["de-telekom"]["plmn"] == "262-01"
    assert roll["by_country"]["de"]["targets"] == 3
    assert roll["roaming_edges"]["unprotected"] == 1
    assert roll["international"]["dt-group"]["critical"] == 2
    assert roll["worst_targets"][0]["severity"] == "critical"


def test_rollup_empty_is_honest():
    roll = posture_rollup([], _carriers())
    assert roll["totals"]["targets"] == 0 and roll["totals"]["avg_score"] == 0
    assert roll["roaming_edges"] == {"sepp_targets": 0, "protected": 0, "unprotected": 0}
    assert roll["international"] == {} and roll["worst_targets"] == []
