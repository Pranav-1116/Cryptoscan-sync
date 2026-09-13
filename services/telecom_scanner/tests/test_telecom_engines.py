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


# ---------------------------------------------------------------- roadmap

from telecom_scanner.roadmap import (
    carrier_entity_families,
    carrier_families,
    telecom_roadmap,
)
from telecom_scanner.roaming import normalize_partner, roaming_matrix


def _probe_with(key_type, key_bits, sig, cipher):
    return {
        "status": "OK",
        "crypto": {"tls_version": "TLSv1.2", "cipher_suite": cipher},
        "certificates": [{"expiry_status": "VALID", "days_until_expiry": 100,
                          "is_self_signed": False, "key_size": key_bits,
                          "key_type": key_type, "signature_algorithm": sig,
                          "not_after": "2027-01-01T00:00:00+00:00"}],
        "chain_validation": {"is_valid": True, "errors": []},
    }


def test_carrier_families_flag_only_what_the_classification_flags():
    legacy = classify_target(_target(nf_id="nf-a"), _probe_with("rsa", 2048, "sha1WithRSAEncryption", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
    modern = classify_target(_target(nf_id="nf-b"), _probe_with("rsa", 3072, "sha256WithRSAEncryption", "TLS_AES_256_GCM_SHA384"))
    down = classify_target(_target(nf_id="nf-c"), {"status": "TIMEOUT"})
    families = carrier_families([legacy, modern, down])
    assert families["de-telekom"] == [("3DES-112", 1), ("RSA-2048", 1), ("RSA-3072", 1), ("SHA1WITHRSA-2048", 1)]
    # unprobed targets contribute nothing
    assert carrier_families([down]) == {}


def test_telecom_roadmap_buckets_per_ir_8547():
    legacy = classify_target(_target(nf_id="nf-a"), _probe_with("rsa", 2048, "sha1WithRSAEncryption", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
    modern = classify_target(_target(nf_id="nf-b"), _probe_with("rsa", 3072, "sha256WithRSAEncryption", "TLS_AES_256_GCM_SHA384"))
    roadmap = telecom_roadmap([legacy, modern], {"de-telekom": _CARRIER})
    by_family = {row["family"]: row["bucket"] for row in roadmap["rows"]}
    assert by_family == {"3DES-112": "immediate", "SHA1WITHRSA-2048": "immediate",
                         "RSA-2048": "by-2030", "RSA-3072": "by-2035"}
    assert roadmap["basis"].startswith("NIST IR 8547")
    assert roadmap["summary"]["entities_affected"] == ["de-telekom"]


def test_entity_fold_links_carriers_into_the_group_plan():
    fr = normalize_carrier({"code": "fr-orange", "name": "Orange", "country": "fr",
                            "plmn": "208-01", "legal_entity": "dt-group"})
    carriers = {"de-telekom": _CARRIER, "fr-orange": fr}
    v1 = classify_target(_target(nf_id="nf-a"), _probe_with("rsa", 2048, "sha256WithRSAEncryption", "TLS_AES_128_GCM_SHA256"))
    v2 = classify_target(_target(nf_id="nf-b", carrier="fr-orange"), _probe_with("rsa", 1024, "sha256WithRSAEncryption", "TLS_AES_128_GCM_SHA256"))
    folded = carrier_entity_families([v1, v2], carriers)
    assert folded["dt-group"] == [("RSA-1024", 1), ("RSA-2048", 1)]


# ---------------------------------------------------------------- roaming

def test_partner_normalization():
    p = normalize_partner({"carrier_code": "de-telekom", "partner_plmn": "208-01",
                           "partner_name": "Orange France", "country": "FR"})
    assert p["id"] == "de-telekom:208-01" and p["partner_plmn"] == "208-01"
    for bad in ({"carrier_code": "x", "partner_plmn": "208-01", "partner_name": "N", "country": "fr"},
                {"carrier_code": "de-telekom", "partner_plmn": "26-1", "partner_name": "Ok Name", "country": "fr"},
                {"carrier_code": "de-telekom", "partner_plmn": "208-01", "partner_name": "Ok Name", "country": "fra"}):
        with pytest.raises(ValueError):
            normalize_partner(bad)


def test_roaming_matrix_status_priority_and_honest_unknown():
    p_protected = normalize_partner({"carrier_code": "de-telekom", "partner_plmn": "208-01",
                                     "partner_name": "Orange", "country": "fr"})
    # a partner whose carrier has NO probed SEPP — must read unknown, never protected
    p_unknown = normalize_partner({"carrier_code": "fr-orange", "partner_plmn": "262-02",
                                   "partner_name": "Vodafone DE", "country": "de"})
    sepp_ok = classify_target(_target(nf_id="sepp-1", nf_type="sepp"), _probe())
    rows = roaming_matrix([p_unknown, p_protected], [sepp_ok])
    assert [(r["partner_name"], r["status"]) for r in rows["rows"]] == [
        ("Vodafone DE", "unknown"),   # no SEPP verdict for fr-orange — never fabricated
        ("Orange", "protected"),
    ]
    assert rows["summary"] == {"partners": 2, "protected": 1, "unprotected": 0, "unknown": 1}

    sepp_bad = classify_target(_target(nf_id="sepp-1", nf_type="sepp"), {"status": "TLS_ERROR"})
    rows = roaming_matrix([p_protected, p_unknown], [sepp_bad])
    assert rows["rows"][0]["status"] == "unprotected"      # worst first
    assert rows["rows"][0]["severity"] == "critical"
    assert "33.501" in rows["rows"][0]["ref"]


def test_roaming_matrix_uses_explicit_sepp_mapping_first():
    partner = normalize_partner({"carrier_code": "de-telekom", "partner_plmn": "208-01",
                                 "partner_name": "Orange", "country": "fr",
                                 "sepp_nf_id": "sepp-fr"})
    sepp_fr = classify_target(_target(nf_id="sepp-fr", nf_type="sepp"), _probe())
    sepp_generic = classify_target(_target(nf_id="sepp-9", nf_type="sepp"), {"status": "TLS_ERROR"})
    rows = roaming_matrix([partner], [sepp_fr, sepp_generic])
    # the explicit mapping wins over the carrier's first SEPP
    assert rows["rows"][0]["status"] == "protected"
    assert rows["rows"][0]["sepp_nf_id"] == "sepp-fr"


def test_roaming_matrix_pqc_ready_follows_the_sepp_verdict():
    partner = normalize_partner({"carrier_code": "de-telekom", "partner_plmn": "208-01",
                                 "partner_name": "Orange", "country": "fr",
                                 "sepp_nf_id": "sepp-fr"})
    hybrid = _probe()
    hybrid["crypto"]["key_exchange"] = "X25519MLKEM768"
    pqc_sepp = classify_target(_target(nf_id="sepp-fr", nf_type="sepp"), hybrid)
    rows = roaming_matrix([partner], [pqc_sepp])
    assert rows["rows"][0]["pqc_ready"] is True

    classic_sepp = classify_target(_target(nf_id="sepp-fr", nf_type="sepp"), _probe())
    rows = roaming_matrix([partner], [classic_sepp])
    assert rows["rows"][0]["pqc_ready"] is False

    # no SEPP verdict at all -> not pqc_ready (never inferred)
    rows = roaming_matrix([partner], [])
    assert rows["rows"][0]["pqc_ready"] is False
    assert rows["rows"][0]["status"] == "unknown"


# ---------------------------------------------------------------- automation

from telecom_scanner.automation import automation_data, automation_event_kind


def test_automation_event_mapping_policy():
    assert automation_event_kind({"kind": "TELECOM_CERT_EXPIRING"}) == "certificate_expiring"
    assert automation_event_kind({"kind": "TELECOM_REACHABILITY_LOST"}) == "agent_offline"
    assert automation_event_kind({"kind": "TELECOM_FINDINGS_CHANGED", "severity": "critical"}) == "drift_detected"
    assert automation_event_kind({"kind": "TELECOM_FINDING", "severity": "high"}) == "drift_detected"
    # noise never wakes the engine
    assert automation_event_kind({"kind": "TELECOM_RECOVERED"}) is None
    assert automation_event_kind({"kind": "TELECOM_FINDINGS_CHANGED", "severity": "info"}) is None
    assert automation_event_kind({"kind": "TELECOM_TARGET_ADDED"}) is None
    assert automation_event_kind({}) is None


def test_automation_condition_data_carries_telecom_identity():
    data = automation_data({"kind": "TELECOM_REACHABILITY_LOST", "target": "sepp-1",
                            "carrier_code": "de-telekom", "plane": "roaming",
                            "severity": "critical", "message": "down"})
    assert data["nf_id"] == "sepp-1"
    assert data["carrier_code"] == "de-telekom" and data["plane"] == "roaming"
    assert data["severity"] == "CRITICAL"
    assert "kind" not in data and None not in data.values()


def test_telecom_playbook_registered_and_reachable():
    from automation.playbooks import get_playbook, playbook_for_event

    pb = get_playbook("pb_telecom_nf_down")
    assert pb is not None and pb.trigger == "agent_offline"
    actions = [s.action for s in pb.steps]
    assert "targeted_rescan" in actions and "create_alert" in actions
    assert any(s.requires_approval for s in pb.steps)  # failover is gated
    assert playbook_for_event("agent_offline").id == "pb_telecom_nf_down"


# ---------------------------------------------------------------- pack

from telecom_scanner.pack import DECLARED_LIMITS, carrier_pack


def test_carrier_pack_scopes_to_one_carrier():
    fr = normalize_carrier({"code": "fr-orange", "name": "Orange", "country": "fr",
                            "plmn": "208-01"})
    mine = classify_target(_target(), _probe())
    theirs = classify_target(_target(nf_id="nf-fr", carrier="fr-orange"),
                             _probe_with("rsa", 2048, "sha1WithRSAEncryption",
                                         "TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
    roaming = [{"carrier_code": "de-telekom", "partner_name": "Orange", "status": "protected"},
               {"carrier_code": "fr-orange", "partner_name": "DT", "status": "unknown"}]
    pack = carrier_pack(_CARRIER, [mine, theirs], roaming_rows=roaming)
    assert pack["pack"]["kind"] == "telecom-nra-pack"
    assert pack["pack"]["carrier_code"] == "de-telekom"
    assert pack["pack"]["plmn"] == "262-01"
    assert pack["posture"]["totals"]["targets"] == 1          # only mine
    # _probe() serves RSA-3072: Shor-vulnerable per IR 8547 -> flagged (by-2035)
    assert pack["families_flagged"] == [("RSA-3072", 1)]
    assert [r["partner_name"] for r in pack["roaming_edges"]] == ["Orange"]
    assert pack["declared_limits"] == list(DECLARED_LIMITS)

    fr_pack = carrier_pack(fr, [mine, theirs], roaming_rows=roaming)
    # legacy probe: 3DES cipher + SHA1 signature + RSA-2048 leaf key
    assert fr_pack["families_flagged"] == [("3DES-112", 1), ("RSA-2048", 1), ("SHA1WITHRSA-2048", 1)]
    assert fr_pack["posture"]["totals"]["targets"] == 1


def test_carrier_pack_empty_is_honest():
    pack = carrier_pack(_CARRIER, [])
    assert pack["posture"]["totals"]["targets"] == 0
    assert pack["families_flagged"] == [] and pack["roaming_edges"] == []
    assert pack["declared_limits"]


def _state_row(verdict):
    """The exact state shape the API scan/ingest and the monitor runner mirror."""
    return {k: verdict[k] for k in ("status", "severity", "fingerprint",
                                    "cert_not_after", "pqc_ready")}


def test_pqc_readiness_transitions_stream():
    """A roaming link gaining/losing hybrid ML-KEM must be an EVENT: the
    pqc.hybrid_kem finding is info-severity (excluded from the fingerprint),
    so without the explicit transition the flip would be event-silent."""
    classical = classify_target(_target(nf_type="sepp"), _probe())
    pqc_probe = _probe()
    pqc_probe["crypto"]["key_exchange"] = "X25519MLKEM768"
    pqc_verdict = classify_target(_target(nf_type="sepp"), pqc_probe)

    # the fingerprint is IDENTICAL — this is exactly why the explicit
    # transition check exists
    assert classical["fingerprint"] == pqc_verdict["fingerprint"]
    assert classical["pqc_ready"] is False and pqc_verdict["pqc_ready"] is True

    gained = evaluate_changes({"amf-prod-01": _state_row(classical)}, [pqc_verdict])
    pqc_events = [(e["kind"], e["severity"]) for e in gained]
    assert ("TELECOM_PQC_READY", "info") in pqc_events
    ready = [e for e in gained if e["kind"] == "TELECOM_PQC_READY"][0]
    assert "roaming link" in ready["message"]  # SEPP phrasing
    assert ready["pqc_kex"] == ["x25519mlkem768"]  # scanner normalizes case

    dropped = evaluate_changes({"amf-prod-01": _state_row(pqc_verdict)}, [classical])
    dropped_events = [(e["kind"], e["severity"]) for e in dropped]
    assert ("TELECOM_PQC_DROPPED", "high") in dropped_events
    reg = [e for e in dropped if e["kind"] == "TELECOM_PQC_DROPPED"][0]
    assert "regression" in reg["message"]

    # steady state: no repeat events
    quiet = evaluate_changes({"amf-prod-01": _state_row(pqc_verdict)}, [pqc_verdict])
    assert "TELECOM_PQC_READY" not in [e["kind"] for e in quiet]


def test_pqc_transition_quiet_on_first_observation():
    """First observation is a baseline (no per-target noise) — a PQC-ready NF
    seen for the first time must not fire TELECOM_PQC_READY."""
    pqc_probe = _probe()
    pqc_probe["crypto"]["key_exchange"] = "X25519MLKEM768"
    v = classify_target(_target(), pqc_probe)
    assert evaluate_changes(None, [v]) == []


def test_pqc_regression_wakes_automation_with_existing_vocabulary():
    """TELECOM_PQC_DROPPED maps onto the EXISTING quantum-vulnerable trigger
    (pb_pqc: rescan, CBOM refresh, migration queue, ticket, gated approval) —
    no new action vocabulary. READY stays noise; data carries the telecom
    identity so rules can target plane/carrier."""
    from telecom_scanner.automation import automation_data, automation_event_kind

    dropped = {"kind": "TELECOM_PQC_DROPPED", "severity": "high",
               "target": "gw-za-01", "nf_id": "gw-za-01", "nf_type": "sepp",
               "carrier_code": "de-telekom", "plane": "roaming",
               "message": "PQC regression on gw-za-01"}
    assert automation_event_kind(dropped) == "quantum_vulnerable_detected"
    # and the rules engine + playbook machinery know this kind end-to-end
    from automation.playbooks import playbook_for_event
    from automation.rules_engine import EVENT_KINDS
    assert "quantum_vulnerable_detected" in EVENT_KINDS
    assert playbook_for_event("quantum_vulnerable_detected") is not None

    data = automation_data(dropped)
    assert data["nf_id"] == "gw-za-01" and data["plane"] == "roaming"
    assert data["severity"] == "HIGH"

    assert automation_event_kind({"kind": "TELECOM_PQC_READY", "severity": "info"}) is None
    assert automation_event_kind({"kind": "TELECOM_RECOVERED", "severity": "info"}) is None
