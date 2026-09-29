"""Operator-side N3/N9 GTP-U and IPsec posture checks."""

from __future__ import annotations

from telecom_scanner.classify import classify_target
from telecom_scanner.registry import normalize_target
from telecom_scanner.user_plane import assess_user_plane


def _target(interface="N3"):
    return normalize_target({
        "nf_id": f"upf-{interface.lower()}",
        "nf_type": "upf",
        "endpoint": "upf.example:2152",
        "interface": interface,
    })


def _codes(result):
    return {finding["code"] for finding in result["findings"]}


def test_n3_without_operator_evidence_is_unknown_not_pass():
    verdict = assess_user_plane(_target("N3"), None)
    assert verdict["status"] == "USER_PLANE_UNKNOWN"
    assert verdict["protected"] is None
    assert "user_plane.ingest_required" in _codes(verdict)


def test_n9_cleartext_gtp_u_is_critical():
    verdict = assess_user_plane(_target("N9"), {
        "status": "OBSERVED", "protocol": "GTP-U", "port": 2152,
        "ipsec": {"enabled": False},
    })
    assert verdict["status"] == "USER_PLANE_OBSERVED"
    assert verdict["protected"] is False
    assert "user_plane.gtp_u_cleartext" in _codes(verdict)
    assert verdict["severity"] == "critical"


def test_protected_flag_without_parameters_is_unknown_not_clean():
    verdict = assess_user_plane(_target("N3"), {
        "status": "OBSERVED", "protocol": "GTP-U", "port": 2152,
        "ipsec": {"enabled": True},
    })
    assert verdict["status"] == "USER_PLANE_UNKNOWN"
    assert verdict["protected"] is True
    assert "user_plane.protection_evidence_incomplete" in _codes(verdict)
    assert "user_plane.ipsec_present" not in _codes(verdict)


def test_n3_ipsec_aead_ikev2_and_strong_dh_is_clean():
    verdict = assess_user_plane(_target("N3"), {
        "status": "OBSERVED", "protocol": "GTP-U", "port": 2152,
        "ipsec": {
            "enabled": True, "ike_version": "IKEv2", "encryption": "AES-GCM-256",
            "integrity": "SHA-256", "dh_groups": [19],
        },
    })
    assert verdict["protected"] is True
    assert verdict["severity"] == "info"
    assert "user_plane.ipsec_present" in _codes(verdict)
    assert not {"user_plane.ipsec_encryption_weak", "user_plane.ipsec_dh_weak"} & _codes(verdict)


def test_n9_weak_ipsec_and_wrong_gtp_port_are_findings():
    verdict = assess_user_plane(_target("N9"), {
        "status": "OBSERVED", "protocol": "GTP-U", "port": 2123,
        "ipsec": {
            "enabled": True, "ike_version": "IKEv1", "encryption": "3DES",
            "integrity": "SHA1", "dh_groups": [2],
        },
    })
    codes = _codes(verdict)
    assert {"user_plane.port_unexpected", "user_plane.ike_version_weak",
            "user_plane.ipsec_encryption_weak", "user_plane.ipsec_integrity_weak",
            "user_plane.ipsec_dh_weak"} <= codes
    assert verdict["severity"] == "critical"


def test_telecom_classifier_uses_user_plane_path_and_never_tls_probe():
    target = _target("N3")
    row = classify_target(target, {
        "status": "OBSERVED", "protocol": "GTP-U", "port": 2152,
        "ipsec": {"enabled": False},
    })
    assert row["status"] == "USER_PLANE_OBSERVED"
    assert row["user_plane"]["interface"] == "N3"
    assert "user_plane.gtp_u_cleartext" in {f["code"] for f in row["findings"]}
