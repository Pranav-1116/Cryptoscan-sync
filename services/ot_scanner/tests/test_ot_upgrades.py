"""OT upgrades: GOOSE/SV, S7comm, weak OPC-UA policies, posture, telemetry, metrics, CLI."""

from __future__ import annotations

import json

from ot_scanner.core.scanner import OtPassiveScanner
from ot_scanner.main import main as cli_main
from ot_scanner.protocols import iec61850, opcua, s7comm
from ot_scanner.reports.metrics import render_prometheus
from ot_scanner.reports.posture import build_ot_posture, build_ot_telemetry


# --------------------------------------------------------------------------- #
# protocol upgrades
# --------------------------------------------------------------------------- #

def test_goose_record_flagged_not_dropped():
    result = OtPassiveScanner().scan_records(
        [{"protocol": "goose", "src_ip": "10.0.4.5", "dst_ip": "10.0.4.255"}]
    )
    assert result["device_count"] == 1
    finding = result["findings"][0]
    assert finding["protocol"] == "IEC-61850-GOOSE"
    assert finding["compliance_issue"] == "OT_UNENCRYPTED_GOOSE"
    assert finding["has_crypto"] is False


def test_sv_record_flagged():
    result = OtPassiveScanner().scan_records([{"protocol": "sv", "src_ip": "10.0.4.6"}])
    assert result["findings"][0]["protocol"] == "IEC-61850-SV"
    assert result["findings"][0]["compliance_issue"] == "OT_UNENCRYPTED_SV"


def test_s7comm_analyzer_and_detection():
    plain = s7comm.analyze({"protocol": "s7comm"})
    assert plain["protocol"] == "S7comm" and plain["compliance_issue"] == "OT_UNENCRYPTED_S7"
    over_tls = s7comm.analyze({"protocol": "s7comm", "tls": "true", "cipher": "AES128-GCM-SHA256"})
    assert over_tls["security_level"] == "ENCRYPT" and over_tls["has_crypto"] is True
    # keyword detection from a raw log line (port 102, product mentions S7)
    result = OtPassiveScanner().scan_records(
        [{"protocol": "s7comm", "src_ip": "10.0.5.7", "product": "Siemens S7-1500"}]
    )
    assert result["findings"][0]["protocol"] == "S7comm"


def test_s7_keyword_detection_from_log_line(tmp_path):
    log = tmp_path / "plc.otlog"
    log.write_text("ts=x src=10.0.5.8 dst=10.0.5.1 port=102 product=Siemens-S7-1200\n")
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert any(row["protocol"] == "S7comm" for row in result["findings"])


def test_port_4840_beats_s7_keyword(tmp_path):
    # OPC-UA on 4840 with an S7 product string stays OPC-UA, not S7comm
    log = tmp_path / "opcua.log"
    log.write_text(
        "ts=x src=10.0.2.15 port=4840 security_mode=SignAndEncrypt policy=Basic256Sha256 product=S7-1500\n"
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert result["findings"][0]["protocol"] == "OPC-UA"


def test_opcua_weak_policies_flagged():
    weak128 = opcua.analyze({"security_mode": "SignAndEncrypt", "policy": "Basic128Rsa15"})
    assert weak128["compliance_issue"] == "OT_WEAK_CRYPTO_POLICY"
    assert weak128["crypto"]["key_exchange"] == "RSA-1024"
    assert weak128["crypto"]["signing"] == "HMAC-SHA1"
    weak256 = opcua.analyze({"security_mode": "SignAndEncrypt", "policy": "Basic256"})
    assert weak256["compliance_issue"] == "OT_WEAK_CRYPTO_POLICY"
    strong = opcua.analyze({"security_mode": "SignAndEncrypt", "policy": "Basic256Sha256"})
    assert strong["compliance_issue"] is None


def test_opcua_unencrypted_beats_weak_policy():
    # mode None with a weak policy string still reports the bigger problem
    finding = opcua.analyze({"security_mode": "None", "policy": "Basic128Rsa15"})
    assert finding["compliance_issue"] == "OT_UNENCRYPTED_TRAFFIC"


# --------------------------------------------------------------------------- #
# posture + telemetry
# --------------------------------------------------------------------------- #

def _encrypted_finding(ip="10.0.0.1"):
    return {
        "protocol": "OPC-UA", "security_level": "ENCRYPT", "has_crypto": True,
        "compliance_issue": None, "vulnerabilities": [],
        "device": {"ip_address": ip, "criticality": "SAFETY_CRITICAL"},
    }


def _plain_finding(ip="10.0.0.2", criticality="SAFETY_CRITICAL"):
    return {
        "protocol": "Modbus TCP", "security_level": "NONE", "has_crypto": False,
        "compliance_issue": "OT_UNENCRYPTED_MODBUS", "vulnerabilities": [],
        "device": {"ip_address": ip, "criticality": criticality},
    }


def test_posture_fail_on_unencrypted_safety_critical():
    report = build_ot_posture(findings=[_plain_finding()], devices=[{"ip_address": "10.0.0.2"}])
    assert report["posture"] == "FAIL"
    assert "OT_UNENCRYPTED_SAFETY_CRITICAL" in report["policy_issues"]
    assert "SAFETY_CRITICAL" in report["headline"] or "unencrypted" in report["headline"]


def test_posture_fail_on_device_with_cves():
    cve_finding = {**_encrypted_finding(), "vulnerabilities": [{"cve": "CVE-2020-15782"}]}
    report = build_ot_posture(findings=[cve_finding], devices=[{"ip_address": "10.0.0.1"}])
    assert report["posture"] == "FAIL"
    assert report["devices_with_cves"] == ["10.0.0.1"]


def test_posture_warn_on_unencrypted_non_safety():
    report = build_ot_posture(
        findings=[_plain_finding(criticality="AUXILIARY")], devices=[{"ip_address": "10.0.0.2"}]
    )
    assert report["posture"] == "WARN"
    assert report["policy_issues"] == ["OT_UNENCRYPTED_TRAFFIC"]
    assert report["unencrypted_safety_critical"] == 0


def test_posture_warn_on_weak_crypto():
    weak = {
        "protocol": "OPC-UA", "security_level": "ENCRYPT", "has_crypto": True,
        "compliance_issue": "OT_WEAK_CRYPTO_POLICY", "vulnerabilities": [],
        "device": {"ip_address": "10.0.0.9", "criticality": "SAFETY_CRITICAL"},
    }
    report = build_ot_posture(findings=[weak], devices=[{"ip_address": "10.0.0.9"}])
    assert report["posture"] == "WARN"
    assert report["weak_crypto_observations"] == 1


def test_posture_pass_and_counts():
    report = build_ot_posture(
        findings=[_encrypted_finding(), {**_encrypted_finding(ip="10.0.0.3"), "protocol": "DNP3-SA"}],
        devices=[{"ip_address": "10.0.0.1"}, {"ip_address": "10.0.0.3"}],
    )
    assert report["posture"] == "PASS"
    assert report["protocol_counts"] == {"DNP3-SA": 1, "OPC-UA": 1}
    assert report["security_level_counts"] == {"ENCRYPT": 2}
    assert report["headline"] is None


def test_telemetry_verdicts():
    assert build_ot_telemetry(records=0, findings=[], devices=[])["status"] == "SKIPPED"
    # records existed but nothing protocol-matched
    assert build_ot_telemetry(records=5, findings=[], devices=[])["status"] == "FAILED"
    ok = build_ot_telemetry(records=4, findings=[_encrypted_finding()], devices=[{"ip_address": "x"}])
    assert ok["status"] == "OK" and ok["match_rate"] == 0.25 and ok["packets_sent"] == 0


def test_scan_result_carries_posture_and_telemetry(tmp_path):
    (tmp_path / "modbus.log").write_text("ts=x src=10.0.1.5 port=502 proto=modbus\n")
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert result["risk_report"]["posture"] == "FAIL"  # safety-critical + unencrypted
    assert result["risk_report"]["issue_counts"]["OT_UNENCRYPTED_MODBUS"] == 1
    assert result["ot_telemetry"]["status"] == "OK"
    assert result["ot_telemetry"]["records_analyzed"] >= 1
    assert result["ot_telemetry"]["packets_sent"] == 0


def test_emergency_stop_returns_honest_result():
    scanner = OtPassiveScanner()
    scanner.emergency_stop()
    result = scanner.scan_filesystem("/nonexistent-path")
    assert result["stopped"] is True
    assert result["devices"] == [] and result["packets_sent"] == 0


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #

def _ot_payload():
    return {
        "device_count": 2,
        "unencrypted": 1,
        "findings": [_plain_finding(), _encrypted_finding()],
        "risk_report": {
            "posture": "FAIL",
            "device_count": 2,
            "unencrypted_observations": 1,
            "weak_crypto_observations": 0,
            "devices_with_cves": [],
            "protocol_counts": {"Modbus TCP": 1, "OPC-UA": 1},
            "security_level_counts": {"ENCRYPT": 1, "NONE": 1},
            "issue_counts": {"OT_UNENCRYPTED_MODBUS": 1},
        },
        "ot_telemetry": {"status": "OK", "records_analyzed": 2},
    }


def test_ot_metrics_families():
    text = render_prometheus(_ot_payload())
    assert "cryptoscan_ot_devices 2" in text
    assert "cryptoscan_ot_unencrypted_observations 1" in text
    assert 'cryptoscan_ot_findings_by_protocol{protocol="Modbus TCP"} 1' in text
    assert 'cryptoscan_ot_findings_by_security_level{level="NONE"} 1' in text
    assert 'cryptoscan_ot_posture{posture="FAIL"} 1' in text
    assert 'cryptoscan_ot_posture{posture="PASS"} 0' in text
    assert "cryptoscan_ot_packets_sent 0" in text  # the passive guarantee, on the record
    assert 'cryptoscan_ot_scan_verdict{verdict="OK"} 1' in text
    assert "cryptoscan_ot_records_analyzed 2" in text
    assert text.endswith("\n")


def test_ot_metrics_unknown_payload():
    assert render_prometheus({"x": 1}).strip().startswith("# cryptoscan:")
    assert render_prometheus(None).startswith("# cryptoscan:")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_json_and_metrics(tmp_path, capsys):
    log = tmp_path / "plant.otlog"
    log.write_text(
        "ts=x src=10.0.2.15 port=4840 security_mode=None product=Siemens-S7-1500 version=2.8.2\n"
        "ts=x src=10.0.2.28 port=502 proto=modbus\n"
    )
    out = tmp_path / "result.json"
    assert cli_main([str(log), "-o", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert payload["device_count"] == 2
    assert payload["risk_report"]["posture"] == "FAIL"
    assert "CVE-2020-15782" in str(payload["findings"])  # passive CVE match lives on
    assert payload["ot_telemetry"]["packets_sent"] == 0

    assert cli_main([str(log), "--metrics"]) == 0
    rendered = capsys.readouterr().out
    assert "cryptoscan_ot_packets_sent 0" in rendered
    assert 'cryptoscan_ot_posture{posture="FAIL"} 1' in rendered
