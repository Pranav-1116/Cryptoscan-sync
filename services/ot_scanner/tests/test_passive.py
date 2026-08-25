import pytest

from ot_scanner.core.safety import OtSafetyError, send_packet
from ot_scanner.core.scanner import OtPassiveScanner


def test_send_packet_is_forbidden():
    with pytest.raises(OtSafetyError):
        send_packet(b"anything")
    with pytest.raises(OtSafetyError):
        OtPassiveScanner().send_packet({"dst": "10.0.0.1"})


def test_parses_opcua_and_modbus_logs(tmp_path):
    (tmp_path / "opcua.log").write_text(
        "ts=2024-01-15T10:00:00 src=10.0.2.15 dst=10.0.2.1 mac=00:1B:1B:aa:bb:cc port=4840 "
        "security_mode=None product=Siemens SIMATIC S7-1500 version=2.8.2\n"
        "ts=2024-01-15T10:00:01 src=10.0.2.16 dst=10.0.2.1 mac=00:1B:1B:aa:bb:dd port=4840 "
        "security_mode=SignAndEncrypt policy=Basic256Sha256 product=urn:Siemens:S7-1500 version=2.9.1\n"
    )
    (tmp_path / "modbus.log").write_text(
        "ts=2024-01-15T10:00:00 src=10.0.2.28 dst=10.0.2.1 port=502 proto=modbus tls=false\n"
    )
    (tmp_path / "dnp3.log").write_text(
        "ts=2024-01-15T10:00:00 src=10.0.3.42 dst=10.0.3.1 port=20000 proto=dnp3 sa=false\n"
    )
    result = OtPassiveScanner().scan_filesystem(tmp_path)
    assert result["packets_sent"] == 0
    assert result["device_count"] >= 3
    issues = {row.get("compliance_issue") for row in result["findings"]}
    assert "OT_UNENCRYPTED_TRAFFIC" in issues
    assert "OT_UNENCRYPTED_MODBUS" in issues
    assert "OT_NO_AUTHENTICATION" in issues
    encrypted = next(row for row in result["findings"] if row.get("security_level") == "ENCRYPT")
    assert encrypted["crypto"]["encryption"] == "AES-256-CBC"
    siemens = next(row for row in result["devices"] if row["ip_address"] == "10.0.2.15")
    assert siemens["vendor"] == "Siemens"
    weak = next(row for row in result["findings"] if row["device"]["ip_address"] == "10.0.2.15")
    assert any(item["cve"] == "CVE-2020-15782" for item in weak.get("vulnerabilities") or [])
