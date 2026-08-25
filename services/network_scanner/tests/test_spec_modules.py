from network_scanner.alerts.expiry_alerter import alert_expiring
from network_scanner.config.settings import load_settings
from network_scanner.core.scan_context import ScanContext
from network_scanner.main import main
from network_scanner.inventory.certificate_deduplicator import dedupe_certificates
from network_scanner.models.network_finding import NetworkFinding
from network_scanner.passive.envoy_log_parser import parse_envoy_line
from network_scanner.probing.ssl_error_classifier import classify_ssl_error
from network_scanner.probing.tcp_connector import connect


def test_envoy_parser_and_inventory_helpers():
    line = parse_envoy_line('tls_version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 authority=api.example.com')
    assert line is not None
    assert line["crypto"]["tls_version"] == "TLSv1.3"
    merged = dedupe_certificates(
        [],
        [
            {"fingerprint_sha256": "abc", "days_until_expiry": 5, "subject": "CN=api", "usages": ["a"]},
            {"fingerprint_sha256": "abc", "endpoint": "b", "days_until_expiry": 4},
        ],
    )
    alerts = alert_expiring(merged, days=30)
    assert alerts[0]["severity"] == "HIGH"
    assert "expires" in (alerts[0].get("body") or "").lower()
    assert "Certificate" in (alerts[0].get("html_body") or "")
    finding = NetworkFinding.from_dict(line)
    assert finding.algorithm
    assert classify_ssl_error("wrong version number") == "PROTOCOL_VERSION_MISMATCH"
    refused = connect("127.0.0.1", 1, timeout=0.2)
    assert refused["status"] in {"PORT_CLOSED", "CONNECT_ERROR", "TIMEOUT"}
    ctx = ScanContext.for_path("/tmp", live=False)
    assert ctx.to_dict()["target_kind"] == "filesystem"
    assert load_settings().timeout > 0


def test_network_main_scans_tree(tmp_path):
    out = tmp_path / "out.json"
    assert main([str(tmp_path), "-o", str(out)]) == 0
    assert "scan_context" in out.read_text(encoding="utf-8")
