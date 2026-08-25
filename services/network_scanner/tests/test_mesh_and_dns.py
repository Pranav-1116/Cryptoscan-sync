from network_scanner.certificates.hostname_matcher import matches
from network_scanner.certificates.san_extractor import extract_dns_names
from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.discovery.dns_discoverer import parse_hosts, parse_zone
from network_scanner.passive.service_mesh_observer import parse_envoy_line
from network_scanner.probing.ssl_error_classifier import classify_ssl_error


def test_classify_ssl_error():
    assert classify_ssl_error("unsupported protocol") == "PROTOCOL_VERSION_MISMATCH"
    assert classify_ssl_error("no shared cipher") == "CIPHER_SUITE_MISMATCH"
    assert classify_ssl_error("certificate verify failed") == "CERTIFICATE_VERIFY_FAILED"


def test_san_and_hostname():
    cert = {"subject": "CN=api.example.com", "san": ["DNS:api.example.com", "DNS:*.example.com"]}
    assert extract_dns_names(cert)[0] == "api.example.com"
    assert matches("api.example.com", cert)
    assert matches("pay.example.com", cert)


def test_envoy_json_and_kv_lines():
    json_line = '{"authority":"pay","tls_version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384"}'
    kv_line = "GET / HTTP/2 tls_version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384"
    js = parse_envoy_line(json_line)
    kv = parse_envoy_line(kv_line)
    assert js["crypto"]["tls_version"] == "TLSv1.3"
    assert js["algorithm"] == "TLS1.3"
    assert kv["crypto"]["tls_version"] == "TLSv1.2"


def test_dns_and_mesh_discovery(tmp_path):
    (tmp_path / "hosts").write_text("10.0.0.8 api.internal\n127.0.0.1 localhost\n")
    (tmp_path / "corp.zone").write_text("pay IN A 10.1.2.3\n")
    (tmp_path / "envoy.access.log").write_text(
        "GET / HTTP/2 tls_version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384\n"
    )
    hosts = parse_hosts((tmp_path / "hosts").read_text())
    zone = parse_zone((tmp_path / "corp.zone").read_text())
    assert hosts[0]["endpoint"] == "api.internal:443"
    assert zone[0]["endpoint"] == "pay:443"
    result = NetworkTlsScanner(live=False).scan_filesystem(tmp_path)
    assert any(row.get("metadata", {}).get("scan_method") == "PASSIVE_MESH" for row in result["findings"])
    endpoints = {t["endpoint"] for t in result["targets"]}
    assert "api.internal:443" in endpoints
