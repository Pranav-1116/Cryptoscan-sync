"""Prometheus text rendering of scan, SSH, and drift telemetry."""

from __future__ import annotations

from network_scanner.reports.metrics import CONTENT_TYPE, render_prometheus


def _scan_result():
    return {
        "scan_id": "s1",
        "probe_telemetry": {
            "status": "PARTIAL",
            "probed": 6,
            "ok": 4,
            "statuses": {"OK": 4, "TIMEOUT": 1, "TLS_ERROR": 1},
            "weak_tls_versions": 1,
            "weak_cipher_suites": 2,
            "insecure_renegotiation": 1,
            "client_renegotiation_accepted": 0,
            "chain_order_issues": 1,
            "revoked_certificates": 1,
        },
        "certificates": [
            {"fingerprint_sha256": "fp1", "days_until_expiry": 90, "subject": "CN=fine"},
            {"fingerprint_sha256": "fp2", "days_until_expiry": 5, "subject": "CN=soon"},
            {"fingerprint_sha256": "fp3", "days_until_expiry": -1, "subject": "CN=dead"},
            {"fingerprint_sha256": "fp4", "days_until_expiry": None, "subject": "CN=mystery"},
        ],
    }


def test_renders_tls_scan_families():
    text = render_prometheus(_scan_result())
    assert text.startswith("# HELP cryptoscan_network_scan_probed")
    assert "# TYPE cryptoscan_network_probe_status gauge" in text
    assert 'cryptoscan_network_probe_status{status="OK"} 4' in text
    assert 'cryptoscan_network_probe_status{status="TLS_ERROR"} 1' in text
    # verdict one-hot: exactly the active verdict carries 1
    assert 'cryptoscan_network_scan_verdict{verdict="PARTIAL"} 1' in text
    assert 'cryptoscan_network_scan_verdict{verdict="OK"} 0' in text
    # weak counters
    assert "cryptoscan_network_weak_tls_versions 1" in text
    assert "cryptoscan_network_revoked_certificates 1" in text


def test_renders_certificate_expiry_aggregates():
    text = render_prometheus(_scan_result())
    assert 'cryptoscan_network_cert_expiry_status{status="VALID"} 1' in text
    assert 'cryptoscan_network_cert_expiry_status{status="EXPIRING_7D"} 1' in text
    assert 'cryptoscan_network_cert_expiry_status{status="EXPIRED"} 1' in text
    assert 'cryptoscan_network_cert_expiry_status{status="UNKNOWN"} 1' in text
    assert "cryptoscan_network_cert_min_days_until_expiry -1" in text


def test_renders_ssh_families():
    text = render_prometheus(
        {
            "ssh_probe_telemetry": {
                "status": "PARTIAL",
                "probed": 3,
                "ok": 2,
                "statuses": {"OK": 2, "SSH_UNREACHABLE": 1},
                "ssh_weak_host_keys": 1,
                "ssh_host_key_changes": 1,
                "ssh_weak_algorithm_offers": 2,
            }
        }
    )
    assert "# HELP cryptoscan_ssh_scan_probed" in text
    assert 'cryptoscan_ssh_probe_status{status="SSH_UNREACHABLE"} 1' in text
    assert 'cryptoscan_ssh_scan_verdict{verdict="PARTIAL"} 1' in text
    assert "cryptoscan_ssh_host_key_changes 1" in text
    assert "cryptoscan_ssh_weak_algorithm_offers 2" in text


def test_renders_drift_families():
    text = render_prometheus(
        {
            "verdict": "REGRESSED",
            "change_count": 4,
            "severity_counts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0},
            "changes": [{"type": "t", "severity": "CRITICAL"}],
        }
    )
    assert "cryptoscan_drift_change_total 4" in text
    assert 'cryptoscan_drift_changes{severity="CRITICAL"} 1' in text
    assert 'cryptoscan_drift_changes{severity="HIGH"} 2' in text
    assert 'cryptoscan_drift_verdict{verdict="REGRESSED"} 1' in text
    assert 'cryptoscan_drift_verdict{verdict="UNCHANGED"} 0' in text


def test_combined_payload_renders_all_sections():
    payload = _scan_result()
    payload["ssh_probe_telemetry"] = {"status": "OK", "probed": 1, "ok": 1, "statuses": {"OK": 1}}
    payload["verdict"] = "IMPROVED"
    payload["changes"] = []
    payload["severity_counts"] = {}
    text = render_prometheus(payload)
    assert "cryptoscan_network_scan_probed" in text
    assert "cryptoscan_ssh_scan_probed" in text
    assert 'cryptoscan_drift_verdict{verdict="IMPROVED"} 1' in text


def test_label_values_are_escaped():
    text = render_prometheus(
        {"statuses": {'BAD"QUOTE\\SLASH': 1}, "probed": 1}
    )
    assert 'status="BAD\\"QUOTE\\\\SLASH"' in text


def test_unknown_payload_is_valid_comment_only():
    text = render_prometheus({"something": "else"})
    assert text.strip() == "# cryptoscan: no recognizable telemetry in payload"
    assert render_prometheus(None).startswith("# cryptoscan:")
    assert render_prometheus({}).startswith("# cryptoscan:")


def test_bare_telemetry_dict_is_accepted():
    text = render_prometheus({"probed": 2, "ok": 2, "statuses": {"OK": 2}, "status": "OK"})
    assert "cryptoscan_network_scan_probed 2" in text
    assert 'cryptoscan_network_scan_verdict{verdict="OK"} 1' in text


def test_document_ends_with_newline_and_content_type():
    assert render_prometheus(_scan_result()).endswith("\n")
    assert "version=0.0.4" in CONTENT_TYPE
