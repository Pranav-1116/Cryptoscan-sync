from network_scanner.inventory.certificate_inventory import expiring, merge_certificates
from network_scanner.inventory.expiry_monitor import expiry_alerts
from network_scanner.probing.cipher_suite_parser import parse_cipher_suite, tls_algorithm


def test_parse_tls13_and_tls12_ciphers():
    v13 = parse_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert v13["algorithm"] == "AES"
    assert v13["mode"] == "GCM"
    assert v13["key_size"] == 256
    assert v13["key_exchange"] == "ECDHE"
    v12 = parse_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384", bits=256)
    assert v12["key_exchange"] == "ECDHE"
    assert v12["authentication"] == "RSA"
    assert v12["algorithm"] == "AES"
    assert v12["mode"] == "GCM"
    assert tls_algorithm("TLSv1.0") == "TLS1.0"
    assert tls_algorithm("TLSv1.3") == "TLS1.3"


def test_inventory_dedup_and_expiry_alerts():
    first = {
        "fingerprint_sha256": "abc",
        "subject": "CN=api.example.com",
        "days_until_expiry": 12,
        "expiry_status": "EXPIRING_SOON",
        "usages": ["tls://api.example.com:443"],
    }
    second = {
        "fingerprint_sha256": "abc",
        "endpoint": "tls://internal:8443",
        "days_until_expiry": 11,
    }
    other = {"fingerprint_sha256": "def", "days_until_expiry": 90, "expiry_status": "VALID"}
    merged = merge_certificates([], [first, second, other])
    assert len(merged) == 2
    abc = next(row for row in merged if row["fingerprint_sha256"] == "abc")
    assert "tls://api.example.com:443" in abc["usages"]
    assert "tls://internal:8443" in abc["usages"]
    soon = expiring(merged, days=30)
    assert [row["fingerprint_sha256"] for row in soon] == ["abc"]
    alerts = expiry_alerts(merged, days=30)
    assert alerts[0]["type"] == "CERTIFICATE_EXPIRING"
    assert alerts[0]["severity"] == "MEDIUM"
