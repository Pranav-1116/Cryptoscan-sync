from datetime import datetime, timedelta, timezone

from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.certificates.ocsp_checker import check_ocsp, extract_ocsp_urls
from network_scanner.core.scheduler import due_targets, next_scan_time
from network_scanner.inventory.usage_tracker import usage_records


def test_chain_flags_expired_and_self_signed():
    result = validate_chain(
        [{"subject": "CN=a", "issuer": "CN=a", "expiry_status": "EXPIRED", "is_self_signed": True, "san": []}],
        hostname="other.example",
    )
    assert result["is_valid"] is False
    assert "CERT_EXPIRED" in result["errors"]
    assert "SELF_SIGNED" in result["errors"]


def test_ocsp_offline_is_unknown():
    cert = {"pem": "http://ocsp.example.com/ocsp", "fingerprint_sha256": "abc"}
    assert extract_ocsp_urls(cert)
    status = check_ocsp(cert, live=False)
    assert status["status"] == "UNKNOWN"
    assert status["method"] == "OCSP"


def test_scheduler_due_and_usages():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    targets = [
        {"endpoint": "a.example:443", "scan_frequency": "daily", "last_scan_time": (now - timedelta(days=2)).isoformat(), "enabled": True},
        {"endpoint": "b.example:443", "scan_frequency": "weekly", "last_scan_time": now.isoformat(), "enabled": True},
    ]
    due = due_targets(targets, now=now)
    assert [row["endpoint"] for row in due] == ["a.example:443"]
    nxt = next_scan_time(now, "daily", now=now)
    assert nxt > now
    usages = usage_records(
        [{"fingerprint_sha256": "abc", "usages": ["tls://api.example:443", "/tmp/leaf.pem"]}]
    )
    kinds = {row["usage_type"] for row in usages}
    assert "TLS_ENDPOINT" in kinds
    assert "PEM_FILE" in kinds
