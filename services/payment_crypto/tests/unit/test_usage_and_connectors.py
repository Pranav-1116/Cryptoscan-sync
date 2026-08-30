"""Key-usage analytics, transaction correlation, HSM connectors, simulator."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from payment_crypto.auditlog import HsmAuditParser
from payment_crypto.connectors import (
    HttpJsonlConnector,
    PayshieldSimulator,
    SyslogFileConnector,
    connector_from_config,
)
from payment_crypto.usage import TransactionCorrelator, UsageAnalyzer

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def _used(key_id: str, days_ago: int, op: str = "PIN_VERIFY") -> dict:
    return {"occurred_at": (NOW - timedelta(days=days_ago)).isoformat(),
            "device": "hsm-1", "event_type": "KEY_USED", "key_id": key_id,
            "detail": {"op": op}}


def _key(key_id: str, *, state: str = "ACTIVE", activated_days_ago: int = 200) -> dict:
    return {"key_id": key_id, "state": state,
            "activation_at": (NOW - timedelta(days=activated_days_ago)).isoformat()}


# ------------------------------------------------------------------ usage

def test_dormant_active_key_flagged_clean_key_not():
    analyzer = UsageAnalyzer(now=NOW, dormancy_days=90)
    report = analyzer.analyze(
        [_key("ZMK-DORMANT"), _key("ZPK-BUSY", activated_days_ago=30)],
        [_used("ZPK-BUSY", days_ago=1), _used("ZMK-DORMANT", days_ago=120)],
    )
    rules = {(finding["key_id"], finding["rule_id"]) for finding in report["findings"]}
    assert ("ZMK-DORMANT", "PAY-011") in rules   # last used 120d ago
    assert ("ZPK-BUSY", "PAY-011") not in rules  # used yesterday
    assert report["per_key"]["ZPK-BUSY"]["ops"] == 1
    assert report["per_key"]["ZPK-BUSY"]["by_op"] == {"PIN_VERIFY": 1}


def test_dead_key_usage_is_blocking_and_shadow_keys_detected():
    analyzer = UsageAnalyzer(now=NOW)
    findings = analyzer.analyze(
        [_key("K-DEAD", state="DESTROYED")],
        [_used("K-DEAD", days_ago=2), _used("GHOST-KEY", days_ago=1)],
    )["findings"]
    by_rule = {finding["rule_id"] for finding in findings}
    assert "PAY-012" in by_rule
    assert any(f["rule_id"] == "PAY-012" and f["blocking"] for f in findings)
    assert "PAY-013" in by_rule  # GHOST-KEY is used but in no inventory
    shadow = next(f for f in findings if f["rule_id"] == "PAY-013")
    assert shadow["key_id"] == "GHOST-KEY"


# ---------------------------------------------------------- correlation

def test_correlation_insufficient_data_is_honest():
    result = TransactionCorrelator().evaluate(
        {"2026-08-2%d" % i: 10_000_000 for i in range(0, 3)},
        {"2026-08-2%d" % i: 10_800_000 for i in range(0, 3)},
    )
    assert result["status"] == "insufficient_data"
    assert result["findings"] == []


def test_correlation_flags_bypass_anomaly():
    # 20 stable days at ~1.08 ops/tx, then a day at 0.5 (software fallback?)
    tx = {(date(2026, 8, 1) + timedelta(days=i)).isoformat(): 10_000_000 for i in range(20)}
    ops = {(date(2026, 8, 1) + timedelta(days=i)).isoformat(): 10_800_000 for i in range(20)}
    ops[date(2026, 8, 20).isoformat()] = 5_000_000
    result = TransactionCorrelator().evaluate(tx, ops)
    assert result["status"] == "anomalies"
    anomaly = result["findings"][-1]
    assert anomaly["rule_id"] == "PAY-014"
    assert anomaly["evidence"]["date"] == "2026-08-20"
    assert anomaly["evidence"]["deviation_pct"] < -35  # ~ -54%


def test_correlation_clean_series_no_findings():
    tx = {(date(2026, 8, 1) + timedelta(days=i)).isoformat(): 10_000_000 for i in range(20)}
    ops = {(date(2026, 8, 1) + timedelta(days=i)).isoformat(): 10_800_000 + i * 1000 for i in range(20)}
    result = TransactionCorrelator().evaluate(tx, ops)
    assert result["status"] == "ok"
    assert result["findings"] == []


# ----------------------------------------------------------- connectors

def test_http_connector_parses_and_reports_cursor():
    feed = "\n".join([
        '{"occurred_at":"2026-08-30T10:00:00Z","device":"hsm-1","event_type":"KEY_USED","key_id":"ZPK-1","detail":{"op":"PIN_VERIFY"}}',
        '{"occurred_at":"2026-08-30T10:01:00Z","device":"hsm-1","event_type":"AUTH_FAILURE"}',
    ])

    def fake_fetch(url, headers):
        assert "since=2026-08-29" in url
        assert headers.get("Authorization") == "Bearer tok"
        return 200, feed

    connector = HttpJsonlConnector("https://siem.example/hsm", token="tok", fetch=fake_fetch)
    result = connector.poll(since=datetime(2026, 8, 29, tzinfo=timezone.utc))
    assert result.ok
    assert len(result.records) == 2
    assert result.cursor == "2026-08-30T10:01:00+00:00"

    failing = HttpJsonlConnector("https://siem.example/hsm", fetch=lambda url, headers: (503, ""))
    assert failing.poll().errors[0] == "HTTP 503 from https://siem.example/hsm"


def test_syslog_file_connector_cursor_and_rotation(tmp_path):
    audit = tmp_path / "audit.log"
    audit.write_text(
        '<30>2026-08-30T10:00:00Z hsm-1 crypto: event=pin_verify key_id=ZPK-1\n', encoding="utf-8")
    connector = SyslogFileConnector(audit)
    first = connector.poll()
    assert len(first.records) == 1
    assert first.records[0].event_type == "KEY_USED"

    audit.write_text(
        audit.read_text() + '<30>2026-08-30T11:00:00Z hsm-1 crypto: event=auth_fail user=x\n',
        encoding="utf-8")
    second = connector.poll()
    assert len(second.records) == 1            # only the new line
    assert second.records[0].event_type == "AUTH_FAILURE"

    audit.write_text('<30>2026-08-30T12:00:00Z hsm-1 crypto: event=key_use key_id=ZPK-2\n',
                     encoding="utf-8")        # rotation: file shrank
    third = connector.poll()
    assert any("rotated" in error for error in third.errors)
    assert len(third.records) == 1


def test_simulator_output_parses_and_is_labeled():
    simulator = PayshieldSimulator(seed=7)
    lines = simulator.day(NOW, transactions=10_000_000)
    parsed = HsmAuditParser().parse_jsonl(lines)
    assert parsed.records and not parsed.rejected
    assert all((record.detail or {}).get("sim") == "hsm-simulator" for record in parsed.records)
    summary = simulator.summary(NOW, transactions=10_000_000)
    assert summary["hsm_ops"] == 10_800_000 and summary["simulator"] is True


def test_connector_from_config_dispatch():
    assert isinstance(connector_from_config({"url": "https://x"}), HttpJsonlConnector)
    assert isinstance(connector_from_config({"path": "/tmp/a.log"}), SyslogFileConnector)
    assert connector_from_config({}) is None
