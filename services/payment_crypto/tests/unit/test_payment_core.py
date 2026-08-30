"""Payment crypto core: TR-31 parsing, audit-log ingestion, PAY-xxx policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from payment_crypto.auditlog import HsmAuditParser
from payment_crypto.keyblocks import parse_tr31_header
from payment_crypto.policy import PaymentPolicyEngine

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


# ------------------------------------------------------------------ TR-31

def test_tr31_header_fields():
    block = "B00401B001N0" + "0000" + "00" * 16  # B0, ZMK, TDES, any-mode, non-exportable
    header = parse_tr31_header(block)
    assert header.valid
    assert header.key_usage == "ZONE_MASTER_KEY_ZMK"
    assert header.algorithm == "TRIPLE_DES"
    assert header.exportability == "NON_EXPORTABLE"
    assert header.legacy_binding  # B0 has no cryptographic binding


def test_tr31_modern_version_not_flagged():
    block = "B20502E001E0" + "0000" + "00" * 16  # B2, ZPK, AES, encrypt
    header = parse_tr31_header(block)
    assert header.valid
    assert header.key_usage == "ZONE_PIN_KEY_ZPK"
    assert header.algorithm == "AES"
    assert not header.legacy_binding


def test_tr31_unknown_codes_stay_honest():
    header = parse_tr31_header("ZZ9901B001E0" + "0000" + "00" * 16)
    assert header.valid  # structure parses…
    assert header.key_usage.startswith("UNKNOWN")  # …but codes are not guessed


def test_tr31_rejects_garbage():
    header = parse_tr31_header("nope")
    assert not header.valid
    assert header.errors


# --------------------------------------------------------------- ingest

def test_jsonl_ingest_and_rejection():
    parser = HsmAuditParser()
    result = parser.parse_jsonl("\n".join([
        '{"occurred_at":"2026-08-30T10:00:00Z","device":"hsm-1","event_type":"KEY_GENERATED",'
        '"key_id":"ZPK-1","actor":"custodian-a","detail":{"algorithm":"AES"}}',
        '{"occurred_at":"2026-08-30T10:01:00Z","device":"hsm-1","event":"clear_key","key_id":"ZMK-9"}',
        "{broken json",
        '{"device":"hsm-1","event_type":"KEY_EXPORTED"}',  # missing timestamp
    ]))
    assert [record.event_type for record in result.records] == ["KEY_GENERATED", "CLEAR_KEY_EXPORT"]
    assert len(result.rejected) == 2
    assert result.records[0].occurred_at.year == 2026


def test_syslog_kv_ingest():
    parser = HsmAuditParser()
    result = parser.parse_syslog(
        '<30>2026-08-30T12:00:00Z hsm-2 crypto: event=auth_fail user=unknown src=10.0.0.9'
    )
    assert result.records[0].event_type == "AUTH_FAILURE"
    assert result.records[0].detail.get("src") == "10.0.0.9"


def test_csv_with_column_map():
    parser = HsmAuditParser()
    csv_text = (
        "2026-08-30T10:00:00Z,hsm-1,77,key_export,ZMK-01,ops1,INFO\n"
        "2026-08-30T10:01:00Z,hsm-1,12,auth_fail,,root,WARNING\n"
    )
    result = parser.parse_csv(csv_text, columns={
        "ts": 0, "device": 1, "event": 3, "key_id": 4, "actor": 5, "severity": 6})
    assert [record.event_type for record in result.records] == ["KEY_EXPORTED", "AUTH_FAILURE"]
    assert not result.rejected


# ---------------------------------------------------------------- policy

def _engine() -> PaymentPolicyEngine:
    return PaymentPolicyEngine(now=NOW)


def test_weak_algorithm_and_rotation_and_legacy_block():
    findings = _engine().evaluate([
        {"key_id": "ZMK-OLD", "key_usage": "ZONE_MASTER_KEY_ZMK", "algorithm": "TRIPLE_DES",
         "state": "ACTIVE", "activation_at": (NOW - timedelta(days=800)).isoformat(),
         "key_block_version": "B0"},
    ], ceremonies=[{"key_id": "ZMK-OLD", "held_at": "2026-01-01", "custodians": ["a", "b"],
                    "dual_control": True}])
    rules = {finding.rule_id for finding in findings}
    assert "PAY-001" in rules   # deprecated 3DES on an active key
    assert "PAY-002" in rules   # past 24-month ZMK rotation window
    assert "PAY-008" in rules   # B0 key block without binding


def test_dual_control_and_missing_ceremony():
    findings = _engine().evaluate([
        {"key_id": "K-DUAL", "key_usage": "KEK", "algorithm": "AES", "state": "ACTIVE",
         "activation_at": NOW - timedelta(days=5)},
        {"key_id": "K-NONE", "key_usage": "KEK", "algorithm": "AES", "state": "ACTIVE",
         "activation_at": NOW - timedelta(days=5)},
    ], ceremonies=[{"key_id": "K-DUAL", "held_at": "2026-08-01",
                    "custodians": ["only-one"], "dual_control": False}])
    by_key = {(f.key_id, f.rule_id) for f in findings}
    assert ("K-DUAL", "PAY-003") in by_key  # single custodian, no dual control
    assert ("K-NONE", "PAY-005") in by_key  # no ceremony at all


def test_clean_key_no_findings():
    findings = _engine().evaluate([
        {"key_id": "K-OK", "key_usage": "ZONE_PIN_KEY_ZPK", "algorithm": "AES", "state": "ACTIVE",
         "activation_at": NOW - timedelta(days=30)},
    ], ceremonies=[{"key_id": "K-OK", "held_at": "2026-08-01",
                    "custodians": ["a", "b"], "dual_control": True}])
    assert findings == []


def test_event_rules_clear_export_auth_storm_firmware():
    events = (
        [{"occurred_at": "2026-08-29T10:00:00Z", "device": "hsm-1",
          "event_type": "CLEAR_KEY_EXPORT", "key_id": "ZMK-9"}]
        + [{"occurred_at": f"2026-08-{day:02d}T09:00:00Z", "device": "hsm-1",
            "event_type": "AUTH_FAILURE"} for day in range(20, 26)]
        + [{"occurred_at": "2026-08-28T09:00:00Z", "device": "hsm-2",
            "event_type": "FIRMWARE_UPDATED", "detail": {}}]
        + [{"occurred_at": "2026-08-28T09:30:00Z", "device": "hsm-3",
            "event_type": "FIRMWARE_UPDATED", "detail": {"change_ref": "CHG-0042"}}]
    )
    findings = _engine().evaluate([], events=events)
    rules = {finding.rule_id for finding in findings}
    assert "PAY-004" in rules  # clear-key export
    assert "PAY-006" in rules  # auth failure storm
    assert "PAY-007" in rules  # firmware change without change ref
    firmware = [f for f in findings if f.rule_id == "PAY-007"]
    assert all(f.evidence.get("device") == "hsm-2" for f in firmware)  # ref'd one not flagged


def test_compromised_key_still_enabled_and_small_rsa():
    findings = _engine().evaluate([
        {"key_id": "K-BAD", "algorithm": "RSA", "key_size": 1024, "state": "ACTIVE",
         "activation_at": NOW - timedelta(days=1)},
        {"key_id": "K-DEAD", "algorithm": "AES", "state": "COMPROMISED", "enabled": True},
    ], ceremonies=[
        {"key_id": "K-BAD", "held_at": "2026-08-01", "custodians": ["a", "b"], "dual_control": True},
        {"key_id": "K-DEAD", "held_at": "2026-08-01", "custodians": ["a", "b"], "dual_control": True},
    ])
    by_key = {(f.key_id, f.rule_id) for f in findings}
    assert ("K-BAD", "PAY-001") in by_key   # RSA-1024
    assert ("K-DEAD", "PAY-009") in by_key  # compromised yet enabled
