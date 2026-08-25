from datetime import datetime, timedelta, timezone

from cbom.coverage import effective_status, initial_status, parse_system_import, rollup


def test_unknown_until_scanned():
    assert initial_status(None) == "NO_TARGET"
    assert initial_status("https://git/bank/pay.git") == "NEVER_SCANNED"
    assert effective_status(coverage_status="NEVER_SCANNED", scan_target="git://x") == "NEVER_SCANNED"
    now = datetime.now(timezone.utc)
    assert effective_status(coverage_status="CURRENT", last_scanned_at=now) == "CURRENT"
    stale = now - timedelta(days=120)
    assert effective_status(coverage_status="CURRENT", last_scanned_at=stale) == "STALE"


def test_rollup_bank_message():
    summary = rollup({"NO_TARGET": 10, "NEVER_SCANNED": 80, "CURRENT": 8, "STALE": 1, "FAILED": 1})
    assert summary["systems"] == 100
    assert summary["unknown_crypto"] == 90
    assert summary["with_cbom"] == 9
    assert "unknown cryptography until they are scanned" in summary["message"]


def test_parse_cmdb_csv_and_json():
    csv = "name,scan_target,owner,environment\npayments-api,https://git/bank/pay.git,alice,prod\nledger,,bob,prod\n"
    rows = parse_system_import(csv)
    assert rows[0]["name"] == "payments-api"
    assert rows[0]["coverage_status"] == "NEVER_SCANNED"
    assert rows[1]["coverage_status"] == "NO_TARGET"
    js = parse_system_import([{"name": "atm-switch", "repo": "https://git/bank/atm.git", "bu": "Cards"}])
    assert js[0]["business_unit"] == "Cards"
    assert js[0]["scan_target"].endswith("atm.git")
