"""KEY_INVENTORY_ATTRIBUTE — policy over HSM/KMS/keystore export metadata, silent on code findings."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from policy.conditions.key_inventory_attribute import KeyInventoryAttributeCondition
from policy.core.engine import PolicyEngine

RULES = Path(__file__).resolve().parents[3] / "rule_definitions"


def _ev(**inv):
    return {"id": "e1", "algorithm": inv.pop("algorithm", "AES"), "key_size": 256,
            "finding_data": {"source": {"type": "KEY_INVENTORY"}, "inventory": inv, "metadata": {"library": "ICSF"}}}


def test_not_applicable_to_code_findings():
    c = KeyInventoryAttributeCondition()
    out = c.evaluate({"finding_data": {"source": {"type": "SOURCE_CODE"}, "inventory": {"exportability": "exportable"}}},
                     {"attribute": "exportability", "operator": "contains", "value": "exportable"})
    assert out.result == "NOT_APPLICABLE"


def test_operators():
    c = KeyInventoryAttributeCondition()
    today = date.today()
    assert c.evaluate(_ev(key_label="K", extractable=True), {"attribute": "extractable", "operator": "is_true"}).result == "FAIL"
    assert c.evaluate(_ev(key_label="K", extractable=False), {"attribute": "extractable", "operator": "is_true"}).result == "PASS"
    assert c.evaluate(_ev(key_label="K"), {"attribute": "extractable", "operator": "is_true"}).result == "NOT_APPLICABLE"
    assert c.evaluate(_ev(key_label="K", state="PendingDeletion"), {"attribute": "state", "operator": "in", "values": ["Disabled", "PendingDeletion"], "result": "WARN"}).result == "WARN"
    assert c.evaluate(_ev(key_label="K", not_after=(today - timedelta(days=1)).isoformat()), {"attribute": "not_after", "operator": "date_before_today"}).result == "FAIL"
    assert c.evaluate(_ev(key_label="K", not_after=(today + timedelta(days=30)).isoformat()), {"attribute": "not_after", "operator": "date_within_days", "days": 90, "result": "WARN"}).result == "WARN"
    assert c.evaluate(_ev(key_label="K", not_after=(today + timedelta(days=300)).isoformat()), {"attribute": "not_after", "operator": "date_within_days", "days": 90, "result": "WARN"}).result == "PASS"
    assert c.evaluate(_ev(key_label="K", last_used=(today - timedelta(days=400)).isoformat()), {"attribute": "last_used", "operator": "older_than_days", "days": 365, "result": "WARN"}).result == "WARN"
    assert c.evaluate(_ev(key_label="K"), {"attribute": "last_used", "operator": "older_than_days", "days": 365, "require_attributes": ["last_used"]}).result == "NOT_APPLICABLE"
    assert c.evaluate(_ev(key_label="K", not_after="soon"), {"attribute": "not_after", "operator": "date_before_today"}).result == "NOT_APPLICABLE"
    assert c.evaluate(_ev(key_label="K", role="certificate signature digest", not_after="2001-01-01"), {"attribute": "not_after", "operator": "date_before_today"}).result == "NOT_APPLICABLE"
    assert c.evaluate(_ev(key_label="K"), {"attribute": "x", "operator": "nope"}).result == "WARN"


def test_shipped_key_inventory_rules_end_to_end():
    engine = PolicyEngine(str(RULES))
    ids = {r.rule_id for r in engine.get_enabled_rules()}
    assert {"KEYINV-001", "KEYINV-002", "KEYINV-003", "KEYINV-004", "KEYINV-005", "KEYINV-006", "KEYINV-007", "KEYINV-008", "KEYINV-009"} <= ids
    # a TR-31 version A, exportable, expired key
    ev = _ev(key_label="PAY.ZPK.ACQ001", algorithm="3DES", key_block_version="TR-31 A (key variant binding)",
             exportability="sensitive (exportable under any KEK)", not_after="2019-01-01", last_used="2018-01-01", weak_binding=True)
    res = {r.rule_id: r.evaluation_result for r in engine.evaluate(ev).rules_evaluated}
    assert res["KEYINV-001"] == "FAIL" and res["KEYINV-002"] == "FAIL" and res["KEYINV-003"] == "FAIL" and res["KEYINV-007"] == "FAIL"
    assert res["KEYINV-005"] == "WARN" and res["KEYINV-004"] == "PASS" and res["KEYINV-006"] == "NOT_APPLICABLE"
    # non-exportable must not trip the exportable rule (substring trap)
    ok = _ev(key_label="STMT.AES.DATA", exportability="non-exportable", key_block_version="TR-31 D (AES key derivation)", state="Enabled")
    res = {r.rule_id: r.evaluation_result for r in engine.evaluate(ok).rules_evaluated}
    assert res["KEYINV-001"] == "PASS" and res["KEYINV-002"] == "PASS" and res["KEYINV-006"] == "PASS"
    # code findings never see KEYINV rules as FAIL/WARN
    code = {"id": "e2", "algorithm": "AES", "key_size": 256, "finding_data": {"source": {"type": "SOURCE_CODE"}, "metadata": {}}}
    assert all(r.evaluation_result == "NOT_APPLICABLE" for r in engine.evaluate(code).rules_evaluated if r.rule_id.startswith("KEYINV"))
