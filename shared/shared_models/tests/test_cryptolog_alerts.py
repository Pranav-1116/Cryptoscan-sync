"""CryptoLog deterministic rules and alert lifecycle tests
(docs/cryptolog/01_PRODUCT_SPEC.md, Phase 5).

A pattern never automatically becomes a confirmed compromise; severity is
calculated from named factors, never one unexplained number; every alert
carries what is proven and what is not."""

from __future__ import annotations

import pytest

from shared_models.cryptolog_alerts import (
    ACKNOWLEDGE, ACKNOWLEDGED, ALERT_SCHEMA, HIGH, CRITICAL, RULES, RESOLVE,
    evaluate, severity_for, transition,
)
from shared_models.cryptolog_events import make_event

AS_OF = "2026-11-07T04:00:00Z"


def _ev(event_type="TLS_NEGOTIATION_OBSERVED", category="TLS",
        asset="asset_gateway_001", ev="ev-1", ctx=None, attrs=None,
        approval=None, system=None):
    return make_event(
        event_type=event_type, category=category, logging_kind="ACTIVITY",
        tenant_id="tenant_001", severity="INFO", asset_id=asset,
        business_system_id=system,
        source={"collector_id": "c1", "collector_version": "1",
                "source_type": "NETWORK_OBSERVATION"},
        cryptographic_context=ctx or {"protocol": "TLS",
                                      "protocol_version": "TLS1.3",
                                      "evidence_level": "NETWORK_NEGOTIATED"},
        observed_at=AS_OF, evidence_ids=[ev], attributes=attrs or {},
        approval_ref=approval)


def test_the_registry_is_the_full_deterministic_rule_set():
    assert [r for r in RULES] == [f"CL-{i:03d}" for i in range(1, 16)]
    for rule_id, rule in RULES.items():
        assert rule["detection"] and rule["suggested_severity"]
        assert rule["investigation"], "every alert has a recommended investigation"


def test_cl001_downgrade_fires_only_against_previous_state():
    previous = _ev(ctx={"protocol": "TLS", "protocol_version": "TLS1.3",
                        "evidence_level": "NETWORK_NEGOTIATED"})
    downgrade = _ev(ev="ev-2", ctx={"protocol": "TLS",
                                    "protocol_version": "TLS1.2",
                                    "evidence_level": "NETWORK_NEGOTIATED"})
    upgrade = _ev(ev="ev-3", ctx={"protocol": "TLS",
                                  "protocol_version": "TLS1.3",
                                  "evidence_level": "NETWORK_NEGOTIATED"})

    alerts = evaluate([downgrade], previous_by_asset={
        "asset_gateway_001": previous})
    assert [a["rule_id"] for a in alerts] == ["CL-001"]
    assert alerts[0]["expected"] == "TLS1.3 remains negotiated"
    assert alerts[0]["observed"] == "TLS1.2 negotiated"

    quiet = evaluate([upgrade], previous_by_asset={
        "asset_gateway_001": previous})
    assert quiet == []
    assert evaluate([downgrade]) == [], "no previous state, no downgrade claim"


def test_cl002_weak_cipher_and_named_severity_drivers():
    weak = _ev(ev="ev-2", ctx={"protocol": "TLS", "protocol_version": "TLS1.2",
                               "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
                               "evidence_level": "NETWORK_NEGOTIATED"})
    alerts = evaluate([weak], assessments={"asset_gateway_001": {
        "asset_criticality": "CRITICAL", "exposure": "INTERNET_FACING"}})
    assert [a["rule_id"] for a in alerts] == ["CL-002"]
    alert = alerts[0]
    assert alert["severity"] == CRITICAL, "MEDIUM base + critical asset + facing"
    drivers = alert["severity_drivers"]
    assert any("asset criticality CRITICAL" in d for d in drivers)
    assert any("internet-facing" in d for d in drivers)
    assert alert["severity_basis"]["asset_criticality"] == "CRITICAL"

    strong = _ev(ctx={"protocol": "TLS", "protocol_version": "TLS1.3",
                      "cipher_suite": "TLS_AES_256_GCM_SHA384",
                      "evidence_level": "NETWORK_NEGOTIATED"})
    assert evaluate([strong]) == [], "a strong suite is not a weak-suite alert"


def test_unapproved_changes_fire_only_without_approval():
    for event_type, category, rule_id in (
            ("CERTIFICATE_REPLACEMENT", "CERTIFICATE", "CL-003"),
            ("HSM_KEY_METADATA_CHANGE", "HSM_KMS", "CL-005"),
            ("CA_TRUST_CHANGED", "CERTIFICATE", "CL-008"),
            ("CRYPTO_PROVIDER_CHANGED", "CONFIGURATION", "CL-013")):
        unapproved = _ev(event_type=event_type, category=category,
                         ctx={"protocol": "TLS",
                              "protocol_version": "TLS1.3",
                              "evidence_level": "CONFIGURED"})
        alerts = evaluate([unapproved])
        assert [a["rule_id"] for a in alerts] == [rule_id], rule_id
        approved = _ev(event_type=event_type, category=category,
                       approval="chg-42",
                       ctx={"protocol": "TLS", "protocol_version": "TLS1.3",
                            "evidence_level": "CONFIGURED"})
        assert evaluate([approved]) == [], f"{rule_id} respects approvals"


def test_cl010_pqc_removal_fires_but_capability_is_never_a_removal():
    removed = _ev(event_type="PQC_CONFIGURATION_CHANGED",
                  category="CONFIGURATION", attrs={"action": "REMOVED"},
                  ctx={"protocol": "TLS", "protocol_version": "TLS1.3",
                       "evidence_level": "CONFIGURED"})
    alerts = evaluate([removed])
    assert [a["rule_id"] for a in alerts] == ["CL-010"]

    capability = _ev(event_type="PQC_CAPABILITY_DISCOVERED",
                     category="ALGORITHM",
                     ctx={"protocol": "TLS", "protocol_version": "TLS1.3",
                          "evidence_level": "CAPABILITY"})
    assert evaluate([capability]) == [], \
        "a discovered capability is never an alert of any kind"


def test_cl015_reports_conflicts_never_picks_a_truth():
    first = _ev(ev="ev-1", ctx={"protocol": "TLS",
                                "protocol_version": "TLS1.3",
                                "evidence_level": "NETWORK_NEGOTIATED"})
    second = _ev(ev="ev-2", ctx={"protocol": "TLS",
                                 "protocol_version": "TLS1.2",
                                 "evidence_level": "NETWORK_NEGOTIATED"})
    alerts = evaluate([first, second])
    conflicts = [a for a in alerts if a["rule_id"] == "CL-015"]
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert set(conflict["supporting_event_ids"]) == {
        first["event_id"], second["event_id"]}
    assert "disagrees" in conflict["observed"]
    assert "never a truth to pick" not in conflict["what_is_proven"]
    assert "reconcile" in conflict["recommended_investigation"]


def test_every_alert_carries_proven_not_proven_and_history():
    weak = _ev(ev="ev-2", ctx={"protocol": "TLS", "protocol_version": "TLS1.2",
                               "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
                               "evidence_level": "NETWORK_NEGOTIATED"})
    alert = evaluate([weak])[0]
    assert alert["schema"] == ALERT_SCHEMA
    assert alert["supporting_event_ids"] == [weak["event_id"]]
    assert alert["supporting_evidence_ids"] == ["ev-2"]
    assert alert["affected"]["asset_ids"] == ["asset_gateway_001"]
    assert "ev-2" in alert["what_is_proven"]
    assert "never automatically becomes a confirmed compromise" \
        in alert["what_is_not_proven"]
    assert alert["recommended_investigation"]
    assert alert["lifecycle"] == {"status": "OPEN", "history": []}, \
        "an engine output is an open investigation, never a confirmed state"


def test_lifecycle_history_is_append_only_and_confirmations_demand_evidence():
    weak = _ev(ev="ev-2", ctx={"protocol": "TLS", "protocol_version": "TLS1.2",
                               "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
                               "evidence_level": "NETWORK_NEGOTIATED"})
    alert = evaluate([weak])[0]
    alert = transition(alert, action=ACKNOWLEDGE, actor="analyst-7",
                       at=AS_OF, note="looking")
    assert alert["lifecycle"]["status"] == ACKNOWLEDGED

    with pytest.raises(ValueError):
        transition(alert, action=RESOLVE, actor="analyst-7", at=AS_OF,
                   note="done", resolution="MADE_UP_KIND")
    with pytest.raises(ValueError):
        transition(alert, action=RESOLVE, actor="", at=AS_OF,
                   note="done", resolution="BENIGN_EXPLAINED")
    with pytest.raises(ValueError) as exc:
        transition(alert, action=RESOLVE, actor="analyst-7", at=AS_OF,
                   note="it is a compromise", resolution="CONFIRMED_INCIDENT")
    assert "never declares a compromise" in str(exc.value)

    confirmed = transition(alert, action=RESOLVE, actor="ciso-1", at=AS_OF,
                           note="incident opened from the bank SOC",
                           resolution="CONFIRMED_INCIDENT",
                           evidence_ids=["ev-2", "inc-77"])
    assert confirmed["lifecycle"]["status"] == "RESOLVED"
    entries = confirmed["lifecycle"]["history"]
    assert [e["action"] for e in entries] == [ACKNOWLEDGE, RESOLVE]
    assert entries[-1]["evidence_ids"] == ["ev-2", "inc-77"]
    assert entries[-1]["resolution"] == "CONFIRMED_INCIDENT"
