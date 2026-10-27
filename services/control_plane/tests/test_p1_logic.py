"""Pure-logic tests for the P1 enterprise layer."""

from datetime import datetime, timedelta, timezone

from control_plane import (
    assess_dr,
    build_signed_export,
    evaluate_policy,
    framework_posture,
    is_deprecated_or_worse,
    load_signed_export,
    lookup,
    lookup_vendor,
    merge_policy_layers,
    migration_target,
    normalize_siem_events,
    policy_version,
    residency_violations,
    resolve_cmdb_assets,
    route_region,
    ticket_state_machine,
    to_cef,
)

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------- crypto KB
def test_crypto_kb_status_and_migration():
    assert lookup("RSA", 1024)["status"] == "broken"
    assert lookup("RSA", 2048)["status"] == "acceptable"
    assert lookup("tls1.3")["status"] == "recommended"
    assert lookup("ml-kem-768")["status"] == "pqc"
    assert is_deprecated_or_worse("3des") is True
    assert is_deprecated_or_worse("aes-256-gcm") is False
    assert "ml-dsa" in migration_target("RSA", 1024)
    assert lookup_vendor("cisco-asa")["vendor"] == "cisco"


# -------------------------------------------------------- policy as code
def test_policy_layering_and_version():
    sector = {"id": "banking", "rules": [
        {"id": "tls-min", "path": "tls.version", "op": "gte", "value": 1.2, "effect": "fail"}]}
    org = {"rules": [
        {"id": "no-ssh-rsa", "path": "ssh.key_algorithm", "op": "ne", "value": "rsa", "effect": "warn"}]}
    merged = merge_policy_layers(sector, org)
    assert len(merged["rules"]) == 2 and "version" in merged
    # version is stable
    assert policy_version(merged) == merged["version"]
    # FAIL on weak TLS
    res = evaluate_policy(merged, {"tls": {"version": 1.0}, "ssh": {"key_algorithm": "ed25519"}})
    assert res.verdict == "FAIL"
    # WARN-only when TLS ok but SSH rsa
    res2 = evaluate_policy(merged, {"tls": {"version": 1.3}, "ssh": {"key_algorithm": "rsa"}})
    assert res2.verdict == "WARN"
    # PASS when both fine
    res3 = evaluate_policy(merged, {"tls": {"version": 1.3}, "ssh": {"key_algorithm": "ed25519"}})
    assert res3.verdict == "PASS"


def test_policy_applicability_scope():
    pol = {"id": "ot-only", "rules": [
        {"id": "r1", "path": "x", "op": "eq", "value": 1,
         "when": {"environment": "ot"}}]}
    assert evaluate_policy(pol, {"environment": "it", "x": 9}).verdict == "NOT_APPLICABLE"


# ------------------------------------------------------------ compliance
def test_compliance_posture_traceable():
    controls = [
        {"id": "SC-8", "framework": "NIST", "assets": ["a1", "a2"]},
        {"id": "SC-12", "framework": "NIST", "assets": ["a1"]},
        {"id": "SC-13", "framework": "NIST", "assets": ["a3"]},
    ]
    findings = [{"control_id": "SC-12", "asset_id": "a1", "status": "open"}]
    evidence = [
        {"control_id": "SC-8", "asset_id": "a1", "current": True},
        {"control_id": "SC-8", "asset_id": "a2", "current": True},
        # SC-13 has no evidence -> NOT_EVIDENCED
    ]
    posture = framework_posture(controls, findings, evidence)
    assert posture["gaps"] == 1
    assert posture["not_evidenced"] == 1
    assert posture["compliant"] == 1
    assert 0 < posture["coverage_pct"] < 100


# ------------------------------------------------------------------ CMDB
def test_cmdb_resolution_matches_and_enriches():
    cmdb = [
        {"serial": "S1", "owner": "security", "business_unit": "payments",
         "criticality": "tier1", "ci_id": "CI-001"},
        {"serial": "S2", "owner": "it"},
    ]
    discovered = [
        {"serial": "S1", "asset_type": "hsm"},
        {"fqdn": "new-host.local", "asset_type": "server"},
    ]
    r = resolve_cmdb_assets(cmdb, discovered)
    assert r["matched"] == 1 and r["new_unmatched"] == 1 and r["cmdb_stale"] == 1
    assert r["enriched"][0]["business_unit"] == "payments"


# ------------------------------------------------------------------ ITSM
def test_ticket_lifecycle():
    assert ticket_state_machine("open", "triage") == "triaged"
    assert ticket_state_machine("triaged", "assign") == "assigned"
    assert ticket_state_machine("validation", "pass") == "resolved"
    assert ticket_state_machine("validation", "fail") == "reopened"
    assert ticket_state_machine("resolved", "close") == "closed"
    # invalid action leaves state unchanged
    assert ticket_state_machine("open", "close") == "open"


# ------------------------------------------------------------------ SIEM
def test_cef_and_siem_normalization():
    cef = to_cef({"category": "risk_change", "name": "risk up", "severity": "high",
                  "asset": "hsm-1", "sector": "banking"})
    assert cef.startswith("CEF:0|ZELNX|") and "|8|" in cef  # high severity -> CEF 8
    events = [
        {"category": "alert", "severity": "critical", "name": "x"},
        {"category": "ignored_type"},
    ]
    out = normalize_siem_events(events, "splunk")
    assert len(out) == 1 and out[0]["provider"] == "splunk"
    assert out[0]["cef"].startswith("CEF:0")


# -------------------------------------------------------- air-gapped export
def test_signed_export_roundtrip_and_tamper():
    doc = {"findings": [{"id": "f1", "severity": "high"}], "evidence": ["e1"]}
    pkg = build_signed_export(doc, "shared-secret")
    assert pkg["format"] == "zelnx-signed-export/v1"
    assert load_signed_export(pkg, "shared-secret")["findings"][0]["id"] == "f1"
    # wrong secret rejected
    import pytest
    with pytest.raises(ValueError):
        load_signed_export(pkg, "wrong-secret")
    # tampered content rejected
    tampered = dict(pkg); tampered["document"] = {"findings": []}
    with pytest.raises(ValueError):
        load_signed_export(tampered, "shared-secret")


# ------------------------------------------------- regions / residency / DR
def test_routing_and_residency():
    tenant = {"data_residency_region": "uae", "processing_regions": ["uae"]}
    assert route_region(tenant) == "uae"
    assert route_region(tenant, "eu") == "uae"  # residency locks to uae
    assert residency_violations(tenant, ["uae", "eu"]) == ["eu"]
    unrestricted = {"data_residency_region": "us", "processing_regions": []}
    assert residency_violations(unrestricted, ["eu", "us"]) == []


def test_dr_assessment():
    # fresh backup, healthy -> ok
    ok = assess_dr({"rpo_minutes": 60, "rto_minutes": 60},
                   last_backup_at=(NOW - timedelta(minutes=10)).isoformat(), now=NOW)
    assert ok["rpo_within_target"] is True and ok["recommended_action"] == "healthy"
    # stale backup exceeds RPO
    stale = assess_dr({"rpo_minutes": 60},
                      last_backup_at=(NOW - timedelta(minutes=300)).isoformat(), now=NOW)
    assert stale["rpo_within_target"] is False and "exceeds RPO" in stale["recommended_action"]
    # primary down, secondary up -> failover
    fo = assess_dr({"rpo_minutes": 60}, last_backup_at=(NOW - timedelta(minutes=5)).isoformat(),
                   primary_healthy=False, secondary_healthy=True, now=NOW)
    assert fo["recommended_action"] == "failover" and fo["failover_ready"] is True
    # no backup
    assert "no backups" in assess_dr({}, now=NOW)["recommended_action"]
