"""Scanner gate tests — the full control chain (spec §21)."""

from __future__ import annotations

from privacy.gate import ScannerGate
from privacy.policy import build_policy
from privacy.ratelimit import Limits, RateLimiter


def _gate(**scan_overrides) -> ScannerGate:
    return ScannerGate(policy=build_policy(dict(scan_overrides), {}, sector="banking"),
                       limits=Limits())


def test_gate_permits_authorized_scope_scan():
    gate = _gate()
    d = gate.evaluate(
        actor="alice", tenant="bank-a", environment="prod-uae",
        targets={"network": ["10.20.0.10:443"], "crypto": ["router-001"]},
        credentials={"network": True, "crypto": True},
        scope_includes={"excluded": [], "special": [], "special_approved": False},
    )
    assert d.permitted is True, d.reason
    assert d.audit["decision"] == "allow"
    # every control ran
    assert {c.control for c in d.checks} == {
        "authorization", "scope", "privacy", "scan_policy", "rate_limit",
        "target_safety", "credential"}


def test_gate_denies_absent_actor_or_tenant():
    gate = _gate()
    d = gate.evaluate(actor="", tenant="bank-a", targets={"network": ["10.0.0.1:443"]},
                      credentials={"network": True})
    assert d.denied and d.denied_by == "authorization"
    d2 = gate.evaluate(actor="alice", tenant="", targets={"network": ["10.0.0.1:443"]},
                       credentials={"network": True})
    assert d2.denied and d2.denied_by == "authorization"


def test_gate_denies_excluded_target():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"network": ["10.40.0.5:443"]}, credentials={"network": True},
                      scope_includes={"excluded": ["10.40.0.5:443"], "special": []})
    assert d.denied and d.denied_by == "scope"
    assert "excluded" in d.reason


def test_gate_denies_no_authorized_targets():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a", targets={}, credentials={})
    assert d.denied and d.denied_by == "scope"


def test_gate_denies_special_approval_not_granted():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"hardware": ["hsm-pay-bank"]}, credentials={"hardware": True},
                      scope_includes={"excluded": [], "special": ["hsm-pay-bank"],
                                      "special_approved": False})
    assert d.denied and d.denied_by == "scope"
    assert "special approval" in d.reason


def test_gate_bypasses_special_approval_when_granted():
    # scope explicitly grants special approval for the HSM, so the target-safety
    # gate passes (the conservative budget still applies).
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"hardware": ["hsm-pay-bank"]}, credentials={"hardware": True},
                      scope_includes={"excluded": [], "special": ["hsm-pay-bank"],
                                      "special_approved": True})
    assert d.permitted, d.reason


def test_gate_denies_scan_intensity_off():
    gate = ScannerGate(policy=build_policy({"intensity": "off", "mode": "read-only"}, {},
                                           sector="banking"),
                       limits=Limits())
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"network": ["10.20.0.10:443"]}, credentials={"network": True})
    assert d.denied and d.denied_by == "scan_policy"
    assert "intensity is OFF" in d.reason


def test_gate_denies_read_only_high_intensity():
    gate = ScannerGate(policy=build_policy({"mode": "read-only", "intensity": "high"}, {},
                                           sector="banking"),
                       limits=Limits())
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"network": ["10.20.0.10:443"]}, credentials={"network": True})
    assert d.denied and d.denied_by == "scan_policy"


def test_gate_denies_missing_credentials():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"network": ["10.20.0.10:443"], "cloud": ["aws:123"]},
                      credentials={"network": True},  # no cloud cred
                      )
    assert d.denied and d.denied_by == "credential"
    assert "cloud" in d.reason


def test_gate_denies_hsm_without_specials():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"hardware": ["hsm-core-01"]}, credentials={"hardware": True},
                      scope_includes={"excluded": [], "special": [], "special_approved": False})
    # target_safety: HSM is blocked because HSM protection requires a special
    # conservative policy; with read-only low the scan policy passes, so it is
    # the HSM special-approval gate that denies.
    assert d.denied, d.reason
    assert d.denied_by in ("target_safety", "scope")


def test_gate_rate_limits_scanner_burst():
    limiter = RateLimiter(Limits(requests_per_second=1, max_concurrency=1))
    gate = ScannerGate(policy=build_policy({}, {}, sector="banking"), limiter=limiter,
                       limits=Limits(requests_per_second=1))
    first = gate.evaluate(actor="alice", tenant="bank-a",
                          targets={"network": ["10.20.0.10:443"]}, credentials={"network": True})
    assert first.permitted, first.reason
    second = gate.evaluate(actor="alice", tenant="bank-a",
                           targets={"network": ["10.20.0.11:443"]}, credentials={"network": True})
    assert second.denied, second.reason
    assert second.denied_by == "rate_limit"


def test_gate_to_dict_roundtrip():
    gate = _gate()
    d = gate.evaluate(actor="alice", tenant="bank-a",
                      targets={"network": ["10.20.0.10:443"]}, credentials={"network": True},
                      scope_includes={"excluded": [], "special": [], "special_approved": False})
    dd = d.to_dict()
    assert dd["permitted"] is True
    assert len(dd["checks"]) == 7
