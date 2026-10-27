"""Requirements register (§4.3): requirement → evidence / gaps / expiry / sign-off.

Pure evaluation tests: every standing is derived, never invented — missing
controls stay missing, stale evidence expires, a manual sign-off never turns
an unmapped requirement into evidence, and a signature over a DIFFERENT pack
never signs this one off.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from compliance.requirements import REGISTER, evaluate_requirements

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def _pack(statuses: dict[str, str], *, age_days: float = 0.0, include: set[str] | None = None) -> dict:
    """A pack whose controls carry exactly the given statuses.

    ``include`` drops controls not listed even when their status is given —
    used to make a mapped control MISSING from the pack.
    """
    controls = []
    for key, status in statuses.items():
        if include is not None and key not in include:
            continue
        controls.append({"control": key, "status": status, "checked_at": NOW.isoformat(), "evidence": {}})
    generated_at = (NOW - timedelta(days=age_days)).isoformat()
    return {"generated_at": generated_at, "controls": controls, "summary": {}, "pack_sha256": "p" * 64}


def _row(report: dict, req_id: str) -> dict:
    return next(r for r in report["requirements"] if r["requirement"] == req_id)


def _att(scope: str, *, valid: bool = True, sha: str = "p" * 64) -> dict:
    return {"scope": scope, "signed_by": "alice", "signed_at": NOW.isoformat(), "pack_sha256": sha, "jws_valid": valid}


ALL_PASS = {
    "access.session_config": "pass",
    "config.production_gate": "pass",
    "protection.rate_limits": "pass",
    "audit.chain_integrity": "pass",
    "deploy.schema_in_sync": "pass",
    "retention.worm_policy": "pass",
}


def test_no_pack_means_no_evidence_never_a_pass():
    report = evaluate_requirements(None, [])
    assert report["summary"]["denominator"] == len(REGISTER)
    assert report["summary"]["closed"] == 0
    assert all(r["standing"] == "no_evidence" for r in report["requirements"])
    # unmapped requirements are visible as requirements, not hidden
    assert _row(report, "PCI-DSS-4.2.1")["standing"] == "no_evidence"
    assert _row(report, "PCI-DSS-4.2.1")["gap"]


def test_passing_fresh_signed_requirement_closes():
    pack = _pack(ALL_PASS)
    report = evaluate_requirements(pack, [_att("SOC2-CC6.1"), _att("RETENTION-WORM")], now=NOW)
    cc61 = _row(report, "SOC2-CC6.1")
    assert cc61["standing"] == "evidenced"
    assert cc61["closed"] is True
    assert cc61["expiry"]["state"] == "fresh"
    assert cc61["sign_off"]["state"] == "signed"
    # signed-off rows close; the summary denominator stays the full register
    assert report["summary"]["closed"] == 2
    assert report["summary"]["denominator"] == len(REGISTER)


def test_unsigned_requirement_awaits_sign_off_it_does_not_close():
    report = evaluate_requirements(_pack(ALL_PASS), [], now=NOW)
    cc61 = _row(report, "SOC2-CC6.1")
    assert cc61["standing"] == "awaiting_sign_off"
    assert cc61["closed"] is False
    assert report["summary"]["closed"] == 0


def test_fail_gap_unknown_and_missing_controls_each_have_their_own_standing():
    report = evaluate_requirements(
        _pack({"access.session_config": "fail", **{k: "pass" for k in ALL_PASS if k != "access.session_config"}}),
        [],
        now=NOW,
    )
    assert _row(report, "SOC2-CC6.1")["standing"] == "gap"

    report = evaluate_requirements(
        _pack({"audit.chain_integrity": "unknown", **{k: "pass" for k in ALL_PASS if k != "audit.chain_integrity"}}),
        [],
        now=NOW,
    )
    assert _row(report, "SOC2-CC7.2")["standing"] == "not_evaluable"

    # a mapped control ABSENT from the pack is missing evidence, never a pass
    report = evaluate_requirements(_pack(ALL_PASS, include=set(ALL_PASS) - {"deploy.schema_in_sync"}), [], now=NOW)
    cc81 = _row(report, "SOC2-CC8.1")
    assert cc81["standing"] == "missing_evidence"
    assert cc81["evidence_controls"][0]["status"] == "missing"


def test_evidence_expires_against_the_requirements_own_window():
    pack = _pack(ALL_PASS, age_days=100)  # older than 90d, younger than 365d
    report = evaluate_requirements(pack, [_att("SOC2-CC6.1"), _att("RETENTION-WORM")], now=NOW)
    assert _row(report, "SOC2-CC6.1")["standing"] == "expired"
    assert _row(report, "SOC2-CC6.1")["expiry"]["state"] == "expired"
    # the 365-day retention requirement is still inside its window
    assert _row(report, "RETENTION-WORM")["standing"] == "evidenced"
    assert _row(report, "RETENTION-WORM")["expiry"]["state"] == "fresh"


def test_unmapped_requirements_stay_unevaluated_even_when_manually_signed():
    report = evaluate_requirements(_pack(ALL_PASS), [_att("PCI-DSS-4.2.1")], now=NOW)
    pci = _row(report, "PCI-DSS-4.2.1")
    assert pci["standing"] == "unevaluated"  # the signature does not invent evidence
    assert pci["closed"] is False
    assert pci["sign_off"]["state"] == "signed"  # ...but the manual sign-off IS recorded
    assert pci["mapped_controls"] == []


def test_signature_over_a_different_pack_never_signs_this_one():
    other = _att("SOC2-CC6.1", sha="q" * 64)  # signed over different evidence
    report = evaluate_requirements(_pack(ALL_PASS), [other], now=NOW)
    assert _row(report, "SOC2-CC6.1")["sign_off"]["state"] == "unsigned"
    assert _row(report, "SOC2-CC6.1")["standing"] == "awaiting_sign_off"


def test_invalid_signature_is_invalid_not_signed():
    bad = _att("SOC2-CC6.1", valid=False)
    report = evaluate_requirements(_pack(ALL_PASS), [bad], now=NOW)
    cc61 = _row(report, "SOC2-CC6.1")
    assert cc61["sign_off"]["state"] == "invalid"
    assert cc61["standing"] == "awaiting_sign_off"
    assert cc61["closed"] is False


def test_every_mapped_control_is_one_the_evidence_engine_can_collect():
    # the register must not reference a control the engine never emits —
    # that would be a permanent, invisible "missing"
    from compliance.engine import collect_evidence  # noqa: F401 — import check

    engine_src = open(collect_evidence.__code__.co_filename, encoding="utf-8").read()
    for req in REGISTER:
        for key in req["mapped_controls"]:
            assert f'"{key}"' in engine_src, (
                f"{req['requirement']} maps control '{key}' which the engine "
                "never emits — it would report missing forever"
            )
