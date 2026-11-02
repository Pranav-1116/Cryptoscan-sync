"""Guide 155 tests: the history guide script, plus the module's refusals.

The module's own behaviour is pinned by `test_nbom_history.py`. This file covers the
guide script (every probe must pass, `--check` must exit 0, the sections must be the
five the guide claims) and the edges a report can go wrong on: a snapshot that is not
a snapshot, a timeline of one, and a finding that only ever fires on a weakening.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from cbom import nbom_history

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "cbom_nbom_history.py"
GUIDE_JSON = ROOT / "docs" / "bank-environment" / "155-nbom-history.json"
GUIDE_MD = ROOT / "docs" / "bank-environment" / "155-nbom-history.md"

PAYMENTS = {
    "host": "payments.bank.example", "port": 443, "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "sni": "payments.bank.example",
    "alpn": "h2", "evidence_id": "NET-1",
    "certificate": {"fingerprint_sha256": "aa11", "issuer": "BANK-ICA-01",
                    "not_after": "2027-01-01", "public_key_algorithm": "ECDSA",
                    "public_key_size": 256},
}
PARTNER = {
    "host": "partner.bank.example", "port": 443, "tls_version": "1.2",
    "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "NET-2",
    "certificate": {"fingerprint_sha256": "bb22", "issuer": "PARTNER-CA"},
}


def _load_script():
    spec = importlib.util.spec_from_file_location("cbom_nbom_history_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report():
    return _load_script().measure()


# --------------------------------------------------------------------------- #
# the guide itself


def test_the_guide_has_exactly_five_sections(report):
    assert [row["id"] for row in report["rows"]] == [
        "snapshot_is_a_state", "the_change_list", "downgrade_is_not_any_change",
        "the_finding", "history"]


def test_every_probe_in_the_guide_passes(report):
    failed = [(row["id"], probe["probe"]) for row in report["rows"]
              for probe in row["probes"] if not probe["ok"]]
    assert failed == []
    assert report["counts"] == {"PASS": 5, "PARTIAL": 0, "FAIL": 0}


def test_the_guide_declares_every_change_kind_it_can_report(report):
    assert set(report["change_kinds"]) == set(nbom_history.CHANGE_KINDS)
    assert set(report["regression_kinds"]) < set(report["change_kinds"])


def test_the_guide_states_its_own_limits(report):
    assert len(report["limits"]) >= 5
    assert any("not probed" in limit for limit in report["limits"])
    assert any("baseline" in limit for limit in report["limits"])


def test_the_guide_sample_is_a_regression_with_evidence_on_both_sides(report):
    assert report["comparison"]["identical"] is False
    finding = report["regression"]["findings"][0]
    assert finding["finding"] == "NETWORK_CRYPTO_REGRESSION"
    assert finding["evidence_before"] == ["NET-1"]
    assert finding["evidence_after"] == ["NET-9"]


def test_check_exits_zero_and_writes_nothing_elsewhere(tmp_path, capsys):
    module = _load_script()
    assert module.main(["--check", "--json", str(tmp_path / "g.json")]) == 0
    assert (tmp_path / "g.json").exists()
    assert "pass" in capsys.readouterr().err


def test_the_committed_guide_matches_the_script(report):
    """The checked-in JSON must be what the script produces now, not what it produced."""
    committed = json.loads(GUIDE_JSON.read_text(encoding="utf-8"))
    assert committed["counts"] == report["counts"]
    assert committed["probes"] == report["probes"]
    assert [row["id"] for row in committed["rows"]] == [row["id"] for row in report["rows"]]
    for row in committed["rows"]:
        assert row["verdict"] == "PASS", row["id"]


def test_the_committed_markdown_mentions_every_change_kind(report):
    body = GUIDE_MD.read_text(encoding="utf-8")
    for kind in report["change_kinds"]:
        assert kind in body
    assert "What this does not prove" in body


def test_the_guide_never_claims_an_attack():
    body = GUIDE_MD.read_text(encoding="utf-8").lower()
    for phrase in ("attack detected", "compromise confirmed", "attacker identified"):
        assert phrase not in body


# --------------------------------------------------------------------------- #
# edges a report can go wrong on


def test_a_snapshot_that_is_not_a_snapshot_is_refused():
    good = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    for broken in ({"schema": "cryptoscan.nbom/1"}, {"endpoints": []}, {}):
        with pytest.raises(ValueError, match="not a"):
            nbom_history.compare(broken, good)
        with pytest.raises(ValueError, match="not a"):
            nbom_history.compare(good, broken)


def test_a_snapshot_with_no_endpoints_is_still_a_valid_state():
    empty = nbom_history.snapshot([], taken_at="2026-11-01T00:00:00Z")
    assert empty["endpoints"] == []
    assert nbom_history.compare(empty, empty)["identical"] is True


def test_a_timeline_of_one_snapshot_has_no_periods_and_says_so():
    only = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    body = nbom_history.timeline([only])
    assert body["periods"] == [] and body["snapshots"] == 1
    assert body["regressions"] == 0 and body["worst"] is None
    assert "no regression" in body["statement"]


def test_a_timeline_orders_snapshots_by_observation_time_not_by_argument_order():
    early = nbom_history.snapshot([PARTNER], taken_at="2026-11-01T00:00:00Z")
    late = nbom_history.snapshot([{**PARTNER, "tls_version": "1.3"}],
                                 taken_at="2026-11-02T00:00:00Z")
    body = nbom_history.timeline([late, early])
    assert body["periods"][0]["from"] == "2026-11-01T00:00:00Z"
    assert body["periods"][0]["regression"]["findings"] == []


def test_an_added_endpoint_is_a_change_and_never_a_regression():
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot([PAYMENTS, PARTNER], taken_at="2026-11-02T00:00:00Z")
    comparison = nbom_history.compare(before, after)
    assert "ENDPOINT_ADDED" in {change["kind"] for change in comparison["changes"]}
    assert nbom_history.regression(comparison)["findings"] == []


def test_a_removed_endpoint_is_reported_with_the_evidence_it_had():
    before = nbom_history.snapshot([PAYMENTS, PARTNER], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-02T00:00:00Z")
    removed = [change for change in nbom_history.compare(before, after)["changes"]
               if change["kind"] == "ENDPOINT_REMOVED"]
    assert len(removed) == 1
    assert removed[0]["evidence_before"] == ["NET-2"]
    assert removed[0]["evidence_after"] == []
    assert "decommissioned" in removed[0]["detail"]


def test_an_uncollected_endpoint_is_not_compared_as_if_it_had_no_crypto():
    """An endpoint that was never observed must not read as *cipher became None*."""
    known = {**PAYMENTS, "observed": False, "cipher_suite": None, "tls_version": None}
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot([known], taken_at="2026-11-02T00:00:00Z")
    kinds = {change["kind"] for change in nbom_history.compare(before, after)["changes"]}
    assert "COLLECTION_STATUS_CHANGED" in kinds
    # a missing observation is a gap; the downgrade classification belongs to
    # observed state, and the finding must not silently become CRITICAL on a timeout
    finding = nbom_history.regression(nbom_history.compare(before, after))
    assert finding["findings"] == []


def test_two_endpoints_downgrading_produce_two_findings_not_one():
    weak = {**PARTNER, "cipher_suite": "RC4-SHA"}
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot(
        [{**PAYMENTS, "cipher_suite": "ECDHE-RSA-AES128-SHA"}, weak],
        taken_at="2026-11-02T00:00:00Z")
    findings = nbom_history.regression(nbom_history.compare(before, after))["findings"]
    assert [finding["endpoint"] for finding in findings] == ["payments.bank.example:443"]


def test_the_finding_names_the_endpoint_and_no_guessed_owner():
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot([{**PAYMENTS, "tls_version": "1.0"}],
                                  taken_at="2026-11-02T00:00:00Z")
    finding = nbom_history.regression(nbom_history.compare(before, after))["findings"][0]
    assert finding["endpoint"] == "payments.bank.example:443"
    assert finding["affected_systems"] == []
    assert "Payments" not in json.dumps(finding)


def test_the_severity_never_exceeds_what_the_signals_support():
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot([{**PAYMENTS, "sni": "other.bank.example"}],
                                  taken_at="2026-11-02T00:00:00Z")
    comparison = nbom_history.compare(before, after)
    assert "SNI_CHANGED" in {change["kind"] for change in comparison["changes"]}
    assert nbom_history.regression(comparison)["findings"] == []
    assert nbom_history.summary(comparison)["worst"] is None


def test_summary_reports_changes_and_regressions_separately():
    before = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    after = nbom_history.snapshot(
        [{**PAYMENTS, "tls_version": "1.2"}, PARTNER], taken_at="2026-11-02T00:00:00Z")
    body = nbom_history.summary(nbom_history.compare(before, after))
    assert body["changes"] == 2
    assert body["regressions"] == 1
    assert body["worst"] == "HIGH"
    assert "NETWORK_CRYPTO_REGRESSION" in body["statement"]


def test_the_digest_does_not_move_when_only_provenance_moves():
    first = nbom_history.snapshot([PAYMENTS], taken_at="2026-11-01T00:00:00Z")
    again = nbom_history.snapshot([{**PAYMENTS, "evidence_id": "NET-42"}],
                                  taken_at="2026-11-02T00:00:00Z")
    assert first["hash"] == again["hash"]
    assert [entry["digest"] for entry in first["endpoints"]] == [
        entry["digest"] for entry in again["endpoints"]]
    assert again["endpoints"][0]["evidence_ids"] == ["NET-42"]
