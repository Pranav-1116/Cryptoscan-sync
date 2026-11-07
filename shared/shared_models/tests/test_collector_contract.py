"""Collector standard contract (gap analysis §D), as tests.

"Each collector should publish a standard contract: collector identity and
version, supported asset types, required permissions, collection start/end
time, target scope, success, partial, refused or failed state, evidence
references, coverage metrics, data sensitivity classification, signature or
integrity metadata." — and the rule that decides honest zeroes:

"A collector that returns zero assets must explain whether it found nothing,
lacked permissions, failed, or did not support the target."
"""

from __future__ import annotations

import pytest

from shared_models.collector_contract import (
    FOUND_NOTHING,
    NO_PERMISSION,
    SUCCESS,
    UNSUPPORTED_TARGET,
    collector_contract,
    collection_report,
)


def contract(**over):
    base = dict(
        collector_id="linux-procfs", version="2.1.0",
        supported_asset_types=["crypto-library", "key-material"],
        required_permissions=["read:/proc", "read:/etc/ssl"],
        data_sensitivity="INTERNAL",
        signature={"algorithm": "ed25519", "value": "sig-1",
                   "key_id": "release-key-2026"},
    )
    base.update(over)
    return collector_contract(**base)


def report(**over):
    base = dict(
        contract=contract(), started_at="2026-11-07T01:00:00+00:00",
        ended_at="2026-11-07T01:05:00+00:00",
        target_scope="prod-linux-fleet",
        state=SUCCESS,
        assets_found=[{"asset_id": "lib-1", "asset_type": "crypto-library"}],
        evidence_ids=["RUN-LOG-1"],
        coverage_metrics={"expected": 10, "collected": 1},
    )
    base.update(over)
    return collection_report(**base)


class TestContract:

    def test_the_contract_names_every_field_the_review_requires(self):
        row = contract()
        for field in ("collector_id", "version", "supported_asset_types",
                      "required_permissions", "data_sensitivity", "signature"):
            assert row[field], field

    def test_identity_version_permissions_and_signature_are_mandatory(self):
        with pytest.raises(ValueError, match="unaccountable"):
            contract(collector_id="")
        with pytest.raises(ValueError, match="cannot be qualified"):
            contract(version="")
        with pytest.raises(ValueError, match="unbounded claim"):
            contract(supported_asset_types=[])
        with pytest.raises(ValueError, match="nobody can review"):
            contract(required_permissions=[])
        with pytest.raises(ValueError, match="checkable"):
            contract(signature={"algorithm": "ed25519"})

    def test_sensitivity_is_classified(self):
        with pytest.raises(ValueError, match="data_sensitivity"):
            contract(data_sensitivity="whatever")


class TestReport:

    def test_a_run_reports_clock_scope_state_evidence_and_coverage(self):
        row = report()
        for field in ("started_at", "ended_at", "target_scope", "state",
                      "evidence_ids", "coverage_metrics"):
            assert row[field] is not None, field
        assert row["report_digest"].startswith("sha256:")

    def test_a_zero_result_must_explain_itself(self):
        for reason in (FOUND_NOTHING, NO_PERMISSION, UNSUPPORTED_TARGET, "FAILED"):
            state = ("REFUSED" if reason == NO_PERMISSION
                     else "FAILED" if reason == "FAILED" else SUCCESS)
            row = report(assets_found=[], state=state, zero_reason=reason,
                         evidence_ids=["RUN-LOG-1"] if state == SUCCESS else [])
            assert row["zero_reason"] == reason
        with pytest.raises(ValueError, match="must explain itself"):
            report(assets_found=[], zero_reason=None)
        with pytest.raises(ValueError, match="must explain itself"):
            report(assets_found=[], zero_reason="BECAUSE")

    def test_success_without_evidence_or_a_clock_is_refused(self):
        with pytest.raises(ValueError, match="claim"):
            report(evidence_ids=[])
        with pytest.raises(ValueError, match="without a clock"):
            report(started_at="")
        with pytest.raises(ValueError, match="clock is wrong"):
            report(ended_at="2026-11-07T00:00:00+00:00")

    def test_the_digest_is_reproducible(self):
        row = report()
        assert row["report_digest"] == report()["report_digest"]
