"""Collector-contract publication tests (gap analysis §D).

"Each collector should publish a standard contract" — the published schema
at ``docs/contracts/collector-contract.schema.json`` is the contract of
record; these tests keep the publication in lockstep with the module. A
drift between the two is a build failure, never a quiet documentation lag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared_models.collector_contract import (
    CONTRACT_SCHEMA, PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED,
    SUCCESS, PARTIAL, REFUSED, RUN_FAILED, RUN_STATES,
    FOUND_NOTHING, NO_PERMISSION, FAILED, UNSUPPORTED_TARGET, ZERO_REASONS,
    SENSITIVITY_LEVELS, collector_contract, collection_report,
)

PUBLISHED = Path(__file__).resolve().parents[3] / "docs" / "contracts" / "collector-contract.schema.json"


@pytest.fixture(scope="module")
def published():
    assert PUBLISHED.is_file(), (
        "the collector standard contract is a published artifact: "
        f"{PUBLISHED} must exist")
    return json.loads(PUBLISHED.read_text())


def _descriptor(**over):
    base = dict(collector_id="collector-tls-observer", version="2.4.0",
                supported_asset_types=["certificate", "tls_endpoint"],
                required_permissions=["net:connect", "file:read"],
                data_sensitivity=INTERNAL,
                signature={"algorithm": "ed25519", "value": "AAECAw=="})
    base.update(over)
    return collector_contract(**base)


def _report(contract, **over):
    base = dict(contract=contract,
                started_at="2026-11-07T05:00:00+00:00",
                ended_at="2026-11-07T05:02:00+00:00",
                target_scope="vpc:payments-prod",
                state=SUCCESS,
                assets_found=[{"asset_type": "certificate"}],
                evidence_ids=["ev-1"],
                coverage_metrics={"endpoints_probed": 12, "endpoints_reached": 11})
    base.update(over)
    return collection_report(**base)


# ------------------------------------------------------- publication sync
def test_published_schema_is_the_module_contract(published):
    assert published["$id"] == CONTRACT_SCHEMA
    defs = published["$defs"]
    assert tuple(defs["zero_reason"]["enum"]) == ZERO_REASONS
    assert tuple(defs["run_state"]["enum"]) == RUN_STATES
    assert tuple(defs["sensitivity"]["enum"]) == SENSITIVITY_LEVELS


def test_every_gap_analysis_field_is_published(published):
    declared = published["x-gap-analysis-fields"]
    assert len(declared) == 10, "the review names exactly ten published fields"
    descriptor_props = published["oneOf"][0]["properties"]
    report_props = published["oneOf"][1]["properties"]
    joined = " ".join(sorted(set(descriptor_props) | set(report_props)))
    for field in ("collector_id", "version",            # identity and version
                  "supported_asset_types",               # asset types
                  "required_permissions",                # permissions
                  "started_at", "ended_at",              # start/end time
                  "target_scope",                        # target scope
                  "state",                               # run state
                  "evidence_ids",                        # evidence references
                  "coverage_metrics",                    # coverage metrics
                  "data_sensitivity",                    # sensitivity
                  "signature", "report_digest"):         # integrity metadata
        assert field in joined, f"the published contract must cover {field}"


# -------------------------------------------------- module vs publication
def test_real_descriptor_validates_against_the_publication(published):
    from jsonschema import validate
    validate(instance=_descriptor(), schema=published)


def test_real_report_validates_against_the_publication(published):
    from jsonschema import validate
    validate(instance=_report(_descriptor()), schema=published)


def test_real_zero_run_validates_and_explains_itself(published):
    from jsonschema import validate
    report = _report(_descriptor(), state=RUN_FAILED, assets_found=[],
                     evidence_ids=[], zero_reason=FAILED)
    validate(instance=report, schema=published)
    assert report["zero_reason"] in ZERO_REASONS


def test_signature_is_published_as_mandatory_integrity(published):
    descriptor_required = published["oneOf"][0]["required"]
    assert "signature" in descriptor_required
    with pytest.raises(ValueError):
        _descriptor(signature={"algorithm": "ed25519"})  # value missing
