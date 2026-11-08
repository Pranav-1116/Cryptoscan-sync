"""Performance Phase-8 qualification tests (docs/performance/01_PRODUCT_SPEC.md).

The harness must prove its acceptance rows: every check passes on the
SYNTHETIC corpus, external acts stay register-only, the report is
byte-identical to its generator, and the honesty rules are structural —
retention plans never delete, unknown telemetry is never zero.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

sys.path.insert(0, str(ROOT / "services" / "performance"))
sys.path.insert(0, str(ROOT / "shared" / "shared_models"))

from performance.qualification_suite import (  # noqa: E402
    EXTERNAL_ACTS, SCHEMA, run_suite,
)
from shared_models.performance_corpus import (  # noqa: E402
    SYNTHETIC_SOURCE, generate_corpus, missing_row,
)
from shared_models.performance_retention import (  # noqa: E402
    RetentionPolicy, plan_retention,
)


def test_every_qualification_check_passes_on_the_synthetic_corpus():
    result = run_suite()
    assert result["schema"] == SCHEMA
    failures = [c for c in result["checks"] if c["status"] != "PASS"]
    assert failures == [], failures
    assert result["summary"]["all_pass"] is True
    assert len(result["checks"]) >= 12


def test_the_harness_labels_itself_synthetic_and_keeps_timings_out():
    result = run_suite()
    assert "SYNTHETIC" in result["note"]
    assert "never qualify a real-environment act" in result["note"]
    for check in result["checks"]:
        assert "seconds" not in check["detail"], \
            "a wall-clock number in a byte-identity document is a lie " \
            "waiting to happen — timings belong in `timings` only"
    assert set(result["timings"]) <= {"volume_ingest_seconds"}


def test_external_acts_stay_register_only():
    result = run_suite()
    statuses = {act["act"]: act["status"] for act in result["external_acts"]}
    assert set(statuses) == {act for act, _ in EXTERNAL_ACTS}
    for status in statuses.values():
        assert status == "EXTERNAL — NOT DONE (register only)"
    assert any("bank" in act for act in statuses), \
        "bank validation is the bank's act"


def test_the_corpus_is_deterministic_and_labelled_at_the_source():
    first = generate_corpus(40)
    second = generate_corpus(40)
    assert first == second
    for row in first:
        assert row.source_id == SYNTHETIC_SOURCE
        assert row.labels["synthetic"] == "1"
    unknown = missing_row(0)
    assert unknown.value_or_unknown() is None
    assert unknown.quality_status.value in ("stale", "missing")


def test_a_retention_plan_is_a_projection_that_never_deletes():
    rows = generate_corpus(10, seed=20261120)
    policy = RetentionPolicy(policy_key="p1", samples_days=30)
    now = rows[0].observed_at + timedelta(days=90)
    plan = plan_retention(rows, policy=policy, now=now)
    snapshot = [row.metric_id for row in rows]
    assert plan.expired_total == 10
    assert "never deletes originals" in plan.as_dict()["note"]
    assert [row.metric_id for row in rows] == snapshot, \
        "planning never mutates the rows it classifies"
    with pytest.raises(ValueError, match="positive"):
        RetentionPolicy(policy_key="p2", samples_days=0)


def test_the_generated_report_is_byte_identical():
    path = ROOT / "docs" / "performance" / "02_QUALIFICATION_REPORT.md"
    assert path.exists(), "the qualification report is a generated deliverable"
    on_disk = path.read_text(encoding="utf-8")
    produced = subprocess.check_output(
        [sys.executable,
         str(ROOT / "scripts" / "gen_performance_qualification.py")],
        cwd=str(ROOT), text=True,
        env={"PATH": "/usr/bin:/bin", "ENVIRONMENT": "test"},
    )
    assert on_disk == produced, \
        "docs/performance/02_QUALIFICATION_REPORT.md is stale — " \
        "regenerate it with scripts/gen_performance_qualification.py --write"
