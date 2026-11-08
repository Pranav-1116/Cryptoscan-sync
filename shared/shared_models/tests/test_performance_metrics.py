"""Performance contract tests (docs/performance/01_PRODUCT_SPEC.md).

The §10 success criteria, test-proven at the contract level: defined
units from the taxonomy, missing telemetry never zero, idempotent
ingestion, bounded cardinality, tenant isolation, and aggregates that
match raw delivered measurements while naming their unknowns.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models.performance_metrics import (
    NO_VALUE_QUALITIES, PerformanceMetric, QualityStatus,
)
from shared_models.performance_taxonomy import (
    DEFINITIONS, DOMAINS, definition_for,
)
from shared_models.performance_store import (
    DUPLICATE, INSERTED, MetricRepository,
)

NOW = datetime.now(timezone.utc)


def _metric(metric_id="m-1", metric_name="network.rtt_ms", value=42.0,
            quality=QualityStatus.VALID, tenant="tenant_a", labels=None,
            observed=None):
    return PerformanceMetric(
        metric_id=metric_id, tenant_id=tenant, asset_id="asset-1",
        metric_name=metric_name, metric_type="gauge", metric_value=value,
        unit=definition_for(metric_name).unit, source_id="collector-1",
        observed_at=observed or (NOW - timedelta(minutes=5)),
        quality_status=quality, labels=labels or {})


def test_the_taxonomy_covers_the_eight_domains():
    domains = {d.domain for d in DEFINITIONS}
    assert domains == set(DOMAINS)
    for definition in DEFINITIONS:
        assert definition.unit, f"{definition.name} has no defined unit"


def test_a_metric_outside_the_taxonomy_is_refused_not_guessed():
    with pytest.raises(KeyError, match="not in the metric taxonomy"):
        definition_for("vendor.queue_length")


def test_missing_and_stale_telemetry_never_carry_a_value():
    for quality in NO_VALUE_QUALITIES:
        with pytest.raises(ValueError, match="never drawn as a zero"):
            _metric(value=0.0, quality=quality)
        row = _metric(value=None, quality=quality)
        assert row.value_or_unknown() is None, \
            "unknown telemetry is None, never a fabricated zero"


def test_ingestion_is_idempotent_with_accepted_identity():
    repo = MetricRepository()
    first = repo.accept(_metric())
    assert first == (INSERTED, "m-1")
    again = repo.accept(_metric(value=999.0))
    assert again == (DUPLICATE, "m-1"), \
        "a duplicate reports the accepted identity, never a second row"
    assert len(repo) == 1
    assert repo.get("tenant_a", "m-1").metric_value == 42.0, \
        "the accepted record stands unchanged"


def test_no_cross_tenant_metric_access():
    repo = MetricRepository()
    repo.accept(_metric(metric_id="m-a", tenant="tenant_a"))
    repo.accept(_metric(metric_id="m-b", tenant="tenant_b"))
    assert [r.metric_id for r in repo.query("tenant_a")] == ["m-a"]
    assert repo.get("tenant_a", "m-b") is None, \
        "a tenant never sees another tenant's metrics"


def test_aggregates_match_raw_measurements_and_name_their_unknowns():
    repo = MetricRepository()
    base = NOW - timedelta(minutes=10)
    repo.accept(_metric(metric_id="m-1", value=40.0, observed=base))
    repo.accept(_metric(metric_id="m-2", value=60.0,
                        observed=base + timedelta(minutes=1)))
    repo.accept(_metric(metric_id="m-3", value=None,
                        quality=QualityStatus.STALE,
                        observed=base + timedelta(minutes=2)))
    result = repo.aggregate("tenant_a", "network.rtt_ms",
                            window_start=NOW - timedelta(hours=1),
                            window_end=NOW)
    assert result.average == 50.0, "average over delivered values only"
    assert result.minimum == 40.0 and result.maximum == 60.0
    assert result.unknown_count == 1
    assert result.coverage.startswith("partial — 2/3"), result.coverage
    assert "never zero" in result.coverage
    all_unknown = MetricRepository()
    all_unknown.accept(_metric(metric_id="m-4", value=None,
                               quality=QualityStatus.MISSING))
    honest = all_unknown.aggregate("tenant_a", "network.rtt_ms",
                                   window_start=NOW - timedelta(hours=1),
                                   window_end=NOW)
    assert honest.average is None, \
        "no delivered values means unknown — never an average of zeros"


def test_cardinality_is_bounded_per_tenant():
    repo = MetricRepository()
    for i in range(256):
        repo.accept(_metric(metric_id=f"m-{i}", labels={"shard": f"v{i}"}))
    with pytest.raises(ValueError, match="bounded cardinality"):
        repo.accept(_metric(metric_id="m-over", labels={"shard": "v-new"}))
    assert repo.accept(_metric(metric_id="m-repeat",
                               labels={"shard": "v1"}))[0] == INSERTED, \
        "existing label values stay accepted"
