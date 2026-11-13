"""Collector adapter and backpressure tests (docs/performance/
01_PRODUCT_SPEC.md §3, §4, §9).

Acceptance rows: every documented exporter adapter maps through its
documented table and refuses what it cannot map; rate-derived counters
need two snapshots; SNMP unit conversions are documented, never
guessed; bounded queues refuse and count — they never silently drop.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shared_models.performance_backpressure import BoundedIngestQueue
from shared_models.performance_collectors import (
    translate_cadvisor, translate_kube_state_metrics, translate_node_exporter,
    translate_otlp, translate_postgres_exporter, translate_snmp,
    translate_windows_exporter,
)
from shared_models.performance_metrics import QualityStatus
from shared_models.performance_corpus import generate_corpus
from shared_models.performance_taxonomy import DEFINITIONS, definition_for

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)


def test_cadvisor_maps_memory_and_refuses_rate_derived_cpu():
    result = translate_cadvisor(
        {"metrics": {
            "container_memory_working_set_bytes": [
                {"value": 104857600.0, "labels": {"pod": "api-1"}}],
            "container_cpu_usage_seconds_total": [
                {"value": 12.5, "labels": {}}],
            "container_unknown_thing": [{"value": 1.0, "labels": {}}]}},
        asset_id="asset-001", tenant_id="tenant_001", source_id="cadvisor-1",
        observed_at=NOW)
    assert [m.metric_name for m in result.metrics] == ["container.memory_bytes"]
    assert result.metrics[0].unit == "bytes"
    reasons = {r["raw_family"]: r["reason"] for r in result.refused}
    assert "two snapshots" in reasons["container_cpu_usage_seconds_total"]
    assert "never guessed" in reasons["container_unknown_thing"]


def test_kube_state_maps_restarts_and_phases_only():
    result = translate_kube_state_metrics(
        {"metrics": {
            "kube_pod_container_status_restarts_total": [
                {"value": 2.0, "labels": {"pod": "api-1"}}],
            "kube_pod_status_phase": [{"value": 1.0, "labels": {}}],
            "kube_deployment_spec_replicas": [{"value": 3.0, "labels": {}}]}},
        asset_id="asset-001", tenant_id="tenant_001", source_id="kube-1",
        observed_at=NOW)
    names = {m.metric_name for m in result.metrics}
    assert names == {"k8s.pod_restarts", "process.health"}
    assert result.refused_count == 1
    assert "never guessed" in result.refused[0]["reason"]


def test_windows_exporter_maps_disk_gauges_and_refuses_counters():
    result = translate_windows_exporter(
        {"metrics": {
            "windows_logical_disk_size_bytes": [
                {"value": 500_000_000_000.0, "labels": {"volume": "C:"}}],
            "windows_logical_disk_free_bytes": [
                {"value": 280_000_000_000.0, "labels": {"volume": "C:"}}],
            "windows_cpu_time_total": [{"value": 100.0, "labels": {}}]}},
        asset_id="asset-001", tenant_id="tenant_001", source_id="win-1",
        observed_at=NOW)
    names = {m.metric_name for m in result.metrics}
    assert names == {"storage.capacity_bytes", "storage.available_bytes"}
    assert "two snapshots" in result.refused[0]["reason"]


def test_snmp_conversions_are_documented_and_counters_refused():
    result = translate_snmp(
        {"metrics": {
            "ifSpeed": [{"value": 10_000_000_000.0, "labels": {"if": "eth0"}}],
            "ifOperStatus": [{"value": 1.0, "labels": {"if": "eth0"}}],
            "ifHCInOctets": [{"value": 5000.0, "labels": {}}]}},
        asset_id="asset-001", tenant_id="tenant_001", source_id="snmp-1",
        observed_at=NOW)
    by_name = {m.metric_name: m for m in result.metrics}
    assert by_name["network.bandwidth_mbps"].metric_value == 10_000.0, \
        "ifSpeed is bits/sec; the metric unit is Mbps — the divisor is " \
        "documented, never guessed"
    assert by_name["network.bandwidth_mbps"].unit == "Mbps"
    assert by_name["network.tunnel_health"].metric_value == 1.0
    assert "throughput is never guessed" in result.refused[0]["reason"]


def _payload(**families):
    return {"metrics": {name: [{"value": value, "labels": labels}]
                        for name, (value, labels) in families.items()}}


def test_node_counters_require_two_snapshots_and_correct_rate_units():
    current = _payload(
        node_disk_read_bytes_total=(11_000_000, {"device": "sda"}),
        node_disk_written_bytes_total=(20_000_000, {"device": "sda"}),
        node_disk_reads_completed_total=(120, {"device": "sda"}),
        node_disk_writes_completed_total=(50, {"device": "sda"}),
        node_memory_MemTotal_bytes=(1000, {}),
        node_memory_MemAvailable_bytes=(250, {}),
        node_filesystem_size_bytes=(9000, {"mountpoint": "/data"}),
    )
    previous = _payload(
        node_disk_read_bytes_total=(10_000_000, {"device": "sda"}),
        node_disk_written_bytes_total=(16_000_000, {"device": "sda"}),
        node_disk_reads_completed_total=(100, {"device": "sda"}),
        node_disk_writes_completed_total=(40, {"device": "sda"}),
    )
    kw = {"asset_id": "host-a", "tenant_id": "bank-a", "source_id": "node-1",
          "observed_at": NOW}
    first = translate_node_exporter(current, **kw)
    assert all(m.metric_value is None and m.quality_status == QualityStatus.MISSING
               for m in first.metrics if m.metric_name in ("disk.iops", "disk.throughput_mbps"))
    assert "storage.capacity_bytes" in {m.metric_name for m in first.metrics}
    assert sum(m.metric_name == "storage.capacity_bytes" for m in first.metrics) == 1, \
        "RAM is not filesystem capacity"
    assert next(m for m in first.metrics if m.metric_name == "ram.utilization_pct").metric_value == 75.0
    measured = translate_node_exporter(current, previous=previous,
                                       interval_seconds=2, **kw)
    values = {(m.metric_name, m.labels.get("direction")): m.metric_value
              for m in measured.metrics if m.metric_name in ("disk.iops", "disk.throughput_mbps")}
    assert values == {("disk.throughput_mbps", "read"): 0.5,
                      ("disk.throughput_mbps", "write"): 2.0,
                      ("disk.iops", "read"): 10.0,
                      ("disk.iops", "write"): 5.0}
    assert all(m.unit == "MB/s" for m in measured.metrics if m.metric_name == "disk.throughput_mbps")


def test_ambiguous_previous_counter_sample_does_not_create_a_rate():
    current = _payload(node_disk_read_bytes_total=(130, {"device": "sda"}))
    previous = {"metrics": {"node_disk_read_bytes_total": [
        {"value": 100, "labels": {"device": "sda"}},
        {"value": 110, "labels": {"device": "sda"}}]}}
    result = translate_node_exporter(current, previous=previous,
        interval_seconds=10, asset_id="host-a", tenant_id="bank-a",
        source_id="node-1", observed_at=NOW)
    assert result.metrics[0].metric_value is None
    assert result.metrics[0].quality_status == QualityStatus.MISSING
    assert any("ambiguous" in row["reason"] for row in result.refused)


def test_node_counter_reset_or_partial_cpu_modes_never_report_use():
    kw = {"asset_id": "host-a", "tenant_id": "bank-a", "source_id": "node-1",
          "observed_at": NOW, "interval_seconds": 60}
    prior = _payload(node_disk_read_bytes_total=(100, {"device": "sda"}))
    reset = translate_node_exporter(
        _payload(node_disk_read_bytes_total=(5, {"device": "sda"})),
        previous=prior, **kw)
    assert reset.metrics[0].quality_status == QualityStatus.STALE
    assert reset.metrics[0].metric_value is None
    now = {"metrics": {"node_cpu_seconds_total": [
        {"value": 110, "labels": {"cpu": "0", "mode": "idle"}},
        {"value": 20, "labels": {"cpu": "0", "mode": "user"}}]}}
    before = {"metrics": {"node_cpu_seconds_total": [
        {"value": 100, "labels": {"cpu": "0", "mode": "idle"}},
        {"value": 40, "labels": {"cpu": "0", "mode": "user"}}]}}
    cpu = translate_node_exporter(now, previous=before, **kw)
    assert cpu.metrics[0].quality_status == QualityStatus.STALE
    assert cpu.metrics[0].metric_value is None


def test_postgres_does_not_turn_capacity_or_tuples_into_idle_or_queries():
    kw = {"asset_id": "db-a", "tenant_id": "bank-a", "source_id": "pg-1",
          "observed_at": NOW, "interval_seconds": 2}
    current = _payload(
        pg_stat_activity_count=(7, {"state": "active"}),
        pg_settings_max_connections=(100, {}),
        pg_stat_database_tup_returned=(1000, {"datname": "payments"}),
        pg_stat_database_xact_commit=(110, {"datname": "payments"}),
        pg_stat_database_xact_rollback=(20, {"datname": "payments"}),
        pg_stat_database_blks_hit=(90, {"datname": "payments"}),
        pg_stat_database_blks_read=(10, {"datname": "payments"}),
    )
    previous = _payload(
        pg_stat_database_xact_commit=(100, {"datname": "payments"}),
        pg_stat_database_xact_rollback=(10, {"datname": "payments"}),
        pg_stat_database_blks_hit=(80, {"datname": "payments"}),
        pg_stat_database_blks_read=(5, {"datname": "payments"}),
    )
    first = translate_postgres_exporter(current, **kw)
    assert {m.metric_name: m.metric_value for m in first.metrics} == {
        "db.connections_active": 7.0, "db.transactions_per_sec": None,
        "db.cache_hit_ratio": None}
    measured = translate_postgres_exporter(current, previous=previous, **kw)
    values = {m.metric_name: m.metric_value for m in measured.metrics}
    assert values == {"db.connections_active": 7.0,
                      "db.transactions_per_sec": 10.0,
                      "db.cache_hit_ratio": 0.666667}
    reasons = " ".join(r["reason"] for r in measured.refused)
    assert "capacity is not idle" in reasons and "tuples returned are not queries" in reasons
    unlabeled = translate_postgres_exporter(_payload(pg_stat_activity_count=(5, {})), **kw)
    assert unlabeled.metrics == []
    assert "unlabeled count" in unlabeled.refused[0]["reason"]


def test_long_source_ids_do_not_collapse_different_metrics():
    result = translate_node_exporter(_payload(
        node_filesystem_size_bytes=(100, {"mountpoint": "/a"}),
        node_filesystem_avail_bytes=(40, {"mountpoint": "/a"})),
        asset_id="host-a", tenant_id="bank-a", source_id="s" * 120,
        observed_at=NOW)
    assert len(result.metrics) == 2
    assert len({m.metric_id for m in result.metrics}) == 2
    assert all(len(m.metric_id) <= 64 for m in result.metrics)
    labels = "x" * 90
    different = translate_node_exporter({"metrics": {
        "node_filesystem_size_bytes": [
            {"value": 100, "labels": {"mountpoint": labels + "a"}},
            {"value": 100, "labels": {"mountpoint": labels + "b"}},
        ]}}, asset_id="host-a", tenant_id="bank-a", source_id="node-1",
        observed_at=NOW)
    assert len({m.metric_id for m in different.metrics}) == 2


def test_identical_exporter_samples_are_scoped_to_bank_and_asset():
    payload = _payload(node_filesystem_size_bytes=(100, {"mountpoint": "/a"}))
    def ids(tenant, asset):
        result = translate_node_exporter(payload, asset_id=asset,
                                         tenant_id=tenant, source_id="node-exporter",
                                         observed_at=NOW)
        return [metric.metric_id for metric in result.metrics]
    assert ids("bank-a", "host-1") == ids("bank-a", "host-1")
    assert len({ids("bank-a", "host-1")[0], ids("bank-b", "host-1")[0],
                ids("bank-a", "host-2")[0]}) == 3


def test_otlp_histogram_is_not_p50_and_cpu_fraction_is_converted():
    translated = translate_otlp(_payload(
        **{"http.server.request.duration": (0.3, {}),
           "http.server.active_requests": (3, {}),
           "http.server.error.rate": (0.01, {}),
           "process.cpu.utilization": (0.25, {}),
           "process.memory.usage": (2048, {})}),
        asset_id="svc-a", tenant_id="bank-a", source_id="otlp-1", observed_at=NOW)
    values = {m.metric_name: m.metric_value for m in translated.metrics}
    assert values == {"api.concurrent_requests": 3.0,
                      "cpu.utilization_pct": 25.0,
                      "container.memory_bytes": 2048.0}
    assert "p50" in " ".join(r["reason"] for r in translated.refused)
    assert "percentage" in " ".join(r["reason"] for r in translated.refused)
    invalid = translate_otlp(_payload(**{"process.cpu.utilization": (1.5, {})}),
        asset_id="svc-a", tenant_id="bank-a", source_id="otlp-1", observed_at=NOW)
    assert invalid.metrics == [] and invalid.refused_count == 1


def test_a_bounded_queue_refuses_and_counts_never_silently_drops():
    queue = BoundedIngestQueue(max_pending=2)
    rows = generate_corpus(5)
    report = queue.offer_many(rows)
    assert report["offered"] == 2 and report["refused"] == 3
    assert queue.pending == 2
    assert queue.refused_count == 3
    drained = queue.drain()
    assert len(drained) == 2 and queue.pending == 0
    assert "never silently" in queue.as_dict()["note"]
    with pytest.raises(ValueError, match="positive"):
        BoundedIngestQueue(max_pending=0)


def test_every_taxonomy_metric_is_a_complete_definition():
    names = [d.name for d in DEFINITIONS]
    assert len(names) == len(set(names)), "a definition registers once"
    # 76 -> 80: the taxonomy gains the binary-intelligence scanner
    # telemetry family (docs/binary-intelligence/01_PRODUCT_SPEC.md
    # §13/§17 — measurements of the SCANNER under the cryptography
    # domain; counts of recorded findings, never of running
    # cryptography; coverage is not confidence).
    assert len(names) == 80, \
        f"the taxonomy covers §2 A–H plus binary scanner telemetry; expected 80 metrics, found {len(names)}"
    for definition in DEFINITIONS:
        assert definition.unit, f"{definition.name} has no unit"
        assert definition.what_it_tells, f"{definition.name} has no meaning"
        assert definition_for(definition.name) is definition
