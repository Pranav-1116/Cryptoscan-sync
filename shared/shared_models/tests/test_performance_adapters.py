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
    translate_cadvisor, translate_kube_state_metrics, translate_snmp,
    translate_windows_exporter,
)
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
