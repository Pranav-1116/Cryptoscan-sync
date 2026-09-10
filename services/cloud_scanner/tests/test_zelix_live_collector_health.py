"""ZELNX Live engine tests — live asset state engine (§7), event-triggered
deep discovery (§14), priority engine (§21), multi-region collectors
(§22), collector resilience (§23), scanner health (§24), and the full
unified multi-cloud flow (§2) end-to-end.
"""

from __future__ import annotations

import json


from cloud_scanner.enterprise.live.asset_state import (
    LiveCloudAssetStateEngine,
    action_for_event,
)
from cloud_scanner.enterprise.live.collector import (
    CollectorConfig,
    GlobalControlPlane,
    LocalEventQueue,
    RegionalCollector,
)
from cloud_scanner.enterprise.live.deep_discovery import (
    DeepDiscoveryPlanner,
)
from cloud_scanner.enterprise.live.event_schema import CloudEvent
from cloud_scanner.enterprise.live.health import (
    AUTH_FAILED,
    DEGRADED,
    EVENT_DELAYED,
    FAILED,
    HEALTHY,
    MAINTENANCE,
    RATE_LIMITED,
    UNREACHABLE,
    CloudScannerHealthMonitor,
)
from cloud_scanner.enterprise.live.priority import (
    CloudPriorityEngine,
    priority_from_score,
)
from zelix_live_fixtures import (
    AWS_CERT,
    AWS_KEY,
    make_live_engine,
)


def ev(event_type: str, resource_id: str, provider: str = "aws",
       timestamp: str = "2026-05-01T10:00:00Z", **meta) -> CloudEvent:
    return CloudEvent(event_id=f"{provider}-{event_type}-{resource_id}",
                      provider=provider, event_type=event_type, change_type="",
                      resource_id=resource_id, resource_type="test",
                      provider_metadata=meta, timestamp=timestamp)


# ------------------------------------------------------------------------- §7

class TestLiveAssetStateEngine:
    def test_first_seen_transition(self):
        engine = LiveCloudAssetStateEngine(clock=lambda: "2026-05-01T10:00:00Z")
        transition = engine.observe(ev("RESOURCE_DISCOVERED", AWS_KEY),
                                    state={"rotation_enabled": True})
        assert transition.transition_type == "FIRST_SEEN"
        asset = engine.get(AWS_KEY)
        assert asset.first_seen == "2026-05-01T10:00:00Z"
        assert asset.monitoring_status == "ACTIVE"

    def test_state_history_tracks_change(self):
        engine = LiveCloudAssetStateEngine(clock=lambda: "2026-05-01T10:00:00Z")
        engine.observe(ev("RESOURCE_DISCOVERED", AWS_KEY, timestamp="2026-05-01T08:00:00Z"),
                       state={"rotation_enabled": True})
        transition = engine.observe(ev("KEY_POLICY_CHANGED", AWS_KEY,
                                       timestamp="2026-05-01T09:00:00Z"),
                                    state={"rotation_enabled": False})
        assert transition.transition_type == "CHANGED"
        assert transition.change_fields == ["rotation_enabled"]
        asset = engine.get(AWS_KEY)
        assert asset.previous_state == {"rotation_enabled": True}
        assert asset.current_state == {"rotation_enabled": False}
        assert asset.last_change == "KEY_POLICY_CHANGED"
        assert len(asset.history) == 2

    def test_actions_for_key_events(self):
        assert action_for_event("KEY_ROTATED") == "CRYPTO_POLICY_REEVALUATION"
        assert action_for_event("KEY_POLICY_CHANGED") == "ACCESS_REVIEW"
        assert action_for_event("KEY_ALGORITHM_CHANGED") == "PQC_REEVALUATION"

    def test_remove_and_verifications(self):
        engine = LiveCloudAssetStateEngine(clock=lambda: "2026-05-01T10:00:00Z")
        engine.observe(ev("RESOURCE_DISCOVERED", AWS_KEY))
        engine.verify(AWS_KEY, kind="api", observed_at="2026-05-01T10:01:00Z")
        engine.verify(AWS_KEY, kind="crypto", observed_at="2026-05-01T10:02:00Z")
        asset = engine.get(AWS_KEY)
        assert asset.last_api_verification == "2026-05-01T10:01:00Z"
        assert asset.last_crypto_verification == "2026-05-01T10:02:00Z"
        engine.remove(ev("RESOURCE_REMOVED", AWS_KEY))
        assert engine.get(AWS_KEY).monitoring_status == "REMOVED"
        assert engine.count() == 0

    def test_reverified_transition(self):
        engine = LiveCloudAssetStateEngine(clock=lambda: "2026-05-01T10:00:00Z")
        engine.observe(ev("RESOURCE_DISCOVERED", AWS_KEY), state={"a": 1})
        transition = engine.observe(ev("RESOURCE_CHANGED", AWS_KEY), state={"a": 1})
        assert transition.transition_type == "REVERIFIED"

    def test_engine_asset_summary(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        summary = report.asset_state["summary"]
        distinct = len({e["resource_id"] for e in report.events})
        assert summary["assets"] == distinct
        assert summary["by_provider"]["aws"] >= 6


# ------------------------------------------------------------------------ §14

class TestDeepDiscoveryPlanner:
    def test_lb_cert_change_selects_cert_tls_pqc(self):
        planner = DeepDiscoveryPlanner()
        plan = planner.plan(ev("CERTIFICATE_CHANGED", AWS_CERT))
        assert "certificate_discovery" in plan.scanners
        assert "tls_discovery" in plan.scanners
        assert "dependency_graph" in plan.scanners
        assert "pqc_readiness" in plan.scanners
        assert plan.deep is True

    def test_routine_update_not_deep(self):
        planner = DeepDiscoveryPlanner()
        plan = planner.plan(ev("SERVERLESS_NEW_VERSION", "fn-1"))
        assert plan.deep is False
        assert "inventory" in plan.scanners

    def test_impact_resolver_adds_scanners(self):
        planner = DeepDiscoveryPlanner(
            impact_resolver=lambda event, change_type: {"scanners": ["network_crypto"]})
        plan = planner.plan(ev("ROUTE_CHANGE", "rt-1"))
        assert "network_crypto" in plan.scanners
        assert plan.deep is True

    def test_rationale_recorded(self):
        planner = DeepDiscoveryPlanner()
        plan = planner.plan(ev("NEW_PUBLIC_ENDPOINT", "ep-1"))
        assert "NEW_PUBLIC_ENDPOINT" in plan.rationale or "change_type" in plan.rationale


# ------------------------------------------------------------------------ §21

class TestPriorityEngine:
    def test_banking_api_high(self):
        engine = CloudPriorityEngine()
        evaluation = engine.evaluate(
            resource_id="api-bank-1",
            criticality="HIGH", exposure="public_internet",
            crypto_risk="HIGH", data_sensitivity="PII",
            compliance=["PCI_DSS"], change_frequency="frequent")
        assert evaluation.priority in ("HIGH", "CRITICAL")

    def test_dev_test_storage_lower(self):
        engine = CloudPriorityEngine()
        evaluation = engine.evaluate(
            resource_id="storage-dev-1",
            criticality="LOW", exposure="internal",
            crypto_risk="LOW", data_sensitivity="PUBLIC")
        assert evaluation.priority == "LOWER"

    def test_policy_configurable(self):
        engine = CloudPriorityEngine()
        engine.reweight("criticality", "STANDARD", 3)
        evaluation = engine.evaluate(resource_id="x", criticality="STANDARD",
                                     exposure="internal", crypto_risk="LOW",
                                     data_sensitivity="PUBLIC")
        assert evaluation.priority != "LOWER"

    def test_priority_bands(self):
        assert priority_from_score(10) == "CRITICAL"
        assert priority_from_score(7) == "HIGH"
        assert priority_from_score(4) == "MEDIUM"
        assert priority_from_score(2) == "LOW"
        assert priority_from_score(0) == "LOWER"


# ------------------------------------------------------------------------ §22

class TestMultiRegionCollectors:
    def test_global_control_plane_regions(self):
        plane = GlobalControlPlane()
        for region, collector_id in (("UAE", "collector-uae"), ("EU", "collector-eu"),
                                     ("USA", "collector-usa")):
            plane.register(RegionalCollector(
                CollectorConfig(collector_id=collector_id, region=region)))
        summary = plane.summary()
        assert summary["collectors"] == 3
        assert summary["by_region"] == {"UAE": 1, "EU": 1, "USA": 1}

    def test_collector_local_processing(self):
        collector = RegionalCollector(
            CollectorConfig(collector_id="c-uae", region="UAE", provider="aws"),
            process=lambda event: {"ok": True})
        stats = collector.ingest([ev("KEY_ROTATED", AWS_KEY)])
        assert stats["pushed"] == 1
        result = collector.drain(sync=False)
        assert result["processed"] == 1
        assert result["queue_depth"] == 0

    def test_temporary_disconnect_keeps_queue(self):
        collected = []
        collector = RegionalCollector(
            CollectorConfig(collector_id="c-eu", region="EU"),
            process=lambda event: {"ok": True},
            sync=lambda outcomes: collected.extend(outcomes))
        collector.ingest([ev("KEY_ROTATED", AWS_KEY)])
        collector.disconnect()
        assert collector.online is False
        result = collector.drain(sync=True)
        # offline → results stay local, nothing synced
        assert result["synced"] == 0
        collector.reconnect()
        result = collector.drain(sync=True)
        assert result["synced"] >= 1

    def test_control_plane_receive_sync(self):
        plane = GlobalControlPlane()
        assert plane.receive_sync("c-usa", [{"event_id": "e1"}, {"event_id": "e2"}]) == 2
        assert plane.summary()["sync_events_received"] == 2


# ------------------------------------------------------------------------ §23

class TestCollectorResilience:
    def test_duplicate_detection_idempotency(self):
        queue = LocalEventQueue()
        first = queue.push([ev("KEY_ROTATED", AWS_KEY)])
        second = queue.push([ev("KEY_ROTATED", AWS_KEY)])
        assert first["pushed"] == 1
        assert second["duplicates"] == 1
        assert queue.depth() == 1

    def test_retry_policy(self):
        attempts = []
        def flaky(event):
            attempts.append(event.event_id)
            if len(attempts) < 3:
                raise RuntimeError("transient")
            return "done"
        collector = RegionalCollector(
            CollectorConfig(collector_id="c-retry", region="EU", max_retries=3),
            process=flaky)
        collector.ingest([ev("KEY_ROTATED", AWS_KEY)])
        result = collector.drain(sync=False)
        assert result["processed"] == 1
        assert len(attempts) == 3  # retried until success

    def test_dead_letter_after_retries_exhausted(self):
        collector = RegionalCollector(
            CollectorConfig(collector_id="c-dlq", region="EU", max_retries=2),
            process=lambda event: (_ for _ in ()).throw(RuntimeError("permanent")))
        collector.ingest([ev("KEY_ROTATED", AWS_KEY)])
        result = collector.drain(sync=False)
        assert result["dead_lettered"] == 1
        assert collector._queue.dead_letter_depth() == 1

    def test_backpressure_sheds_to_dead_letter(self):
        queue = LocalEventQueue(max_depth=2)
        events = [ev("RESOURCE_DISCOVERED", f"r-{i}", timestamp=f"2026-05-01T0{i}:00:00Z")
                  for i in range(5)]
        stats = queue.push(events)
        assert stats["pushed"] == 2
        assert stats["dead_lettered"] == 3
        assert queue.dead_letter_depth() == 3
        assert queue.retry_dead_letter() == 3
        assert queue.depth() == 5

    def test_checkpointing(self):
        collector = RegionalCollector(
            CollectorConfig(collector_id="c-cp", region="USA"),
            process=lambda event: None)
        collector.ingest([ev("KEY_ROTATED", AWS_KEY)])
        collector.drain(sync=False)
        checkpoint = collector.last_checkpoint()
        assert checkpoint["processed_total"] == 1
        assert "queue_depth" in checkpoint

    def test_durable_queue_via_persist(self):
        persisted: list = []
        queue = LocalEventQueue(persist=lambda rows: persisted.append(list(rows)))
        queue.push([ev("KEY_ROTATED", AWS_KEY)])
        assert persisted and persisted[0][0]["event_id"] == "aws-KEY_ROTATED-" + AWS_KEY


# ------------------------------------------------------------------------ §24

class TestCloudScannerHealth:
    def test_all_states_reachable(self):
        monitor = CloudScannerHealthMonitor()
        cases = [
            (dict(), HEALTHY),
            (dict(api_errors=True), DEGRADED),
            (dict(rate_limited=True), RATE_LIMITED),
            (dict(auth_ok=False), AUTH_FAILED),
            (dict(event_lag_ok=False), EVENT_DELAYED),
            (dict(heartbeat_ok=False), UNREACHABLE),
            (dict(plugins_healthy=False), FAILED),
            (dict(maintenance=True), MAINTENANCE),
        ]
        for i, (signals, expected) in enumerate(cases):
            health = monitor.snapshot(collector_id=f"c-{i}", **signals)
            assert health.state == expected, signals

    def test_rate_limited_state_wins_over_errors(self):
        monitor = CloudScannerHealthMonitor()
        health = monitor.snapshot(collector_id="c-1", rate_limited=True, api_errors=True)
        assert health.state == RATE_LIMITED

    def test_health_score_drops(self):
        monitor = CloudScannerHealthMonitor()
        healthy = monitor.snapshot(collector_id="c-ok")
        degraded = monitor.snapshot(collector_id="c-bad", rate_limited=True,
                                    api_errors=True, plugins_healthy=False)
        assert healthy.score == 100.0
        assert degraded.score < healthy.score

    def test_summary_by_state(self):
        monitor = CloudScannerHealthMonitor()
        monitor.snapshot(collector_id="c1")
        monitor.snapshot(collector_id="c2", auth_ok=False)
        summary = monitor.summary()
        assert summary["collectors"] == 2
        assert summary["by_state"][HEALTHY] == 1
        assert summary["by_state"][AUTH_FAILED] == 1


# ------------------------------------------------------------------------- §2

class TestUnifiedMultiCloudFlowIntegration:
    def test_full_flow_end_to_end(self):
        """Provider events → universal events → classification → targeted
        rescan → live state → live CBOM → dependency graph → PQC."""
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert len(report.events) >= 13
        # classification
        change_types = {c["change_type"] for c in report.classifications}
        assert change_types >= {"NEW_RESOURCE", "CRYPTO_CHANGE", "NETWORK_CHANGE",
                                "IDENTITY_CHANGE", "UPDATED_RESOURCE"}
        # targeted rescan (deep discovery plans)
        assert report.deep_discovery_plans
        # live state
        assert report.asset_state["summary"]["active"] >= 13
        # live CBOM
        assert report.cbom["materialized"]["counts"]["components"] >= 10
        # dependency graph
        assert report.dependency_graph["by_provider"]
        # PQC re-evaluation
        assert len(report.pqc["evaluations"]) >= 3
        # evidence chain verified
        assert report.evidence_verified is True

    def test_aws_kms_policy_change_blast_radius(self):
        """§8 example: KMS POLICY CHANGED → identify key → find
        dependencies → update crypto graph → update risk."""
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        key_impacts = [i for i in report.key_impacts if i["event_type"] == "KEY_POLICY_CHANGED"]
        assert key_impacts
        impact = key_impacts[0]
        assert impact["applications"]
        assert impact["datasets"]
        assert impact["severity"] == "HIGH"

    def test_certificate_change_cbom_update(self):
        """§9 example: KEY VAULT CERTIFICATE CHANGED → consumers → blast
        radius → live CBOM update."""
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        cert_changes = [c for c in report.certificate_changes if c["provider"] == "azure"]
        assert cert_changes
        assert cert_changes[0]["change_kind"] == "CREATED"

    def test_cross_provider_certificate_blast_radius(self):
        """§15 example: AWS certificate change must find Azure consumers
        and GCP dependencies with a global blast radius."""
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        aws_cert_impacts = [i for i in report.cross_cloud["impacts"]
                            if i["resource_id"] == AWS_CERT]
        assert aws_cert_impacts
        impact = aws_cert_impacts[0]
        assert impact["impact_by_provider"].get("azure")
        assert impact["impact_by_provider"].get("gcp")
        assert impact["total_impacted"] >= 5

    def test_two_cycles_keep_history(self):
        engine = make_live_engine()
        engine.cycle(cycle_number=1)
        engine.cycle(cycle_number=2)
        assert engine.assets.count() >= 13
        # a key observed twice keeps full evidence history
        asset = engine.assets.get(AWS_KEY)
        assert len(asset.evidence_history) >= 2

    def test_events_never_retrieve_key_material(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        serialized = str(report.to_dict())
        assert "PRIVATE-KEY" not in serialized
        assert "secret_material" not in serialized


# ------------------------------------------------------------- 24/7 loop

class TestLiveMonitoringLoop:
    def test_run_once(self):
        from cloud_scanner.enterprise.live.loop import LiveMonitoringLoop

        engine = make_live_engine()
        loop = LiveMonitoringLoop(engine, max_cycles=1)
        report = loop.run_once()
        assert len(loop.reports()) == 1
        assert report.cycle == 1

    def test_run_forever_respects_max_cycles(self):
        from cloud_scanner.enterprise.live.loop import LiveMonitoringLoop

        engine = make_live_engine()
        loop = LiveMonitoringLoop(engine, max_cycles=3,
                                  sleeper=lambda seconds: None)
        loop.run_forever()
        assert len(loop.reports()) == 3
        assert loop.latest().cycle == 3
        assert engine.events_processed >= 13 * 3

    def test_on_report_callback(self):
        from cloud_scanner.enterprise.live.loop import LiveMonitoringLoop

        seen = []
        engine = make_live_engine()
        loop = LiveMonitoringLoop(engine, max_cycles=2,
                                  sleeper=lambda seconds: None,
                                  on_report=lambda report: seen.append(report.cycle))
        loop.run_forever()
        assert seen == [1, 2]


# ------------------------------------------------------------------ CLI

class TestLiveCLI:
    def test_cli_zelix_live_demo(self, tmp_path):
        from cloud_scanner.main import main

        out = tmp_path / "live.json"
        code = main(["--zelix-live", "--zelix-live-cycles", "1", "-o", str(out)])
        assert code == 0
        report = json.loads(out.read_text())
        assert report["read_only"] is True
        assert report["evidence_verified"] is True
        assert len(report["events"]) >= 5
        assert report["collectors"]["collectors"][0]["collector_id"] == "collector-uae"

    def test_cli_zelix_live_events_file(self, tmp_path):
        from cloud_scanner.main import main

        events = tmp_path / "events.json"
        payload = json.dumps([
            {"event_id": "cli-1", "provider": "aws", "event_name": "kms:RotateKeyOnDemand",
             "resource_id": "k-cli-1", "timestamp": "2026-08-30T10:00:00Z"},
            {"event_id": "cli-2", "provider": "azure",
             "resource_type": "Microsoft.KeyVault/vaults/keys",
             "resourceId": "az-key-1", "timestamp": "2026-08-30T10:01:00Z"},
        ])
        events.write_text(payload)
        out = tmp_path / "live2.json"
        code = main(["--zelix-live", "--zelix-live-events", str(events),
                     "--zelix-live-region", "EU", "-o", str(out)])
        assert code == 0
        report = json.loads(out.read_text())
        assert len(report["events"]) == 2
        assert report["collectors"]["collectors"][0]["collector_id"] == "collector-eu"
