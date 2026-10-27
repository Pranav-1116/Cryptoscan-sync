"""ZELNX Live engine tests — live drift (§13), cross-cloud blast radius
(§15), event-sourced live CBOM with historical reconstruction (§18),
tamper-evident evidence chain (§19), intelligent alert correlation (§20).
"""

from __future__ import annotations


from cloud_scanner.enterprise.live.alerts import (
    AlertCorrelationEngine,
    default_correlation_key,
)
from cloud_scanner.enterprise.live.cbom import (
    LiveEventSourcedCBOM,
    cbom_kind_for_event,
)
from cloud_scanner.enterprise.live.deep_discovery import CrossCloudMonitor
from cloud_scanner.enterprise.live.drift import (
    ACCESS_DRIFT,
    APPROVED,
    CRITICAL_DRIFT,
    CRYPTO_DRIFT,
    EXPECTED,
    LiveDriftDetector,
    NO_CHANGE,
    classify_live_drift,
)
from cloud_scanner.enterprise.live.event_schema import CloudEvent
from cloud_scanner.enterprise.live.evidence import GENESIS_HASH, LiveEvidenceChain
from zelix_live_fixtures import (
    AWS_CERT,
    AWS_KEY,
    AZURE_CERT,
    GCP_CERT,
    GCP_KEY,
    make_live_engine,
)


def ev(event_type: str, resource_id: str, provider: str = "aws",
       timestamp: str = "2026-05-01T10:00:00Z", **meta) -> CloudEvent:
    return CloudEvent(event_id=f"{provider}-{event_type}-{resource_id}",
                      provider=provider, event_type=event_type, change_type="",
                      resource_id=resource_id, resource_type="test",
                      provider_metadata=meta, timestamp=timestamp)


# ------------------------------------------------------------------------ §13

class TestLiveDrift:
    def test_classification_matrix(self):
        assert classify_live_drift({}, {})[0] == NO_CHANGE
        assert classify_live_drift({"encryption_enabled": True},
                                   {"encryption_enabled": True})[0] == NO_CHANGE
        cls, kind, _ = classify_live_drift({"encryption_enabled": True},
                                           {"encryption_enabled": False})
        assert cls == CRITICAL_DRIFT
        assert kind == "ENCRYPTION_DRIFT"
        cls, kind, _ = classify_live_drift({"algorithm": "RSA-2048"},
                                           {"algorithm": "ML-KEM-768"})
        assert cls == CRYPTO_DRIFT
        assert kind == "CRYPTO_ALGORITHM_DRIFT"
        cls, kind, _ = classify_live_drift({"permissions": ["read"]},
                                           {"permissions": ["read", "decrypt"]})
        assert cls == ACCESS_DRIFT
        assert kind == "ACCESS_DRIFT"

    def test_approved_and_expected(self):
        cls, _, _ = classify_live_drift({"a": 1}, {"a": 2}, approved=True)
        assert cls == APPROVED
        cls, _, _ = classify_live_drift({"a": 1}, {"a": 2}, expected_change=True)
        assert cls == EXPECTED

    def test_detector_skips_no_baseline(self):
        detector = LiveDriftDetector(
            expected_state={AWS_KEY: {"rotation_enabled": True, "provider": "aws"}},
            clock=lambda: "2026-05-01T10:00:00Z")
        result = detector.check({
            AWS_KEY: {"rotation_enabled": False, "provider": "aws"},
            "other-resource": {"provider": "aws"},  # no baseline → skipped
        })
        assert len(result.observations) == 1
        assert result.observations[0].drift_classification == CRITICAL_DRIFT
        assert result.alerts()[0].alert is True

    def test_certificate_algorithm_change_is_crypto_drift(self):
        detector = LiveDriftDetector(
            expected_state={AWS_CERT: {"certificate_algorithm": "RSA-2048"}})
        result = detector.check({AWS_CERT: {"certificate_algorithm": "ML-KEM-768"}})
        assert result.observations[0].drift_classification == CRYPTO_DRIFT

    def test_engine_drift_section_present(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert "by_classification" in report.drift


# ------------------------------------------------------------------------ §15

class TestCrossCloudMonitor:
    def test_aws_cert_change_finds_azure_and_gcp(self):
        monitor = CrossCloudMonitor(find_cross_cloud_impact=lambda rid: {
            "aws": ["payments-api", "lb-api"],
            "azure": [AZURE_CERT, "appgw-pay"],
            "gcp": [GCP_CERT],
        })
        impact = monitor.watch(ev("CERTIFICATE_REPLACED", AWS_CERT))
        assert impact.source_provider == "aws"
        assert len(impact.impact_by_provider["azure"]) == 2
        assert impact.total_impacted == 5

    def test_engine_cross_cloud_summary(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert report.cross_cloud["total_resources_impacted"] >= 1
        assert report.cross_cloud["impacts"]


# ------------------------------------------------------------------------ §18

class TestEventSourcedCBOM:
    def test_kinds_mapping(self):
        assert cbom_kind_for_event("KEY_CHANGED") == "key"
        assert cbom_kind_for_event("CERTIFICATE_CHANGED") == "certificate"
        assert cbom_kind_for_event("TLS_TERMINATION_CHANGE") == "tls_endpoint"
        assert cbom_kind_for_event("ROUTE_CHANGE") == "network_asset"
        assert cbom_kind_for_event("DEPENDENCY_CHANGED") == "dependency"

    def test_live_cbom_ingest(self):
        cbom = LiveEventSourcedCBOM()
        cbom.ingest(ev("RESOURCE_DISCOVERED", AWS_KEY, timestamp="2026-05-01T08:00:00Z"),
                    crypto_properties={"algorithm": "SYMMETRIC_DEFAULT"})
        cbom.ingest(ev("KEY_CHANGED", AWS_KEY, timestamp="2026-05-01T09:00:00Z"))
        cbom.ingest(ev("CERTIFICATE_CHANGED", AWS_CERT, timestamp="2026-05-01T09:30:00Z"))
        assert cbom.event_count() == 3
        assert len(cbom.components()) == 2
        summary = cbom.summary()
        assert summary["components"] == 2
        # the key was discovered then mutated → CHANGED; the cert is ACTIVE
        assert summary["active"] == 1
        assert summary["changed"] == 1
        key = [c for c in cbom.components() if c.component_id == AWS_KEY][0]
        assert len(key.events) == 2
        assert key.crypto_properties["algorithm"] == "SYMMETRIC_DEFAULT"

    def test_resource_removed(self):
        cbom = LiveEventSourcedCBOM()
        cbom.ingest(ev("RESOURCE_DISCOVERED", AWS_KEY, timestamp="2026-05-01T08:00:00Z"))
        cbom.ingest(ev("RESOURCE_REMOVED", AWS_KEY, timestamp="2026-05-01T09:00:00Z"))
        assert cbom.components()[0].state == "REMOVED"
        materialized = cbom.materialize(at="2026-05-01T10:00:00Z")
        assert materialized.counts()["components"] == 0

    def test_historical_reconstruction(self):
        """SHOW CLOUD CBOM AT 2026-05-01 10:00 (§18)."""
        cbom = LiveEventSourcedCBOM()
        cbom.ingest(ev("RESOURCE_DISCOVERED", AWS_KEY, timestamp="2026-05-01T08:00:00Z"))
        cbom.ingest(ev("RESOURCE_DISCOVERED", AWS_CERT, timestamp="2026-05-01T09:00:00Z"))
        cbom.ingest(ev("RESOURCE_REMOVED", AWS_CERT, timestamp="2026-05-01T09:30:00Z"))
        cbom.ingest(ev("RESOURCE_DISCOVERED", GCP_KEY, provider="gcp",
                       timestamp="2026-05-01T09:45:00Z"))
        # at 09:00 the AWS cert still existed
        at_0900 = cbom.reconstruct(at="2026-05-01T09:00:00Z")
        ids_0900 = {c.component_id for c in at_0900.components}
        assert AWS_KEY in ids_0900 and AWS_CERT in ids_0900
        # at 10:00 the cert is gone, GCP key is present
        at_1000 = cbom.reconstruct(at="2026-05-01T10:00:00Z")
        ids_1000 = {c.component_id for c in at_1000.components}
        assert AWS_CERT not in ids_1000
        assert GCP_KEY in ids_1000
        assert AWS_KEY in ids_1000

    def test_engine_show_cloud_cbom_at(self):
        engine = make_live_engine()
        engine.cycle(cycle_number=1)
        snapshot = engine.show_cloud_cbom_at("2026-05-01T10:00:00Z")
        assert snapshot.materialized_at == "2026-05-01T10:00:00Z"


# ------------------------------------------------------------------------ §19

class TestEvidenceChain:
    def test_genesis_and_chaining(self):
        chain = LiveEvidenceChain(clock=lambda: "2026-05-01T10:00:00Z")
        r1 = chain.record(provider="aws", event_id="e1", resource_id=AWS_KEY,
                          event_type="KEY_ROTATED", source="events",
                          observation={"rotation": True})
        assert r1.previous_hash == GENESIS_HASH
        r2 = chain.record(provider="azure", event_id="e2", resource_id=AZURE_CERT,
                          event_type="CERTIFICATE_CHANGED", source="events")
        assert r2.previous_hash == r1.record_hash
        assert chain.count() == 2
        assert chain.verify_chain() == (True, "chain-valid")

    def test_tamper_breaks_chain(self):
        chain = LiveEvidenceChain(clock=lambda: "2026-05-01T10:00:00Z")
        chain.record(event_id="e1", resource_id="r1", observation={"a": 1})
        chain.record(event_id="e2", resource_id="r2", observation={"b": 2})
        chain.tamper("ev-000001")
        valid, reason = chain.verify_chain()
        assert valid is False
        assert "hash mismatch" in reason

    def test_engine_evidence_verified(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert report.evidence_verified is True
        assert report.evidence["records"]
        assert report.evidence["chain_valid"] is True
        # provider event + API verification recorded per event
        first = report.evidence["records"][0]
        assert first["api_verification"]["verified"] is True

    def test_hash_function(self):
        from cloud_scanner.enterprise.live.evidence import sha256
        assert len(sha256("x")) == 64
        assert sha256("a") == sha256("a")
        assert sha256("a") != sha256("b")


# ------------------------------------------------------------------------ §20

class TestAlertCorrelation:
    def test_root_ca_change_single_incident(self):
        events = []
        for i in range(6):
            events.append(ev("CERTIFICATE_RENEWED", f"cert-{i}", provider="aws",
                             issuer="root-ca-1"))
        for i in range(4):
            events.append(ev("CERTIFICATE_RENEWED", f"az-cert-{i}", provider="azure",
                             issuer="root-ca-1"))
        for i in range(2):
            events.append(ev("CERTIFICATE_RENEWED", f"gcp-cert-{i}", provider="gcp",
                             issuer="root-ca-1"))
        engine = AlertCorrelationEngine()
        alerts = engine.correlate(events)
        # 12 events → ONE incident, not 12 alerts
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.resource_count == 12
        assert alert.provider_impacts == {"aws": 6, "azure": 4, "gcp": 2}
        assert alert.severity in ("HIGH", "CRITICAL")

    def test_default_correlation_key_uses_ca(self):
        event = ev("CERTIFICATE_RENEWED", "c1", issuer="my-root-ca")
        assert default_correlation_key(event) == "ca:my-root-ca"

    def test_unrelated_events_separate_alerts(self):
        engine = AlertCorrelationEngine()
        alerts = engine.correlate([
            ev("KEY_ROTATED", "k1"),
            ev("ROUTE_CHANGE", "rt1"),
            ev("KEY_ROTATED", "k2"),
        ])
        keys = {a.correlation_key for a in alerts}
        assert len(keys) == 2  # k1+k2 correlated, route separate
        by_key = {a.correlation_key: a.resource_count for a in alerts}
        assert max(by_key.values()) == 2

    def test_engine_alerts_present(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert "alerts" in report.to_dict()
