"""Live layer — event-driven rescanning, TLS/cert/topology watchers, passive."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from network_scanner.enterprise.live.cert_watcher import (
    CERT_EVENTS,
    CertificateWatcher,
)
from network_scanner.enterprise.live.events import (
    CRYPTO_EVENT_KINDS,
    EVENT_KINDS,
    AssetIdentification,
    EventNormalizer,
    ImpactAnalysis,
    NetworkEvent,
)
from network_scanner.enterprise.live.passive_monitor import (
    PASSIVE_SOURCE_KINDS,
    CryptoObservation,
    MetadataExtractor,
    PassiveMonitor,
    PassiveSensor,
)
from network_scanner.enterprise.live.tls_watcher import (
    TLS_STATE_FIELDS,
    TlsWatcher,
)
from network_scanner.enterprise.live.topology_monitor import (
    TOPOLOGY_CHANGE_KINDS,
    TopologyMonitor,
)

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- events

def test_event_kinds_cover_spec():
    for kind in ("NEW_DEVICE_CONNECTED", "DEVICE_DISCONNECTED",
                 "CERTIFICATE_REPLACED", "CERTIFICATE_EXPIRED",
                 "TLS_POLICY_CHANGED", "VPN_CONFIG_CHANGED",
                 "FIREWALL_CONFIG_CHANGED", "CLOUD_RESOURCE_CHANGED",
                 "NEW_PUBLIC_ENDPOINT", "ROUTING_TOPOLOGY_CHANGED",
                 "CRYPTOGRAPHIC_ALGORITHM_CHANGED"):
        assert kind in EVENT_KINDS


def test_normalizer_maps_synonyms():
    normalizer = EventNormalizer()
    event = normalizer.normalize({"type": "cert_replaced",
                                  "ip": "10.0.0.5",
                                  "severity": "HIGH"})
    assert event is not None
    assert event.kind == "CERTIFICATE_REPLACED"
    assert event.severity == "HIGH"
    assert "10.0.0.5" in event.asset_ids


def test_normalizer_rejects_unknown():
    normalizer = EventNormalizer()
    assert normalizer.normalize({"type": "something_else"}) is None
    assert normalizer.normalize({}) is None
    assert normalizer.normalize(None) is None


def test_normalizer_extracts_asset_ids_and_timestamp():
    normalizer = EventNormalizer()
    event = normalizer.normalize({"kind": "NEW_DEVICE_CONNECTED",
                                  "hostname": "switch-7",
                                  "timestamp": "2026-08-30T12:00:00Z"})
    assert event.asset_ids == ["switch-7"]
    assert event.observed_at == "2026-08-30T12:00:00Z"


def test_normalizer_deduplicates_asset_ids():
    ids = EventNormalizer.extract_asset_ids({"ip": ["10.0.0.1", "10.0.0.1"],
                                             "host": "web-1"})
    assert ids == ["web-1", "10.0.0.1"]


def test_asset_identification_resolves_registry():
    identification = AssetIdentification()
    identification.register("web-1", {"ip": "10.0.0.1", "hostname": "web-1"})
    event = NetworkEvent(kind="CERTIFICATE_REPLACED", source="siem",
                         observed_at="2026-08-30T12:00:00Z",
                         asset_ids=["10.0.0.1"])
    identified = identification.identify(event)
    assert identified.asset_ids == ["web-1"]


def test_asset_identification_keeps_unknown_ids():
    identification = AssetIdentification()
    event = NetworkEvent(kind="CERTIFICATE_REPLACED", source="siem",
                         observed_at="2026-08-30T12:00:00Z",
                         asset_ids=["10.9.9.9"])
    identified = identification.identify(event)
    assert identified.asset_ids == ["10.9.9.9"]


def test_impact_analysis_scopes_dependents():
    graph_deps = {"web-1": ["internet", "lb-1"]}
    impact = ImpactAnalysis(dependents_fn=lambda asset: graph_deps.get(asset, []))
    event = NetworkEvent(kind="CERTIFICATE_REPLACED", source="siem",
                         observed_at="2026-08-30T12:00:00Z",
                         asset_ids=["web-1"])
    analysis = impact.analyze(event)
    assert analysis["impacted_assets"] == ["web-1", "internet", "lb-1"]
    assert analysis["targeted_scan_mode"] == "DEEP"


def test_impact_lightweight_for_network_events():
    impact = ImpactAnalysis()
    event = NetworkEvent(kind="DEVICE_DISCONNECTED", source="siem",
                         observed_at="2026-08-30T12:00:00Z",
                         asset_ids=["sw-1"])
    assert impact.analyze(event)["targeted_scan_mode"] == "LIGHTWEIGHT"


def test_crypto_event_kinds():
    assert "CERTIFICATE_REPLACED" in CRYPTO_EVENT_KINDS
    assert "DEVICE_DISCONNECTED" not in CRYPTO_EVENT_KINDS


def test_network_event_validation():
    with pytest.raises(ValueError):
        NetworkEvent(kind="NOPE", source="x", observed_at="t")
    with pytest.raises(ValueError):
        NetworkEvent(kind="SCAN_COMPLETED", source="x", observed_at="t",
                     severity="URGENT")


# ---------------------------------------------------------------- tls watcher

def test_tls_watcher_first_observation_no_change():
    watcher = TlsWatcher()
    change = watcher.observe("web-1:443", {"tls_version": "TLSv1.3",
                                           "cipher_suites": ["TLS_AES_256_GCM_SHA384"]})
    assert change is None
    assert watcher.changes() == []


def test_tls_watcher_detects_downgrade_alert():
    watcher = TlsWatcher()
    watcher.observe("web-1:443", {"tls_version": "TLSv1.3",
                                  "cipher_suites": ["TLS_AES_256_GCM_SHA384"]})
    change = watcher.observe("web-1:443", {"tls_version": "TLSv1.0",
                                           "cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]})
    assert change is not None
    assert change.changed_fields == ["tls_version", "cipher_suites"]
    assert change.alert is True
    assert any(d["classification"] == "CRITICAL_DRIFT" for d in change.drift)


def test_tls_watcher_floor_downgrade_no_alert():
    watcher = TlsWatcher()
    watcher.observe("web-1:443", {"tls_version": "TLSv1.3"})
    change = watcher.observe("web-1:443", {"tls_version": "TLSv1.2"})
    assert change is not None
    assert change.alert is False  # TLSv1.2 is still at the policy floor


def test_tls_watcher_same_state_no_change():
    watcher = TlsWatcher()
    state = {"tls_version": "TLSv1.3"}
    watcher.observe("a:443", state)
    assert watcher.observe("a:443", dict(state)) is None


def test_tls_watcher_upgrade_expected():
    watcher = TlsWatcher()
    watcher.observe("a:443", {"tls_version": "TLSv1.0"})
    change = watcher.observe("a:443", {"tls_version": "TLSv1.3"})
    assert change.alert is False
    assert change.drift[0]["classification"] == "EXPECTED_CHANGE"


def test_tls_watcher_snapshot_and_fields():
    watcher = TlsWatcher()
    watcher.observe("a:443", {"tls_version": "TLSv1.3", "alpn": ["h2"]})
    snapshot = watcher.snapshot()
    assert snapshot["a:443"]["tls_version"] == "TLSv1.3"
    assert "alpn" in TLS_STATE_FIELDS
    assert "mtls" in TLS_STATE_FIELDS
    assert "certificate_chain" in TLS_STATE_FIELDS


def test_tls_change_to_dict():
    watcher = TlsWatcher()
    watcher.observe("a:443", {"tls_version": "TLSv1.3"})
    change = watcher.observe("a:443", {"tls_version": "TLSv1.0"})
    d = change.to_dict()
    assert d["endpoint"] == "a:443"
    assert d["changed_fields"] == ["tls_version"]
    assert d["alert"] is True


# ---------------------------------------------------------------- cert watcher

def _cert(fingerprint="fp-1", subject="CN=web-1", **overrides):
    cert = {"fingerprint_sha256": fingerprint, "subject": subject,
            "issuer": "CN=Enterprise Root CA",
            "signature_algorithm": "SHA256WithRSA",
            "public_key_algorithm": "RSA", "public_key_size": 3072,
            "not_valid_after": "2030-01-01T00:00:00Z"}
    cert.update(overrides)
    return cert


def test_cert_watcher_new_certificate():
    watcher = CertificateWatcher()
    changes = watcher.observe(_cert(), now=T0)
    assert len(changes) == 1
    assert changes[0].kind == "NEW_CERTIFICATE"
    assert changes[0].updates == ["certificate_graph", "dependency_graph",
                                  "live_cbom", "pqc_risk", "compliance_status"]


def test_cert_watcher_algorithm_change():
    watcher = CertificateWatcher()
    watcher.observe(_cert(signature_algorithm="SHA256WithRSA"), now=T0)
    changes = watcher.observe(_cert(signature_algorithm="SHA1WithRSA"), now=T0)
    assert any(c.kind == "ALGORITHM_CHANGED" for c in changes)


def test_cert_watcher_renewed():
    watcher = CertificateWatcher()
    watcher.observe(_cert(serial_number="111"), now=T0)
    changes = watcher.observe(_cert(serial_number="222"), now=T0)
    assert any(c.kind == "CERTIFICATE_RENEWED" for c in changes)


def test_cert_watcher_expiring():
    watcher = CertificateWatcher(expiry_horizon_days=30)
    changes = watcher.observe(_cert(not_valid_after="2026-09-10T00:00:00Z"), now=T0)
    assert any(c.kind == "CERTIFICATE_EXPIRING" for c in changes)


def test_cert_watcher_not_expiring_when_far_out():
    watcher = CertificateWatcher(expiry_horizon_days=30)
    changes = watcher.observe(_cert(not_valid_after="2030-01-01T00:00:00Z"), now=T0)
    assert not any(c.kind == "CERTIFICATE_EXPIRING" for c in changes)


def test_cert_watcher_revoked():
    watcher = CertificateWatcher()
    watcher.observe(_cert(), now=T0)
    changes = watcher.observe(_cert(), revoked={"fp-1"}, now=T0)
    assert any(c.kind == "CERTIFICATE_REVOKED" for c in changes)


def test_cert_watcher_reuse_detection():
    watcher = CertificateWatcher()
    changes = watcher.detect_reuse([
        _cert(fingerprint="same", subject="CN=a"),
        _cert(fingerprint="same", subject="CN=b"),
        _cert(fingerprint="other", subject="CN=c"),
    ])
    assert any(c.kind == "CERTIFICATE_REUSED" and c.fingerprint == "same"
               for c in changes)


def test_cert_watcher_endpoints():
    watcher = CertificateWatcher()
    watcher.observe(_cert(), endpoints=["web-1:443", "web-2:443"], now=T0)
    assert watcher.endpoints_for("fp-1") == ["web-1:443", "web-2:443"]


def test_cert_events_exist():
    for event in ("NEW_CERTIFICATE", "CERTIFICATE_RENEWED", "CERTIFICATE_REVOKED",
                  "CERTIFICATE_EXPIRING", "CERTIFICATE_REUSED", "ALGORITHM_CHANGED"):
        assert event in CERT_EVENTS


# ---------------------------------------------------------------- topology

def _topology(edges):
    return {"edges": edges}


def test_topology_baseline_no_changes():
    monitor = TopologyMonitor()
    edges = [{"source": "a", "target": "b", "relationship": "CONNECTED_TO"}]
    assert monitor.observe(_topology(edges)) == []
    assert monitor.observe(_topology(edges)) == []


def test_topology_new_connection():
    monitor = TopologyMonitor()
    monitor.observe(_topology([{"source": "a", "target": "b",
                                "relationship": "CONNECTED_TO"}]))
    changes = monitor.observe(_topology([
        {"source": "a", "target": "b", "relationship": "CONNECTED_TO"},
        {"source": "a", "target": "c", "relationship": "CONNECTED_TO"},
    ]))
    assert any(c.kind == "NEW_CONNECTION" and c.target == "c" for c in changes)


def test_topology_removed_connection():
    monitor = TopologyMonitor()
    monitor.observe(_topology([
        {"source": "a", "target": "b", "relationship": "CONNECTED_TO"},
        {"source": "a", "target": "c", "relationship": "CONNECTED_TO"},
    ]))
    changes = monitor.observe(_topology([
        {"source": "a", "target": "b", "relationship": "CONNECTED_TO"},
    ]))
    assert any(c.kind == "REMOVED_CONNECTION" and c.target == "c" for c in changes)


def test_topology_route_vpn_firewall_kinds():
    monitor = TopologyMonitor()
    monitor.observe(_topology([]))
    changes = monitor.observe(_topology([
        {"source": "r1", "target": "r2", "relationship": "ROUTES_TO"},
        {"source": "branch", "target": "vpn-gw", "relationship": "USES_VPN"},
        {"source": "fw", "target": "web", "relationship": "PROTECTS"},
    ]))
    kinds = {c.kind for c in changes}
    assert "ROUTE_CHANGED" in kinds
    assert "VPN_CREATED" in kinds
    assert "FIREWALL_PATH_CHANGED" in kinds


def test_topology_lb_change():
    monitor = TopologyMonitor()
    monitor.observe(_topology([]))
    changes = monitor.observe(_topology([
        {"source": "lb-1", "target": "app-1", "relationship": "TERMINATES_TLS_FOR"},
    ]))
    assert any(c.kind == "LOAD_BALANCER_CHANGED" for c in changes)


def test_topology_segment_change():
    monitor = TopologyMonitor()
    monitor.observe(_topology([{"source": "dc1.core", "target": "dc1.app"}]))
    changes = monitor.observe(_topology([{"source": "dc2.core", "target": "dc2.app"}]))
    assert any(c.kind == "NETWORK_SEGMENT_CHANGED" and c.segment == "dc2.core"
               for c in changes)
    assert any(c.kind == "NETWORK_SEGMENT_CHANGED" and c.segment == "dc1.core"
               for c in changes)


def test_topology_change_dict():
    monitor = TopologyMonitor(clock=lambda: T0)
    monitor.observe(_topology([]))
    changes = monitor.observe(_topology(
        [{"source": "a", "target": "b", "relationship": "CONNECTED_TO"}]))
    d = changes[0].to_dict()
    assert d["kind"] == "NEW_CONNECTION"
    assert d["source"] == "a"
    assert d["target"] == "b"
    assert d["observed_at"] == T0


def test_topology_change_kinds_complete():
    for kind in ("NEW_CONNECTION", "REMOVED_CONNECTION", "ROUTE_CHANGED",
                 "VPN_CREATED", "VPN_REMOVED", "LOAD_BALANCER_CHANGED",
                 "NETWORK_SEGMENT_CHANGED", "FIREWALL_PATH_CHANGED"):
        assert kind in TOPOLOGY_CHANGE_KINDS


# ---------------------------------------------------------------- passive

def test_passive_source_kinds():
    for kind in ("SPAN_TAP", "NETFLOW", "IPFIX", "SFLOW", "FIREWALL_LOGS",
                 "VPN_LOGS", "DNS_LOGS", "LOAD_BALANCER_LOGS",
                 "TLS_HANDSHAKE_METADATA", "SIEM_EVENTS"):
        assert kind in PASSIVE_SOURCE_KINDS


def test_passive_sensor_rejects_unknown_kind():
    with pytest.raises(ValueError):
        PassiveSensor("INVALID_KIND")


def test_passive_sensor_poll_returns_and_drains():
    sensor = PassiveSensor("NETFLOW", records=[{"src_ip": "10.0.0.1"}])
    records = sensor.poll()
    assert len(records) == 1
    assert sensor.poll() == []


def test_extractor_builds_observation():
    extractor = MetadataExtractor()
    obs = extractor.extract({"host": "web-1", "protocol": "TLS",
                             "tls_version": "TLSv1.3",
                             "cipher": "TLS_AES_256_GCM_SHA384",
                             "cert_sha256": "abc123",
                             "algorithm": "ECDHE_RSA",
                             "key_size": 2048},
                            source_kind="LOAD_BALANCER_LOGS")
    assert isinstance(obs, CryptoObservation)
    assert obs.asset == "web-1"
    assert obs.tls_version == "TLSv1.3"
    assert obs.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert obs.certificate_fingerprint == "abc123"
    assert obs.source_kind == "LOAD_BALANCER_LOGS"
    assert obs.algorithm == "ECDHE_RSA"
    assert obs.key_size == 2048


def test_extractor_default_protocol_by_kind():
    extractor = MetadataExtractor()
    obs = extractor.extract({"host": "web-1"}, source_kind="NETFLOW")
    assert obs is not None
    assert obs.asset == "web-1"
    assert obs.protocol == ""


def test_extractor_skips_empty_records():
    extractor = MetadataExtractor()
    assert extractor.extract({}) is None
    assert extractor.extract(None) is None
    assert extractor.extract({"src_port": 443}) is None


def test_passive_monitor_polls_sensors():
    sensor = PassiveSensor("TLS_HANDSHAKE_METADATA",
                           records=[{"host": "web-1", "tls_version": "TLSv1.2"}])
    monitor = PassiveMonitor(sensors=[sensor])
    batch = monitor.poll()
    assert len(batch) == 1
    assert batch[0].tls_version == "TLSv1.2"
    assert monitor.observations() == batch


def test_passive_monitor_drain_and_dicts():
    sensor = PassiveSensor("SIEM_EVENTS", records=[{"host": "db-1",
                                                    "protocol": "TLS"}])
    monitor = PassiveMonitor(sensors=[sensor])
    monitor.poll()
    dicts = monitor.to_dicts()
    assert dicts[0]["asset"] == "db-1"
    drained = monitor.drain()
    assert len(drained) == 1
    assert monitor.observations() == []
