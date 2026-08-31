"""24/7 live engine — vendor live monitors + fingerprint + drift +
firmware + cert watcher tests (§4–§12)."""

from __future__ import annotations

from universal_vendor.live.cert_watcher import (
    CertificateChange,
    UniversalCertificateWatcher,
)
from universal_vendor.live.drift import CryptoDriftEngine, DriftState
from universal_vendor.live.fingerprint import ConfigFingerprintTracker, config_hash
from universal_vendor.live.firmware import FirmwareMonitor
from universal_vendor.live.monitoring import LiveConnector, LiveVendorMonitor, MonitorMode
from universal_vendor.live.vendor_monitors import (
    CiscoLiveMonitor,
    FirewallLiveMonitor,
    HsmLiveMonitor,
    LoadBalancerLiveMonitor,
    PkiLiveMonitor,
)


# ── §1 monitoring modes + connectors ─────────────────────────────────

def test_seven_modes_exist():
    assert len(list(MonitorMode)) == 7
    assert MonitorMode.REAL_TIME_TELEMETRY.value == "REAL_TIME_TELEMETRY"
    assert MonitorMode.SCHEDULED_RECONCILIATION.value == "SCHEDULED_RECONCILIATION"


def test_monitor_runs_connectors():
    class DummyConnector(LiveConnector):
        vendor = "Cisco"
        product = "IOS-XE"
        mechanism = "syslog"
        modes = [MonitorMode.REAL_TIME_TELEMETRY]

        def collect(self):
            from universal_vendor.live.events import UniversalVendorEvent

            return [UniversalVendorEvent(vendor="Cisco", product="IOS-XE",
                                         asset_id=self.asset_id,
                                         event_type="CONFIG_CHANGED")]

    monitor = LiveVendorMonitor()
    monitor.register(DummyConnector(asset_id="r1"))
    events = monitor.collect(mode=MonitorMode.REAL_TIME_TELEMETRY)
    assert len(events) == 1
    # other modes filter it out
    assert monitor.collect(mode=MonitorMode.SCHEDULED_RECONCILIATION) == []


def test_broken_connector_never_kills_loop():
    class BrokenConnector(LiveConnector):
        vendor = "F5"
        product = "BIG-IP"
        mechanism = "api"

        def collect(self):
            raise RuntimeError("api down")

    monitor = LiveVendorMonitor()
    monitor.register(BrokenConnector(asset_id="lb1"))
    events = monitor.collect()
    assert len(events) == 1
    assert events[0].event_type == "HEALTH_CHANGED"
    assert "RuntimeError" in events[0].vendor_metadata["error"]


# ── §4 Cisco ─────────────────────────────────────────────────────────

def test_cisco_monitor_classifies_changes():
    monitor = CiscoLiveMonitor(asset_id="r1", events=[
        {"domain": "ipsec", "action": "modified", "detail": "transform set"},
        {"domain": "ssh", "action": "created"},
        {"domain": "certificate", "action": "replaced"},
    ])
    events = monitor.collect()
    types = [e.event_type for e in events]
    assert "IPSEC_CHANGED" in types
    assert "SSH_CHANGED" in types
    assert "CERTIFICATE_REPLACED" in types
    assert all(e.source.startswith("cisco-") for e in events)


def test_cisco_mechanisms():
    monitor = CiscoLiveMonitor(asset_id="r1", mechanism="netconf")
    assert monitor.mechanism == "netconf"
    snapshot = monitor.snapshot()
    assert snapshot["vendor"] == "Cisco"
    assert snapshot["mechanism"] == "netconf"


# ── §5 firewall ──────────────────────────────────────────────────────

def test_firewall_monitor_vendor_override():
    monitor = FirewallLiveMonitor(asset_id="fw1", vendor="Fortinet",
                                  product="FortiOS", events=[
        {"domain": "vpn policy", "change_type": "UPDATED", "policy": "p1"},
    ])
    events = monitor.collect()
    assert events[0].vendor == "Fortinet"
    assert events[0].event_type == "VPN_CHANGED"
    assert events[0].asset_type == "firewall"


# ── §6 load balancer ─────────────────────────────────────────────────

def test_lb_monitor_tls_profile_change():
    monitor = LoadBalancerLiveMonitor(asset_id="lb1", vendor="F5",
                                      product="BIG-IP", events=[
        {"domain": "ssl profile client", "change_type": "UPDATED",
         "profile": "clientssl"},
        {"domain": "backend tls", "change_type": "UPDATED"},
    ])
    events = monitor.collect()
    assert events[0].event_type == "TLS_CHANGED"
    assert events[1].event_type == "CRYPTO_CHANGED"


# ── §7 PKI ───────────────────────────────────────────────────────────

def test_pki_monitor_certificate_events():
    monitor = PkiLiveMonitor(asset_id="root-ca", events=[
        {"action": "REVOKED", "serial": "abc123"},
        {"action": "RENEWED", "serial": "def456"},
        {"action": "EXPIRED"},
    ])
    events = monitor.collect()
    types = [e.event_type for e in events]
    assert "CERTIFICATE_REVOKED" in types
    assert "CERTIFICATE_RENEWED" in types
    assert "CERTIFICATE_EXPIRED" in types


# ── §8 HSM metadata-only ─────────────────────────────────────────────

def test_hsm_monitor_metadata_only():
    monitor = HsmLiveMonitor(asset_id="hsm1", events=[
        {"domain": "firmware", "firmware": "7.4.2"},
        {"domain": "key", "key_id": "k1", "algorithm": "RSA"},
        {"domain": "capabilities", "algorithms": ["RSA", "ECDSA", "ML-KEM"]},
    ])
    events = monitor.collect()
    types = [e.event_type for e in events]
    assert "HSM_FIRMWARE_CHANGED" in types
    assert "HSM_KEY_METADATA_CHANGED" in types
    assert "HSM_CRYPTO_CAPABILITY_CHANGED" in types
    assert all(e.asset_type == "hsm" for e in events)


def test_hsm_monitor_rejects_secret_material():
    import pytest

    monitor = HsmLiveMonitor(asset_id="hsm1", events=[
        {"domain": "key", "private_key": "SUPER-SECRET"},
    ])
    with pytest.raises(AssertionError):
        monitor.collect()


# ── §12 configuration fingerprints ───────────────────────────────────

def test_config_hash_deterministic():
    assert config_hash("a=b\nc=d") == config_hash("a=b\nc=d")
    assert config_hash("a=b") != config_hash("a=c")


def test_fingerprint_tracker_first_and_change():
    tracker = ConfigFingerprintTracker()
    first = tracker.observe("r1", "crypto isakmp policy 1")
    assert first["first_seen"] is True
    assert first["hash_changed"] is False
    second = tracker.observe("r1", "crypto isakmp policy 2")
    assert second["hash_changed"] is True


def test_crypto_relevant_diff():
    from universal_vendor.live.fingerprint import crypto_relevant_diff

    diff = crypto_relevant_diff(
        "interface g0/0\n description uplink",
        "interface g0/0\n crypto isakmp key x",
    )
    assert diff["hash_changed"] is True
    assert diff["crypto_relevant"] is True
    assert "crypto" in diff["matching_tokens"]


def test_non_crypto_diff_not_relevant():
    from universal_vendor.live.fingerprint import crypto_relevant_diff

    diff = crypto_relevant_diff("hostname r1", "hostname r2")
    assert diff["hash_changed"] is True
    assert diff["crypto_relevant"] is False


# ── §10 drift ────────────────────────────────────────────────────────

def test_drift_no_change():
    engine = CryptoDriftEngine()
    engine.set_baseline("r1", "config A")
    verdict = engine.evaluate("r1", "config A")
    assert verdict.state == DriftState.NO_CHANGE


def test_drift_expected_approved():
    engine = CryptoDriftEngine()
    engine.set_baseline("r1", "config A")
    engine.expect("r1", "config B", by="scheduler")
    assert engine.evaluate("r1", "config B").state == DriftState.EXPECTED

    engine2 = CryptoDriftEngine()
    engine2.set_baseline("r1", "config A")
    engine2.approve("r1", config_hash("config C"), by="ciso")
    assert engine2.evaluate("r1", "config C").state == DriftState.APPROVED


def test_drift_unexpected():
    engine = CryptoDriftEngine()
    engine.set_baseline("r1", "hostname r1")
    verdict = engine.evaluate("r1", "hostname r2")
    assert verdict.state == DriftState.UNEXPECTED


def test_drift_crypto_and_critical():
    engine = CryptoDriftEngine()
    engine.set_baseline("r1", "ssh version 2")
    drift = engine.evaluate("r1", "ssh version 2\ncrypto ike policy 1")
    assert drift.state == DriftState.CRYPTO_DRIFT

    engine2 = CryptoDriftEngine()
    engine2.set_baseline("r1", "ssh version 2")
    critical = engine2.evaluate("r1", "ssh version 2\n ipsec crypto rsa md5 on")
    assert critical.state == DriftState.CRITICAL_CRYPTO_DRIFT


# ── §11 firmware ─────────────────────────────────────────────────────

def test_firmware_monitor_tracks_changes():
    from universal_vendor.lifecycle import VendorLifecycleDatabase
    from universal_vendor.pqc_readiness import PqcReadinessDatabase

    monitor = FirmwareMonitor(lifecycle_db=VendorLifecycleDatabase(),
                              pqc_db=PqcReadinessDatabase())
    first = monitor.record(asset_id="fw1", vendor="Fortinet", product="FortiOS",
                           firmware="7.4.1")
    assert first["changed"] is False
    second = monitor.record(asset_id="fw1", vendor="Fortinet", product="FortiOS",
                            firmware="7.4.2")
    assert second["changed"] is True
    assert second["previous_firmware"] == "7.4.1"
    record = monitor.records()[0]
    assert record.previous_firmware == "7.4.1"
    assert record.pqc_capability == "UNKNOWN"  # evidence-backed, never inferred


# ── §9 certificate watcher ───────────────────────────────────────────

def test_cert_watcher_new_changed_renewed_revoked():
    watcher = UniversalCertificateWatcher()
    base = {"subject": "CN=api.example.com", "issuer": "CN=Root CA",
            "serial": "01", "algorithm": "SHA256WITHRSA", "key_size": 2048}
    assert watcher.watch(dict(base)) == [CertificateChange.NEW]

    # same cert re-observed → CHANGED (last_seen updated, no structural change)
    changes = watcher.watch(dict(base))
    assert changes == [CertificateChange.CHANGED]

    # renewed: same subject/issuer, new serial
    renewed = dict(base, serial="02")
    assert CertificateChange.RENEWED in watcher.watch(renewed)

    # revoked
    revoked = dict(base, serial="01", revoked=True)
    assert CertificateChange.REVOKED in watcher.watch(revoked)

    # algorithm changed
    algo = dict(base, serial="01", algorithm="ML-DSA-44")
    assert CertificateChange.ALGORITHM_CHANGED in watcher.watch(algo)


def test_cert_watcher_key_size_and_chain():
    watcher = UniversalCertificateWatcher()
    base = {"subject": "CN=svc", "issuer": "CN=ICA", "serial": "1",
            "key_size": 2048, "chain": ["ICA", "Root"]}
    watcher.watch(dict(base))
    assert CertificateChange.KEY_SIZE_CHANGED in watcher.watch(
        dict(base, key_size=3072))
    assert CertificateChange.CHAIN_CHANGED in watcher.watch(
        dict(base, chain=["ICA", "NewRoot"]))
