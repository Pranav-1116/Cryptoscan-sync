"""24/7 live engine — live PQC + lifecycle + health + offline + regions +
credentials + plugin isolation/lifecycle + live CBOM tests (§15, §20–§26)."""

from __future__ import annotations

import pytest

from universal_vendor.live.cbom import LiveCbom
from universal_vendor.live.credentials import (
    CredentialVault,
    context_with_credential_reference,
    strip_credentials,
)
from universal_vendor.live.events import (
    EventType,
    UniversalVendorEvent,
)
from universal_vendor.live.health import HealthMonitor, HealthState
from universal_vendor.live.offline import (
    LocalEventQueue,
    LocalEvidenceStore,
    SecureSync,
)
from universal_vendor.live.plugin_runner import (
    PluginLifecycle,
    PluginSandbox,
    PluginStage,
)
from universal_vendor.live.pqc_live import LivePqcMonitor
from universal_vendor.live.regions import ControlPlane
from universal_vendor.lifecycle import VendorLifecycleDatabase
from universal_vendor.pqc_readiness import PqcReadinessDatabase


# ── §15 live PQC ─────────────────────────────────────────────────────

def test_live_pqc_six_states():
    from universal_vendor.models import PqcCapability

    assert {p.value for p in PqcCapability} == {
        "PQC_SUPPORTED", "HYBRID_SUPPORTED", "PARTIALLY_SUPPORTED",
        "ROADMAP_DECLARED", "NOT_SUPPORTED", "UNKNOWN",
    }


def test_live_pqc_impact():
    db = PqcReadinessDatabase()
    monitor = LivePqcMonitor(pqc_db=db, lifecycle_db=VendorLifecycleDatabase())
    impact = monitor.assess(asset_id="fw1", vendor="Cisco", product="IOS-XE",
                            version="17.9.4a", dependency_count=12)
    assert impact.pqc_capability == "UNKNOWN"  # evidence-backed
    assert impact.impact in ("LOW", "MEDIUM", "HIGH")
    assert impact.to_dict()["asset_id"] == "fw1"


def test_live_pqc_capability_change_log():
    db = PqcReadinessDatabase()
    monitor = LivePqcMonitor(pqc_db=db)
    monitor.assess(asset_id="a1", vendor="OpenSSL", product="OpenSSL",
                   version="3.5")
    # OpenSSL 3.5 has verified PQC support in the DB
    assert monitor.assessments()[0].pqc_capability == "PQC_SUPPORTED"
    # no change log yet (first assessment)
    assert monitor.capability_changes() == []


def test_lifecycle_critical_priority():
    db = VendorLifecycleDatabase()
    result = db.migration_priority("Microsoft", "Windows Server", "2012 R2",
                                   pqc_required=True)
    assert result["migration_priority"] == "HIGH"


# ── §20 health ───────────────────────────────────────────────────────

def test_health_states():
    assert {s.value for s in HealthState} == {
        "HEALTHY", "DEGRADED", "AUTH_FAILED", "RATE_LIMITED", "EVENT_DELAYED",
        "UNREACHABLE", "FAILED", "MAINTENANCE",
    }


def test_health_derivation():
    monitor = HealthMonitor()
    monitor.register("cisco-netconf", vendor="Cisco")
    assert monitor.heartbeat("cisco-netconf").state == HealthState.HEALTHY

    monitor.heartbeat("cisco-netconf", authentication_status="failed")
    assert monitor.state("cisco-netconf") == HealthState.AUTH_FAILED

    monitor.heartbeat("cisco-netconf", authentication_status="authenticated",
                      rate_limit_remaining=0)
    assert monitor.state("cisco-netconf") == HealthState.RATE_LIMITED

    monitor.heartbeat("cisco-netconf", rate_limit_remaining=10,
                      event_lag_seconds=9999)
    assert monitor.state("cisco-netconf") == HealthState.EVENT_DELAYED

    monitor.heartbeat("cisco-netconf", event_lag_seconds=1,
                      connection_status="unreachable")
    assert monitor.state("cisco-netconf") == HealthState.UNREACHABLE

    monitor.heartbeat("cisco-netconf", connection_status="connected",
                      plugin_health="failing")
    assert monitor.state("cisco-netconf") == HealthState.FAILED

    monitor.heartbeat("cisco-netconf", plugin_health="maintenance")
    assert monitor.state("cisco-netconf") == HealthState.MAINTENANCE

    monitor.heartbeat("cisco-netconf", plugin_health="ok", api_errors=10)
    assert monitor.state("cisco-netconf") == HealthState.DEGRADED


def test_health_history():
    monitor = HealthMonitor()
    monitor.register("f5-api")
    monitor.heartbeat("f5-api")
    monitor.heartbeat("f5-api", authentication_status="failed")
    assert len(monitor.history()) >= 1


# ── §21 offline / disconnected ───────────────────────────────────────

def test_offline_queue_and_sync(tmp_path):
    queue = LocalEventQueue(path=tmp_path / "events.jsonl")
    queue.enqueue(UniversalVendorEvent(vendor="Cisco", product="IOS-XE",
                                       asset_id="r1",
                                       event_type=EventType.CONFIG_CHANGED))
    assert len(queue) == 1

    # offline: no sync
    secure = SecureSync()
    offline = secure.sync(queue, LocalEvidenceStore(path=tmp_path / "ev.jsonl"),
                          network_available=False)
    assert offline["synced"] is False
    assert len(queue) == 1  # still queued

    # online: synced and cleared
    online = secure.sync(queue, LocalEvidenceStore(path=tmp_path / "ev2.jsonl"),
                         network_available=True)
    assert online["synced"] is True
    assert online["events_sent"] == 1
    assert len(queue) == 0


def test_offline_evidence_chain(tmp_path):
    store = LocalEvidenceStore(path=tmp_path / "evidence.jsonl")
    store.append({"vendor": "F5", "product": "BIG-IP", "algorithm": "AES-256"},
                 scan_id="offline-1")
    verification = store.verify(scan_id="offline-1")
    assert verification["chain_intact"] is True


# ── §22 distributed regions ──────────────────────────────────────────

def test_control_plane_regions():
    plane = ControlPlane()
    plane.add_edge("UAE", online=True, control_plane_url="https://cp-uae")
    plane.add_edge("EU", online=False)   # control plane unreachable
    plane.add_edge("USA", online=True)
    assert plane.regions() == ["EU", "UAE", "USA"]
    summary = plane.summary()
    assert summary["online_edges"] == 2
    # EU edge stays operational offline
    eu = plane.edge("EU")
    result = eu.sync()
    assert result["synced"] is False
    assert result["reason"] == "offline"


# ── §23 secure credentials ───────────────────────────────────────────

def test_credentials_never_in_plugins():
    vault = CredentialVault()
    reference = vault.issue_reference(vault_path="secret/vendor/cisco",
                                      scoped_to=["read-only"], ttl_seconds=300)
    context = context_with_credential_reference(
        {"api_password": "super-secret", "host": "10.0.0.1"}, reference)
    assert "api_password" not in context  # stripped
    assert context["credential_reference"]["reference_id"] == reference.reference_id
    assert context["host"] == "10.0.0.1"   # benign fields survive


def test_credentials_strip_secrets():
    context = {"password": "x", "api_key": "y", "token": "z",
               "hostname": "fw1", "config": "crypto key rsa"}
    clean = strip_credentials(context)
    assert "password" not in clean and "api_key" not in clean
    assert "token" not in clean
    assert clean["hostname"] == "fw1"


def test_credentials_lease_expiry():
    vault = CredentialVault()
    reference = vault.issue_reference(vault_path="secret/hsm", ttl_seconds=0)
    with pytest.raises(PermissionError):
        vault.lease(reference.reference_id)


# ── §24 plugin isolation ─────────────────────────────────────────────

def test_sandbox_timeout():
    import time

    def slow(_):
        time.sleep(5)
        return []

    sandbox = PluginSandbox(timeout_seconds=0.2)
    result = sandbox.run("slow-plugin", slow, {})
    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_sandbox_records_cap():
    sandbox = PluginSandbox(max_records=2)
    result = sandbox.run("noisy", lambda ctx: [{"x": 1}] * 10, {})
    assert result.ok is False
    assert "max_records" in (result.error or "")


def test_sandbox_strips_credentials():
    sandbox = PluginSandbox()
    captured = {}

    def spy(context):
        captured.update(context)
        return []

    sandbox.run("spy", spy, {"token": "leak-me", "host": "fw1"})
    assert "token" not in captured
    assert captured["host"] == "fw1"


# ── §25 plugin lifecycle ─────────────────────────────────────────────

def test_plugin_lifecycle_stages():
    lifecycle = PluginLifecycle()
    lifecycle.register("my-vendor-plugin", plugin_version="2.1.0",
                       schema_version="1.3",
                       supported_product_versions=["1.0", "2.0"],
                       security_status="pending")
    assert lifecycle.verify("my-vendor-plugin") is False  # not yet approved

    lifecycle.transition("my-vendor-plugin", PluginStage.SIGNED)
    lifecycle.approve("my-vendor-plugin", signature="sig:sha256:deadbeef")
    assert lifecycle.verify("my-vendor-plugin") is True

    lifecycle.transition("my-vendor-plugin", PluginStage.DEPRECATED)
    assert lifecycle.verify("my-vendor-plugin") is False

    record = lifecycle.record("my-vendor-plugin")
    assert record.plugin_version == "2.1.0"
    assert record.signature == "sig:sha256:deadbeef"


def test_plugin_lifecycle_audit():
    lifecycle = PluginLifecycle()
    lifecycle.register("p1")
    lifecycle.transition("p1", PluginStage.TESTING)
    assert len(lifecycle.audit()) >= 2


# ── §26 live vendor CBOM ─────────────────────────────────────────────

def test_live_cbom_materializes_events():
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="r1",
        product_version="17.9.4a", event_type=EventType.CRYPTO_CHANGED,
        vendor_metadata={"algorithms": ["AES-256-GCM", "ECDH"]}))
    cbom.materialize(UniversalVendorEvent(
        vendor="Palo Alto", product="PAN-OS", asset_id="fw1",
        event_type=EventType.CRYPTO_CHANGED,
        vendor_metadata={"algorithms": ["RSA"]}))
    components = cbom.components()
    assert len(components) == 3
    assert cbom.version() == 3  # 2 events + initial version


def test_live_cbom_asset_removal():
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="F5", product="BIG-IP", asset_id="lb1",
        event_type=EventType.CRYPTO_CHANGED,
        vendor_metadata={"algorithms": ["AES"]}))
    cbom.materialize(UniversalVendorEvent(
        vendor="F5", product="BIG-IP", asset_id="lb1",
        event_type=EventType.ASSET_REMOVED))
    assert cbom.components() == []


def test_live_cbom_document():
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="r1",
        event_type=EventType.CRYPTO_CHANGED,
        vendor_metadata={"algorithms": ["RSA"]}))
    doc = cbom.generate_document(name="live-demo")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["components"]


def test_live_cbom_event_log():
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="Thales", product="Luna HSM", asset_id="hsm1",
        event_type=EventType.HSM_FIRMWARE_CHANGED,
        vendor_metadata={"firmware": "7.4.2"}))
    log = cbom.event_log()
    assert len(log) == 1
    assert log[0]["event_type"] == "HSM_FIRMWARE_CHANGED"
