from scanner.core.plugin import JavaSourcePlugin, registered_plugins
from shared_models.observation import CryptoObservation, observation_from_raw_finding


def test_java_plugin_is_registered():
    plugins = registered_plugins()
    assert "static-java-scanner" in plugins
    plugin = JavaSourcePlugin()
    assert "java" in plugin.capabilities()
    assert plugin.health_check()["ok"] is True


def test_observation_from_raw_finding():
    raw = {
        "finding_id": "f1",
        "scanner_id": "static-java-scanner-v0.1",
        "scanner_version": "0.1.0",
        "file_path": "Pay.java",
        "line_number": 12,
        "algorithm": "AES",
        "mode": "GCM",
        "purpose": "ENCRYPTION",
        "confidence": "HIGH",
    }
    obs = observation_from_raw_finding(raw, scan_id="scan-1")
    assert isinstance(obs, CryptoObservation)
    assert obs.crypto_algorithm == "AES"
    assert obs.scan_id == "scan-1"
    assert obs.location.endswith(":12")
    assert obs.collector
    payload = obs.to_dict()
    assert payload["confidence"] == "HIGH"
