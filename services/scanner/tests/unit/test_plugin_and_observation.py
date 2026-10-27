from scanner.core.plugin import JavaSourcePlugin, plugin_catalog, registered_plugins
from shared_models.observation import CryptoObservation, observation_from_raw_finding


def test_source_plugins_are_registered():
    plugins = registered_plugins()
    assert "static-java-scanner" in plugins
    assert "static-python-scanner" in plugins
    assert "static-js-scanner" in plugins
    assert "static-csharp-scanner" in plugins
    assert "static-go-scanner" in plugins
    assert "static-php-scanner" in plugins
    assert "static-ruby-scanner" in plugins
    assert "static-rust-scanner" in plugins
    assert "static-kotlin-scanner" in plugins
    assert "static-config-scanner" in plugins
    plugin = JavaSourcePlugin()
    assert "java" in plugin.capabilities()
    assert plugin.health_check()["ok"] is True
    ids = {row["plugin_id"] for row in plugin_catalog()}
    assert ids == {
        "static-java-scanner",
        "static-python-scanner",
        "static-js-scanner",
        "static-csharp-scanner",
        "static-go-scanner",
        "static-php-scanner",
        "static-ruby-scanner",
        "static-rust-scanner",
        "static-kotlin-scanner",
        "static-config-scanner",
        "static-c-scanner",
    }


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
