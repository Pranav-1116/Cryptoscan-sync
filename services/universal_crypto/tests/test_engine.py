"""§1/§36 end-to-end engine + discovery correlation + what-if simulator."""

from __future__ import annotations

import base64

from universal_crypto.discovery import SOURCES, UniversalDiscovery
from universal_crypto.engine import UniversalCryptoEngine
from universal_crypto.simulator import MigrationSimulator


def test_universal_discovery_correlates_sources():
    discovery = UniversalDiscovery()
    discovery.discover({
        "source_code": {"algorithms": [{"algorithm": "RSA", "operation": "sign",
                                        "location": "auth/main.py"}],
                        "asset_id": "auth"},
        "tls_endpoints": {"algorithms": ["RSA"], "endpoint": "auth:443",
                          "asset_id": "auth"},
        "certificates": {"algorithms": ["RSA"], "location": "auth.crt",
                         "asset_id": "auth"},
        "hsms": {"capabilities": ["ML-KEM-768"], "asset_id": "auth"},
        "applications": {"algorithms": ["AES-GCM"], "asset_id": "auth"},
    })
    assert set(discovery.sources_run) == {
        "source_code", "tls_endpoints", "certificates", "hsms", "applications"}
    groups = discovery.correlate()
    rsa = next(g for g in groups if g["algorithm"] == "RSA")
    assert set(rsa["sources"]) == {"source_code", "tls_endpoints", "certificates"}
    assert len(rsa["evidence"]) == 3  # correlated, not independent
    mlkem = next(g for g in groups if g["algorithm"] == "ML-KEM-768")
    assert mlkem["capability"] is True
    assert mlkem["usage"] is False  # §27


def test_all_discovery_sources_registered():
    assert len(SOURCES) == 25
    assert "infrastructure_as_code" in SOURCES
    assert "kubernetes" in SOURCES


def test_full_scan_pipeline_shape():
    engine = UniversalCryptoEngine()
    report = engine.scan({
        "policy": "NIST",
        "sources": {"cloud_services": {"algorithms": ["KMS AES-256"]}},
        "source_code": [
            {"language": "python", "text": "import hashlib\nh = hashlib.sha256(x)",
             "asset_id": "svc", "location": "svc/main.py"},
            {"language": "java", "text": "Cipher.getInstance(\"AES/GCM/NoPadding\")",
             "asset_id": "svc", "location": "svc/Crypto.java"},
        ],
        "tls": [{"suite": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                 "endpoint": "svc:443", "asset_id": "svc"}],
        "ssh": [{"host_key": "ssh-ed25519", "host": "svc", "asset_id": "svc"}],
        "ipsec": [{"encryption": "AES_GCM_16", "dh_group": "19", "pfs": True,
                   "gateway": "gw-1", "asset_id": "vpn"}],
        "binaries": [{"name": "libx.so", "asset_id": "svc",
                      "data": base64.b64encode(b"\x7fELF" + b"\x00" * 64).decode()}],
        "runtime": [{"process": "svc", "loaded_libraries": ["libssl.so"],
                     "api_calls": ["EVP_EncryptUpdate"], "asset_id": "svc"}],
        "libraries": [{"imports": ["openssl/ssl.h"], "symbols": ["SSL_CTX_new"],
                       "strings": ["OpenSSL 3.0.13"], "asset_id": "svc"}],
        "hardcoded_scan": [{"language": "python",
                            "text": "key_size = 2048", "asset_id": "svc"}],
        "randomness_scan": [{"language": "python",
                             "text": "key = random.choice(chars)", "asset_id": "svc"}],
        "custom_crypto": [{"implementation_name": "my_digest"}],
        "key_metadata": [{"key_id": "k1", "algorithm": "AES", "size": 256,
                          "usage": "encryption", "generated_at": "2020-01-01T00:00:00+00:00"}],
    })
    assert report["observations"], "observations expected"
    assert report["findings"], "findings expected"
    assert report["quantum_classifications"]
    assert report["readiness"]
    assert report["agility"]
    assert report["graph"]["nodes"]
    assert report["graph"]["edges"]
    assert report["certificates"] == []
    assert report["key_lifecycle"]["findings"], "lifecycle findings expected"
    # every finding is explainable (§29)
    for finding in report["findings"]:
        assert finding["what"] and finding["how_detected"] and finding["recommendation"]
    # TLS observation carries PFS structure
    tls_obs = next(o for o in report["observations"] if o.get("protocol") == "TLS")
    assert tls_obs["algorithm"] in ("AES-GCM", "TLS")
    # library fingerprinting ran
    assert any(l["verdict"] == "CONFIRMED_IMPLEMENTATION"
               for l in report["libraries"])


def test_confidence_flows_into_findings():
    engine = UniversalCryptoEngine()
    report = engine.scan({
        "source_code": [{"language": "python",
                         "text": "import hashlib\nh = hashlib.sha256(x)",
                         "asset_id": "svc"}],
        "tls": [{"suite": "TLS_RSA_WITH_AES_128_GCM_SHA256", "endpoint": "svc:443",
                 "asset_id": "svc"}],
    })
    finding = next(f for f in report["findings"] if f["algorithm"] == "SHA-256")
    # single AST evidence = 30 points → UNCONFIRMED (honest low-confidence
    # finding; §28 never inflates a one-source observation)
    assert finding["confidence"] == 30.0
    assert finding["band"] == "UNCONFIRMED"
    assert finding["evidence"]


def test_unknown_crypto_detected_in_scan():
    engine = UniversalCryptoEngine()
    report = engine.scan({
        "source_code": [{"language": "python",
                         "text": "def custom_sign(msg):\n    return impl(msg)",
                         "asset_id": "svc"}],
    })
    assert any("custom_sign" in u["snippet"] for u in report["unknown_crypto"])


def test_simulator_what_if():
    result = MigrationSimulator().simulate(
        current_algorithm="RSA", target_algorithm="ML-KEM-768",
        protocol="TLS", library="OpenSSL", hardware="HSM", usage=True)
    assert result["projected_quantum_status"] == "QUANTUM_SAFE"
    assert result["risk_impact"]["risk_reduction"] == "HIGH"
    assert result["migration_readiness"] == "READY"
    assert result["agility_after"] > result["agility_current"]


def test_simulator_incompatible_target():
    result = MigrationSimulator().simulate(
        current_algorithm="RSA", target_algorithm="ML-DSA-65",
        protocol="IPsec", library="mbedTLS", usage=True)
    assert result["projected_quantum_status"] == "QUANTUM_SAFE"
    assert result["compatible"] is False
    assert result["migration_readiness"] == "PLANNED"


def test_dependency_graph_relationships():
    from universal_crypto.dependency_graph import CryptoDependencyGraph
    graph = CryptoDependencyGraph()
    graph.build_application(
        application="payments", libraries=["OpenSSL"],
        protocols=["TLS"], algorithms=["ECDSA"],
        certificates=["payments.crt"],
        certificate_algorithms={"payments.crt": "RSA-2048"})
    affected = {a["node"] for a in graph.affected("payments.crt")}
    assert "RSA-2048" in affected
    assert graph.dependency_count("ECDSA") == 1
    paths = graph.paths("payments", "ECDSA")
    assert paths and paths[0] == ["payments", "OpenSSL", "TLS", "ECDSA"]
    assert graph.to_cbom_relationships()
