"""Enterprise layer — passive discovery + TLS & certificate intelligence.

Spec areas 7, 8, 11: passive log ingestion with no active probing, deep TLS
intelligence with four profiles, and certificate intelligence (reuse,
dependency mapping, blast radius, CA hierarchy, trust store, expiration
forecast, weak signatures, vulnerable keys, PQC candidates).
"""

from __future__ import annotations

from datetime import date, timedelta


from network_scanner.enterprise.cert_intel import (
    ca_hierarchy,
    certificate_intelligence_report,
    dependency_map,
    expiration_forecast,
    find_reuse,
    migration_candidates,
    trust_store_discovery,
    usage_tags,
    vulnerable_public_key_identification,
    weak_signature_detection,
)
from network_scanner.enterprise.passive_engine import (
    PassiveDiscoveryEngine,
    PassiveObservation,
    PassiveSource,
    extract_tls_from_line,
)
from network_scanner.enterprise.tls_intel import (
    build_profiles,
    build_tls_intelligence,
    profile_all,
    tls_configuration_profile,
)

TLS_LOG_LINES = [
    "2026-08-30T10:00:01Z fw-1: TLS handshake from 10.0.0.5 to api.example.com:443 "
    "version=TLSv1.2 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "
    "fingerprint=sha256:" + "ab" * 32,
    "2026-08-30T10:00:02Z fw-1: TLS handshake from 10.0.0.6 to db.internal.corp:3306 "
    "version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384",
    "2026-08-30T10:00:03Z lb-2: TLS1.3 negotiated from 10.0.0.8, ALPN h2",
    "no crypto here at all",
]

CERT_A = {
    "subject": "CN=Root CA", "issuer": "CN=Root CA",
    "fingerprint_sha256": "a" * 64, "basic_constraints": "CA:TRUE",
    "not_after": (date.today() + timedelta(days=3650)).isoformat(),
    "signature_algorithm": "sha256WithRSAEncryption", "key_type": "RSA", "key_size": 4096,
}
CERT_B = {
    "subject": "CN=Int CA", "issuer": "CN=Root CA",
    "fingerprint_sha256": "b" * 64, "basic_constraints": "CA:TRUE",
    "not_after": (date.today() + timedelta(days=1800)).isoformat(),
    "signature_algorithm": "sha256WithRSAEncryption", "key_type": "RSA", "key_size": 3072,
}
CERT_C = {
    "subject": "CN=Issuing CA", "issuer": "CN=Int CA",
    "fingerprint_sha256": "c" * 64, "basic_constraints": "CA:TRUE",
    "not_after": (date.today() + timedelta(days=900)).isoformat(),
    "signature_algorithm": "sha256WithRSAEncryption", "key_type": "RSA", "key_size": 2048,
}
CERT_D = {
    "subject": "CN=api.example.com", "issuer": "CN=Issuing CA",
    "fingerprint_sha256": "d" * 64, "basic_constraints": "",
    "not_after": (date.today() + timedelta(days=45)).isoformat(),
    "signature_algorithm": "sha256WithRSAEncryption", "key_type": "RSA", "key_size": 2048,
    "san": ["api.example.com", "api2.example.com"],
}
CERT_E = {
    "subject": "CN=api.example.com", "issuer": "CN=Issuing CA",
    "fingerprint_sha256": "e" * 64, "basic_constraints": "",
    "not_after": (date.today() + timedelta(days=90)).isoformat(),
    "signature_algorithm": "sha1WithRSAEncryption", "key_type": "RSA",
    "key_size": 1024, "public_key_algorithm": "RSA", "public_key_size": 1024,
    "san": ["api.example.com"],
}


# ------------------------------------------------------------- passive

class TestPassiveEngine:
    def test_extract_tls_from_line(self) -> None:
        obs = extract_tls_from_line(TLS_LOG_LINES[0], source_kind="FIREWALL_LOG")
        assert obs is not None
        assert obs.asset == "api.example.com"
        assert obs.tls_version == "TLSv1.2"
        assert obs.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        assert obs.certificate_fingerprint == "ab" * 32
        assert obs.protocol == "TLS"

    def test_no_crypto_line_ignored(self) -> None:
        assert extract_tls_from_line("no crypto here at all", source_kind="FIREWALL_LOG") is None

    def test_ingest_many(self) -> None:
        engine = PassiveDiscoveryEngine()
        count = engine.ingest(PassiveSource(kind="FIREWALL_LOG", name="fw-1", lines=TLS_LOG_LINES))
        assert count == 3
        assert engine.count() == 3
        assert "api.example.com" in engine.assets()

    def test_ingest_many_sources(self) -> None:
        engine = PassiveDiscoveryEngine()
        count = engine.ingest_many([
            PassiveSource(kind="FIREWALL_LOG", name="fw", lines=TLS_LOG_LINES[:2]),
            PassiveSource(kind="TLS_HANDSHAKE", name="lb", lines=TLS_LOG_LINES[2:3]),
        ])
        assert count == 3

    def test_no_active_probing(self) -> None:
        # the engine only consumes what it is given — no sockets, no probing
        engine = PassiveDiscoveryEngine()
        engine.ingest(PassiveSource(kind="FIREWALL_LOG", name="fw", lines=TLS_LOG_LINES))
        assert engine.count() == 3

    def test_to_protocol_observations(self) -> None:
        engine = PassiveDiscoveryEngine()
        engine.ingest(PassiveSource(kind="FIREWALL_LOG", name="fw", lines=TLS_LOG_LINES[:2]))
        obs = engine.to_protocol_observations()
        assert all(o.protocol == "TLS" for o in obs)
        assert obs[0].status == "CRYPTOGRAPHY_OBSERVED"
        assert obs[0].method == "passive"

    def test_custom_parser_hook(self) -> None:
        engine = PassiveDiscoveryEngine()

        def parser(line: str) -> dict | None:
            if "custom" not in line:
                return None
            return {"asset": "c1", "source_kind": "CUSTOM", "protocol": "MQTT",
                    "detail": line, "confidence": 0.9}

        count = engine.ingest(PassiveSource(kind="CUSTOM", name="x", lines=["custom mqtt line"],
                                            parser=parser))
        assert count == 1
        assert engine.observations()[0].protocol == "MQTT"

    def test_passive_observation_to_dict(self) -> None:
        obs = PassiveObservation(asset="h", source_kind="LOG", protocol="TLS",
                                 tls_version="TLSv1.3", confidence=0.8)
        data = obs.to_dict()
        assert data["protocol"] == "TLS"
        assert data["source_kind"] == "LOG"


# ------------------------------------------------------------- TLS intel

class TestTlsIntelligence:
    def _findings(self) -> list[dict]:
        return [
            {"endpoint": "api.example.com:443", "status": "OK",
             "crypto": {"tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                        "algorithm": "ECDHE_RSA", "key_size": 2048, "curve": "prime256v1",
                        "alpn": ["h2", "http/1.1"], "signature_algorithm": "sha256WithRSAEncryption"},
             "certificates": [{"subject": "CN=api.example.com", "issuer": "CN=Int CA",
                               "fingerprint_sha256": "d" * 64, "not_after": "2027-01-01"}],
             "ocsp_stapling": True, "session_resumption": "ticket", "sni_behavior": "strict",
             "chain_verified": True},
            {"endpoint": "api.example.com:443", "status": "OK",
             "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}},
        ]

    def test_build_tls_intelligence(self) -> None:
        info = build_tls_intelligence("api.example.com", self._findings())
        assert set(info.tls_versions_supported) == {"TLSv1.2", "TLSv1.3"}
        assert info.negotiated_tls_version == "TLSv1.2"
        assert "TLS_AES_256_GCM_SHA384" in info.cipher_suites_supported
        assert info.key_exchange == "ECDHE_RSA"
        assert info.key_size == 2048
        assert info.elliptic_curves == ["prime256v1"]
        assert info.alpn == ["h2", "http/1.1"]
        assert info.ocsp_stapling is True
        assert info.trust_chain_verified is True
        assert info.source_findings == 2
        assert info.certificate_fingerprints == ["d" * 64]

    def test_profiles(self) -> None:
        info = build_tls_intelligence("api.example.com", self._findings())
        profiles = profile_all(info)
        names = {p["profile_type"] for p in profiles}
        assert names == {"TLS_CONFIGURATION_PROFILE", "CERTIFICATE_PROFILE",
                         "CIPHER_PROFILE", "CRYPTOGRAPHIC_STRENGTH_PROFILE"}

    def test_tls_configuration_profile_weak(self) -> None:
        info = build_tls_intelligence("h", [{"crypto": {"tls_version": "TLSv1.1",
                                                        "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}])
        profile = tls_configuration_profile(info)
        assert profile["grade"] == "WEAK"
        assert "TLSv1.1" in profile.get("weak_versions", [])
        assert profile["profile_type"] == "TLS_CONFIGURATION_PROFILE"

    def test_build_profiles_convenience(self) -> None:
        profiles = build_profiles("api.example.com", self._findings())
        assert len(profiles) == 4

    def test_to_dict_roundtrip(self) -> None:
        info = build_tls_intelligence("h", self._findings())
        data = info.to_dict()
        assert data["endpoint"] == "h"
        assert "negotiated_tls_version" in data


# ------------------------------------------------------------ cert intel

class TestCertificateIntelligence:
    CERTS = [CERT_A, CERT_B, CERT_C, CERT_D, CERT_E]

    def test_find_reuse(self) -> None:
        # the same certificate (same fingerprint) seen on two endpoints
        cert_d_dup = {**CERT_D, "endpoints": ["api2.example.com"]}
        reuse = find_reuse([CERT_D, cert_d_dup, CERT_A])
        assert len(reuse) == 1
        assert "CN=api.example.com" in reuse["d" * 64]

    def test_no_reuse_when_fingerprints_unique(self) -> None:
        assert find_reuse(self.CERTS) == {}

    def test_dependency_map(self) -> None:
        deps = dependency_map(self.CERTS, endpoints=["api.example.com", "api2.example.com"])
        assert "d" * 64 in deps
        assert "api.example.com" in deps["d" * 64]
        assert "api2.example.com" in deps["d" * 64]

    def test_usage_tags(self) -> None:
        tags = usage_tags(CERT_D)
        assert tags["endpoint"] is True
        assert tags["device"] is False

    def test_ca_hierarchy(self) -> None:
        hierarchy = ca_hierarchy(self.CERTS)
        assert hierarchy["roots"] == ["CN=Root CA"]
        roles = {row["role"] for row in hierarchy["chain_entries"]}
        assert roles <= {"INTERMEDIATE_CA", "SERVER_CERT"}
        assert any(row["subject"] == "CN=api.example.com" for row in hierarchy["chain_entries"])

    def test_trust_store_discovery(self) -> None:
        store = trust_store_discovery(self.CERTS)
        assert "CN=Root CA" in store

    def test_expiration_forecast(self) -> None:
        forecast = expiration_forecast(self.CERTS, horizon_days=60)
        expiring = {row["subject"] for row in forecast if row.get("days_left", 999) <= 60}
        assert "CN=api.example.com" in expiring

    def test_weak_signatures(self) -> None:
        weak = weak_signature_detection(self.CERTS)
        assert any(row.get("signature_algorithm") == "sha1withrsaencryption" for row in weak)
        assert any(row.get("issue") == "WEAK_CERT_SIGNATURE" for row in weak)

    def test_vulnerable_keys(self) -> None:
        vulnerable = vulnerable_public_key_identification(self.CERTS)
        assert any(row.get("key_size", 0) < 2048 for row in vulnerable)
        assert all(row.get("issue") == "WEAK_PUBLIC_KEY" for row in vulnerable)

    def test_migration_candidates(self) -> None:
        candidates = migration_candidates(self.CERTS)
        assert any("api.example.com" in str(c.get("subject")) for c in candidates)

    def test_full_report(self) -> None:
        report = certificate_intelligence_report(self.CERTS, endpoints=["api.example.com"])
        assert report["certificate_count"] == 5
        for key in ("reuse", "dependencies", "blast_radius", "ca_hierarchy", "trust_store",
                    "expiration_forecast", "weak_signatures", "vulnerable_keys",
                    "migration_candidates"):
            assert key in report
