"""ZELNX §6 encryption + §7 network crypto + §8 TLS discovery."""

from __future__ import annotations

from cloud_scanner.enterprise.encryption_discovery import (
    EncryptionDiscovery,
    at_rest_state,
    normalize_encryption,
)
from cloud_scanner.enterprise.network_crypto import (
    NetworkCryptoDiscovery,
    ipsec_weak,
    tls_weak,
)
from cloud_scanner.enterprise.tls_discovery import (
    PQC_MIGRATION_REQUIRED,
    TLS_LEGACY,
    TLS_SECURE,
    TLS_WEAK,
    TlsDiscovery,
    classify_endpoint,
)

from zelix_fixtures import all_providers


# ------------------------------------------------------------------ §6 encryption


def test_encryption_discovery_all_providers():
    enc = EncryptionDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert enc.count() == 4  # 2 aws + 1 azure + 1 gcp
    assert enc.count("aws") == 2
    assert enc.count("azure") == 1
    assert enc.count("gcp") == 1


def test_encryption_at_rest_states():
    enc = EncryptionDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    s3 = next(r for r in enc.resources if r.resource_id == "s3-payments")
    assert s3.at_rest == "ENCRYPTED_CMK"
    assert s3.customer_managed is True
    assert s3.key_reference == "arn:aws:kms:key-1"
    assert s3.in_transit == "TLS_ENABLED"
    rds = next(r for r in enc.resources if r.resource_id == "rds-payments")
    assert rds.at_rest == "NOT_ENCRYPTED"


def test_at_rest_state_matrix():
    assert at_rest_state(True, "kms-1", True) == "ENCRYPTED_CMK"
    assert at_rest_state(True, "kms-1", False) == "ENCRYPTED_PMK"
    assert at_rest_state(True, "kms-1", None) == "ENCRYPTED_UNKNOWN_KEY"
    assert at_rest_state(True, None, True) == "ENCRYPTED_CMK"
    assert at_rest_state(True, None, False) == "ENCRYPTED_PMK"
    assert at_rest_state(False, None, None) == "NOT_ENCRYPTED"
    assert at_rest_state(None, None, None) == "UNKNOWN"


def test_encryption_unencrypted_and_cmk_summary():
    enc = EncryptionDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert [r.resource_id for r in enc.unencrypted()] == ["rds-payments"]
    assert len(enc.customer_managed()) == 3
    summary = enc.summary()
    assert summary["resources"] == 4
    assert summary["customer_managed"] == 3


def test_encryption_normalize_metadata_only():
    resource = normalize_encryption({
        "resource_id": "b1", "encrypted": True, "customer_managed": True,
        "key_reference": "kms://1", "encryption_algorithm": "aws:kms",
        "certificate_reference": "cert-1", "rotation_status": "ROTATING",
    }, provider="aws")
    assert resource.encryption_algorithm == "aws:kms"
    assert resource.certificate_reference == "cert-1"
    assert resource.rotation_status == "ROTATING"
    assert "key_material" not in resource.to_dict()


# ------------------------------------------------------------------ §7 network


def test_network_crypto_tls_and_ipsec_profiles():
    net = NetworkCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert len(net.tls_profiles) == 3  # 2 aws + 1 azure
    assert len(net.ipsec_profiles) == 2
    assert len(net.tunnels) == 2


def test_network_weak_profiles_detected():
    net = NetworkCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    weak = net.weak_profiles()
    weak_ids = [p["profile_id"] for p in weak]
    assert "cf-1" in weak_ids  # TLSv1.0
    assert "vpn-2" in weak_ids  # 3DES/SHA1/DH group 2/no PFS
    assert "lb-1" not in weak_ids
    assert "vpn-1" not in weak_ids


def test_tls_weak_helper():
    assert tls_weak(["TLSv1.3", "TLSv1.2"]) is False
    assert tls_weak(["TLSv1.0"]) is True
    assert tls_weak(["SSLv3"]) is True
    assert tls_weak([]) is False


def test_ipsec_weak_helper():
    assert ipsec_weak(["AES256"], ["SHA256"], [14], True) is False
    assert ipsec_weak(["3DES"], ["SHA256"], [14], True) is True
    assert ipsec_weak(["AES256"], ["SHA1"], [14], True) is True
    assert ipsec_weak(["AES256"], ["SHA256"], [2], True) is True
    assert ipsec_weak(["AES256"], ["SHA256"], [14], False) is True


def test_network_tunnel_relationships():
    net = NetworkCryptoDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    tunnels = net.tunnels
    assert all(t.kind == "VPN_TUNNEL" for t in tunnels)
    assert {t.source for t in tunnels} == {"vpc-core", "vpc-edge"}


def test_network_errors_recorded():
    def boom():
        raise RuntimeError("network api down")

    net = NetworkCryptoDiscovery([{
        "provider": "aws", "enumerate_tls": boom, "enumerate_ipsec": boom,
        "enumerate_tunnels": boom,
    }]).discover()
    assert len(net.errors) == 3


# ------------------------------------------------------------------ §8 TLS


def test_tls_discovery_classifies_endpoints():
    tls = TlsDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert tls.summary()["endpoints"] == 4  # 2 aws + 1 azure + 1 gcp
    by_id = {e.endpoint: e for e in tls.endpoints}
    assert by_id["api.bank.example"].classification == TLS_SECURE
    assert by_id["legacy.bank.example"].classification == TLS_LEGACY
    assert by_id["api.az.bank.example"].classification == TLS_SECURE
    assert by_id["billing.gcp.bank.example"].classification == TLS_SECURE


def test_classify_endpoint_matrix():
    assert classify_endpoint(tls_version="TLSv1.2", key_exchange="ECDHE",
                             public_key_size=2048) == TLS_SECURE
    assert classify_endpoint(tls_version="TLSv1.0", key_exchange="ECDHE",
                             public_key_size=2048) == TLS_LEGACY
    assert classify_endpoint(tls_version="SSLv3", key_exchange="RSA",
                             public_key_size=2048) == TLS_LEGACY
    assert classify_endpoint(tls_version="TLSv1.2", key_exchange="RSA",
                             public_key_size=1024) == TLS_WEAK
    assert classify_endpoint(tls_version="TLSv1.2", key_exchange="RSA",
                             public_key_size=2048) == PQC_MIGRATION_REQUIRED
    assert classify_endpoint(tls_version="TLSv1.3", key_exchange="X25519MLKEM768",
                             public_key_size=2048) == TLS_SECURE
    assert classify_endpoint(tls_version="", key_exchange="", public_key_size=None) == "UNKNOWN"


def test_tls_endpoint_rich_fields():
    tls = TlsDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    endpoint = next(e for e in tls.endpoints if e.endpoint == "api.bank.example")
    payload = endpoint.to_dict()
    assert payload["service"] == "elbv2"
    assert payload["application"] == "payments-api"
    assert payload["tls_version"] == "TLSv1.3"
    assert payload["certificate"] == "arn:aws:acm:cert-1"
    assert payload["key_exchange"] == "ECDHE"
    assert payload["public_key_size"] == 2048
    assert payload["evidence"]["api_source"] == "tls-discovery"
    assert "alpn" in payload and "sni" in payload and "curve" in payload


def test_tls_summary_counts():
    tls = TlsDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = tls.summary()
    assert summary["by_classification"]["TLS_SECURE"] == 3
    assert summary["by_classification"]["TLS_LEGACY"] == 1
