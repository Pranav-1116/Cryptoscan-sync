"""ZELNX §3 keys + §4 certificates + §5 PKI intelligence."""

from __future__ import annotations

from cloud_scanner.enterprise.certificate_discovery import CertificateDiscovery
from cloud_scanner.enterprise.key_discovery import KeyDiscovery, algorithm_for_spec, normalize_key
from cloud_scanner.enterprise.pki_intelligence import PkiIntelligenceEngine

from zelix_fixtures import all_providers


# ------------------------------------------------------------------ §3 keys


def test_key_discovery_finds_all_providers():
    keys = KeyDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert keys.count() == 6  # 3 aws + 1 azure + 2 gcp
    assert keys.count("aws") == 3
    assert keys.count("azure") == 1
    assert keys.count("gcp") == 2


def test_key_algorithm_mapping():
    assert algorithm_for_spec("SYMMETRIC_DEFAULT", "aws") == ("AES", 256)
    assert algorithm_for_spec("RSA_2048", "aws") == ("RSA", 2048)
    assert algorithm_for_spec("ECC_NIST_P384", "aws") == ("ECDSA", 384)
    assert algorithm_for_spec("EC_SIGN_P256_SHA256", "gcp") == ("ECDSA", 256)
    assert algorithm_for_spec("RSA-HSM 2048", "azure") == ("RSA", 2048)


def test_key_rotation_and_manager_summary():
    keys = KeyDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = keys.summary()
    assert summary["keys"] == 6
    assert summary["customer_managed"] == 5
    assert summary["provider_managed"] == 1
    # key-2 (aws) and key-2 (gcp) are non-rotating customer keys
    assert summary["non_rotating_customer_keys"] == 2
    assert summary["hsm_backed"] == 2  # azure RSA-HSM + gcp HSM protection


def test_key_never_exposes_key_material():
    raw = {"key_id": "k1", "name": "k1", "key_material": "SUPER-SECRET-PRIVATE-KEY",
           "private_key": "-----BEGIN PRIVATE KEY-----"}
    key = normalize_key(raw, provider="aws")
    payload = key.to_dict()
    assert "key_material" not in payload
    assert "private_key" not in payload
    assert "SUPER-SECRET-PRIVATE-KEY" not in str(payload)


def test_key_aliases_grants_and_multi_region():
    key = normalize_key({
        "key_id": "arn:kms:1", "name": "m", "key_spec": "SYMMETRIC_DEFAULT",
        "aliases": ["alias/a", "alias/b"], "grants": [{"grantee": "role-x", "ops": ["Encrypt"]}],
        "multi_region": True, "origin": "AWS_KMS", "rotation_enabled": True,
    }, provider="aws")
    assert key.aliases == ["alias/a", "alias/b"]
    assert key.grants == [{"grantee": "role-x", "ops": ["Encrypt"]}]
    assert key.multi_region is True
    assert key.origin == "AWS_KMS"


def test_key_curve_detection():
    key = normalize_key({"key_id": "k", "key_spec": "EC_SIGN_P256_SHA256"}, provider="gcp")
    assert key.curve == "P-256"


def test_key_discovery_errors_recorded():
    def boom():
        raise RuntimeError("kms denied")

    keys = KeyDiscovery([{"provider": "aws", "enumerate_keys": boom}]).discover()
    assert keys.errors
    assert "kms denied" in keys.errors[0]["detail"]


# ------------------------------------------------------------------ §4 certs


def test_certificate_discovery_all_providers_and_graph():
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    assert certs.count() == 4  # 2 aws + 1 azure + 1 gcp
    relations = certs.relations
    kinds = {rel.kind for rel in relations}
    assert "ISSUED_BY_CA" in kinds
    assert "USED_BY_APPLICATION" in kinds
    assert "STORED_IN_VAULT" in kinds
    assert "CONNECTED_TO_DOMAIN" in kinds
    assert "USED_BY_LOAD_BALANCER" in kinds


def test_certificate_relation_targets():
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    aws = certs.by_provider("aws")
    cert1 = next(c for c in aws if c.certificate_id == "arn:aws:acm:cert-1")
    assert cert1.used_by == ["payments-api"]
    assert cert1.dependencies == ["arn:aws:elb:lb-1"]
    rels = [r for r in certs.relations if r.certificate_id == cert1.certificate_id]
    assert any(r.kind == "USED_BY_APPLICATION" and r.target == "payments-api" for r in rels)
    assert any(r.kind == "USED_BY_LOAD_BALANCER" and r.target == "arn:aws:elb:lb-1" for r in rels)
    assert any(r.kind == "ISSUED_BY_CA" and r.target == "arn:aws:acm-pca:ca-root" for r in rels)
    assert any(r.kind == "CONNECTED_TO_DOMAIN" and r.target == "api.bank.example" for r in rels)


def test_certificate_expiry_detection():
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    expiring = certs.expiring(days=30)
    assert [cert.domain for cert in expiring] == ["expiring.bank.example"]


def test_certificate_imported_flag():
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    aws = certs.by_provider("aws")
    cert1 = next(c for c in aws if c.certificate_id == "arn:aws:acm:cert-1")
    assert cert1.imported is False
    assert cert1.signature_algorithm == "SHA256WithRSA"
    assert cert1.public_key_algorithm == "RSA"


def test_certificate_summary():
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    summary = certs.summary()
    assert summary["certificates"] == 4
    assert summary["relations"] == len(certs.relations)
    assert summary["by_relation_kind"]["STORED_IN_VAULT"] == 1


def test_certificate_explicit_relations_enumerator():
    rows = {
        "certificates": [{"certificate_id": "c1", "domain": "x.example", "provider": "aws"}],
        "relations": [{"certificate_id": "c1", "kind": "USED_BY_LOAD_BALANCER",
                       "target": "lb-9"}],
    }
    from cloud_scanner.enterprise.providers import fake_provider

    certs = CertificateDiscovery([fake_provider("aws", rows).to_provider_entry()]).discover()
    assert any(rel.kind == "USED_BY_LOAD_BALANCER" and rel.target == "lb-9"
               for rel in certs.relations)


# ------------------------------------------------------------------ §5 PKI


def test_pki_hierarchy_roots_and_chain():
    pki = PkiIntelligenceEngine([p.to_provider_entry() for p in all_providers()]).discover()
    roots = pki.roots()
    assert len(roots) == 2  # aws ca-root + gcp ca-root
    chain = pki.chain_for("arn:aws:acm-pca:ca-sub")
    assert [node.ca_id for node in chain] == [
        "arn:aws:acm-pca:ca-root", "arn:aws:acm-pca:ca-sub"]
    gcp_chain = pki.chain_for("ca-service://ca-bank")
    assert [node.ca_id for node in gcp_chain] == ["ca-service://ca-root", "ca-service://ca-bank"]


def test_pki_trust_relationships():
    pki = PkiIntelligenceEngine([p.to_provider_entry() for p in all_providers()]).discover()
    trust = [rel for rel in pki.trust if rel.provider == "aws"]
    assert len(trust) == 1
    assert trust[0].parent_id == "arn:aws:acm-pca:ca-root"
    assert trust[0].child_id == "arn:aws:acm-pca:ca-sub"
    assert trust[0].kind == "SIGNS"


def test_pki_certificate_consumers_attached():
    pki = PkiIntelligenceEngine([p.to_provider_entry() for p in all_providers()]).discover()
    certs = CertificateDiscovery([p.to_provider_entry() for p in all_providers()]).discover()
    pki = PkiIntelligenceEngine([p.to_provider_entry() for p in all_providers()]).discover(
        certificates=certs.certificates)
    ca = next(ca for ca in pki.cas if ca.ca_id == "arn:aws:acm-pca:ca-root")
    assert "api.bank.example" in ca.consumers


def test_pki_weak_chains_detected():
    rows = {
        "cas": [
            {"ca_id": "ca-root", "ca_type": "ROOT", "signature_algorithm": "SHA256WithRSA",
             "public_key_algorithm": "RSA", "key_size": 2048},
            {"ca_id": "ca-weak", "ca_type": "SUBORDINATE", "parent_id": "ca-root",
             "signature_algorithm": "SHA1WithRSA", "public_key_algorithm": "RSA",
             "key_size": 1024},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    pki = PkiIntelligenceEngine([fake_provider("aws", rows).to_provider_entry()]).discover()
    flagged = pki.weak_chains()
    assert len(flagged) == 1
    assert any("weak signature" in issue for issue in flagged[0]["issues"])
    assert any("small RSA key" in issue for issue in flagged[0]["issues"])


def test_pki_expiring_cas():
    rows = {
        "cas": [
            {"ca_id": "ca-soon", "ca_type": "ROOT", "expires_at": "2026-09-10T00:00:00Z"},
            {"ca_id": "ca-far", "ca_type": "ROOT", "expires_at": "2040-01-01T00:00:00Z"},
        ]
    }
    from cloud_scanner.enterprise.providers import fake_provider

    pki = PkiIntelligenceEngine([fake_provider("aws", rows).to_provider_entry()]).discover()
    expiring = pki.expiring_cas(days=90)
    assert [ca.ca_id for ca in expiring] == ["ca-soon"]


def test_pki_templates_and_types():
    pki = PkiIntelligenceEngine([p.to_provider_entry() for p in all_providers()]).discover()
    aws_root = next(ca for ca in pki.cas if ca.ca_id == "arn:aws:acm-pca:ca-root")
    assert aws_root.ca_type == "ROOT"
    assert aws_root.templates == ["server-tls"]
    assert aws_root.key_size == 4096
