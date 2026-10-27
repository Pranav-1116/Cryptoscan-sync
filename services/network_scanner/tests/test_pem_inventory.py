from pathlib import Path

from network_scanner.certificates.cert_parser import hostname_matches, parse_pem
from network_scanner.certificates.chain_validator import validate_chain
from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.inventory.certificate_inventory import link_issuer_ids

CERTS = Path(__file__).resolve().parent / "fixtures" / "certs"


def _load(name: str) -> dict:
    parsed = parse_pem((CERTS / name).read_text(encoding="utf-8"))
    assert parsed, name
    return parsed[0]


def test_openssl_parses_leaf_extensions():
    leaf = _load("valid_leaf.pem")
    assert leaf["public_key_algorithm"] == "RSA"
    assert leaf["public_key_size"] == 2048
    assert leaf["signature_algorithm"] == "sha256WithRSAEncryption"
    assert "DNS:api.payment.example.com" in leaf["san"]
    assert "DNS:www.example.com" in leaf["san"]
    assert "digitalSignature" in leaf["key_usage"]
    assert "keyEncipherment" in leaf["key_usage"]
    assert "serverAuth" in leaf["extended_key_usage"]
    assert leaf.get("is_ca") is not True
    assert leaf["ocsp_url"] == "http://ocsp.cryptoscan.test/ocsp"
    assert leaf["crl_url"] == "http://crl.cryptoscan.test/ca.crl"
    assert hostname_matches("api.payment.example.com", leaf)
    assert hostname_matches("www.example.com", leaf)
    assert not hostname_matches("other.example.com", leaf)
    assert leaf["expiry_status"] == "VALID"
    assert leaf["days_until_expiry"] > 30


def test_root_is_ca_and_self_signed_expired_and_self():
    root = _load("valid_root.pem")
    assert root["is_ca"] is True
    assert root["is_self_signed"] is True
    expired = _load("expired_cert.pem")
    assert expired["expiry_status"] == "EXPIRED"
    assert expired["days_until_expiry"] < 0
    self_signed = _load("self_signed.pem")
    assert self_signed["is_self_signed"] is True
    assert "DNS:self.example.com" in self_signed["san"]


def test_chain_links_leaf_to_root():
    leaf = _load("valid_leaf.pem")
    intermediate = _load("valid_intermediate.pem")
    root = _load("valid_root.pem")
    result = validate_chain([leaf, intermediate, root], hostname="api.payment.example.com")
    assert result["is_valid"] is True
    assert result["chain_length"] == 3
    inventory = link_issuer_ids([dict(leaf), dict(intermediate), dict(root)])
    by_subject = {row["subject"]: row for row in inventory}
    linked_leaf = next(row for row in inventory if "api.payment.example.com" in (row.get("subject") or ""))
    assert linked_leaf["issuer_cert_id"] == by_subject[intermediate["subject"]]["fingerprint_sha256"]


def test_network_scanner_inventories_fixture_certs():
    result = NetworkTlsScanner(live=False).scan_filesystem(CERTS)
    subjects = " ".join(cert.get("subject") or "" for cert in result["certificates"])
    assert "api.payment.example.com" in subjects
    assert "CryptoScan Test Root" in subjects
    statuses = {cert["expiry_status"] for cert in result["certificates"]}
    assert "EXPIRED" in statuses
    assert "VALID" in statuses
    leaf = next(cert for cert in result["certificates"] if "api.payment.example.com" in (cert.get("subject") or ""))
    assert leaf.get("issuer_cert_id")
    assert leaf["chain_validation"]["chain_length"] >= 2
    assert leaf["ocsp_url"]
    finding = next(item for item in result["findings"] if item.get("algorithm") == "RSA" and item.get("key_size") == 2048)
    assert finding["purpose"] == "CERTIFICATE"
