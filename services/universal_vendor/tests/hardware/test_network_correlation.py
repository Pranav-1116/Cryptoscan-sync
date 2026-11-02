"""H6: tying a network device to the certificates it actually terminates.

The failure this guards against is a load balancer in the estate with a
management IP and no relationship to the card-auth certificate it serves — a
box nobody can reason about. The other failure is the opposite: an edge invented
because two things exist.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from universal_vendor.hardware.network_correlation import (
    CertificateNotIdentified,
    CertificateRef,
    certificate_exposure,
    correlate,
    derive_network_edges,
    device_blast_radius,
    shared_certificates,
)
from universal_vendor.hardware.relationships import UnevidencedRelationship

PROBE = {
    "device": "lb-01", "port": 443,
    "fingerprint_sha256": "ab12cd34", "subject": "CN=card-auth.bank.example",
    "issuer": "CN=Bank Issuing CA", "san": ["DNS:card-auth.bank.example"],
    "not_after": "2027-01-10T00:00:00+00:00",
}

CONFIG = """
hostname lb-01
crypto pki trustpoint BANK-ROOT
 ssl certificate card-auth
 pkcs11 label: HSM-01
"""


def test_a_tls_observation_becomes_an_evidenced_edge():
    edges = derive_network_edges("lb-01", tls_observations=[PROBE])
    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind == "TERMINATES_TLS"
    assert edge.subject == "cert:ab12cd34"
    assert edge.hardware == "lb-01"
    assert edge.confidence == "HIGH"
    assert edge.evidence[0].kind == "OBSERVED"
    assert "tls-probe:lb-01:443" in edge.evidence[0].reference


def test_a_device_with_no_certificate_and_no_config_earns_no_edges():
    """A management IP is not a TLS relationship."""
    assert derive_network_edges("sw-01") == []
    assert derive_network_edges("sw-01", tls_observations=[]) == []


def test_a_certificate_needs_an_identity():
    with pytest.raises(CertificateNotIdentified):
        CertificateRef.from_probe({"device": "lb-01", "port": 443})
    with pytest.raises(CertificateNotIdentified):
        CertificateRef(fingerprint=None, subject=None)


def test_a_certificate_observed_on_another_device_is_refused():
    """Attributing a certificate to the wrong appliance is worse than missing it."""
    with pytest.raises(ValueError) as caught:
        derive_network_edges("lb-02", tls_observations=[PROBE])
    assert "must not be attributed to another" in str(caught.value)


def test_config_naming_a_certificate_is_config_evidence():
    edges = derive_network_edges("lb-01", config_text=CONFIG,
                                 config_reference="devices/lb-01.conf")
    certificates = {edge.subject: edge for edge in edges
                    if edge.kind == "TERMINATES_TLS"}
    assert "cert:card-auth" in certificates
    assert certificates["cert:card-auth"].evidence[0].kind == "CONFIG"
    assert "devices/lb-01.conf" in certificates["cert:card-auth"].evidence[0].reference


def test_config_naming_an_hsm_token_uses_the_base_rule():
    edges = derive_network_edges("lb-01", config_text=CONFIG,
                                 config_reference="devices/lb-01.conf")
    hsm = [edge for edge in edges if edge.kind == "USES_HSM"]
    assert len(hsm) == 1
    assert hsm[0].hardware == "HSM-01"
    assert hsm[0].evidence[0].kind == "CONFIG"


def test_a_config_word_that_is_not_a_certificate_name_is_ignored():
    edges = derive_network_edges("lb-01", config_text="ssl certificate none\n")
    assert [edge for edge in edges if edge.kind == "TERMINATES_TLS"] == []


def test_observed_and_declared_collapse_to_one_edge_with_the_weaker_confidence():
    edges = derive_network_edges("lb-01", tls_observations=[PROBE],
                                 declared_certificates=["ab12cd34"])
    matching = [edge for edge in edges if edge.subject == "cert:ab12cd34"]
    assert len(matching) == 1
    assert matching[0].confidence == "MEDIUM", "a CMDB row drags the weakest citation in"
    assert {item.kind for item in matching[0].evidence} == {"OBSERVED", "DECLARED"}


def test_an_evidence_reference_carrying_a_secret_is_refused():
    """Inherited from the base module: the pointer is a location, not a value."""
    with pytest.raises(UnevidencedRelationship):
        derive_network_edges("lb-01", config_text=CONFIG,
                             config_reference="devices/lb-01.conf?password=hunter2")


def test_fronting_another_device_is_typed_and_self_reference_is_refused():
    edges = derive_network_edges("lb-01", fronts=["fw-01"])
    assert [(edge.subject, edge.hardware, edge.kind) for edge in edges] == [
        ("lb-01", "fw-01", "FRONTS")]
    with pytest.raises(ValueError):
        derive_network_edges("lb-01", fronts=["lb-01"])


def test_an_ha_pair_shares_its_certificate():
    pair = derive_network_edges("lb-01", tls_observations=[PROBE])
    pair += derive_network_edges("lb-02", tls_observations=[{**PROBE, "device": "lb-02"}])
    assert shared_certificates(pair) == {"cert:ab12cd34": ["lb-01", "lb-02"]}


def test_a_single_device_shares_nothing():
    edges = derive_network_edges("lb-01", tls_observations=[PROBE])
    assert shared_certificates(edges) == {}


def test_blast_radius_of_a_device_names_the_certificates_at_risk():
    edges = derive_network_edges("lb-01", tls_observations=[PROBE], config_text=CONFIG,
                                 config_reference="devices/lb-01.conf")
    radius = device_blast_radius("lb-01", edges)
    assert radius["hardware"] == "lb-01"
    assert "cert:ab12cd34" in radius["certificates_at_risk"]
    assert radius["applications_affected"] == 0, "no application edge was evidenced"


def test_expiring_certificates_are_placed_on_their_device():
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    edges = derive_network_edges("lb-01", tls_observations=[PROBE])
    soon = CertificateRef(fingerprint="ff99", subject="CN=soon.example",
                          not_after=(now + timedelta(days=7)).isoformat())
    far = CertificateRef(fingerprint="ee88", subject="CN=far.example",
                         not_after=(now + timedelta(days=365)).isoformat())
    exposure = certificate_exposure(edges, [soon, far], within_days=90, now=now)
    assert exposure["count"] == 1
    assert exposure["expiring"][0]["certificate"] == "cert:ff99"
    assert exposure["expiring"][0]["severity"] == "HIGH"
    assert exposure["expiring"][0]["placed"] is False
    assert exposure["unplaced"][0]["certificate"] == "cert:ff99"


def test_a_placed_certificate_is_not_reported_as_unplaced():
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    edges = derive_network_edges("lb-01", tls_observations=[PROBE])
    certificate = CertificateRef.from_probe({**PROBE, "not_after":
                                             (now + timedelta(days=30)).isoformat()})
    exposure = certificate_exposure(edges, [certificate], within_days=90, now=now)
    assert exposure["expiring"][0]["placed"] is True
    assert exposure["expiring"][0]["device"] == "lb-01"
    assert exposure["expiring"][0]["severity"] == "MEDIUM"


def test_an_unreadable_expiry_is_reported_not_guessed():
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    certificate = CertificateRef(fingerprint="dd77", not_after="not a date")
    exposure = certificate_exposure([], [certificate], now=now)
    assert exposure["unknown_expiry"] == ["cert:dd77"]
    assert exposure["count"] == 0


def test_correlate_returns_a_storable_result():
    result = correlate("lb-01", tls_observations=[PROBE], config_text=CONFIG,
                       config_reference="devices/lb-01.conf")
    assert result["schema"] == "cryptoscan.network-correlation/1"
    assert result["device"] == "lb-01"
    assert result["by_kind"]["TERMINATES_TLS"] >= 1
    assert result["certificates"][0]["fingerprint_sha256"] == "ab12cd34"
    assert result["edge_count"] == len(result["edges"])
