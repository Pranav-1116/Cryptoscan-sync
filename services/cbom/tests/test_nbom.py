"""NBOM — network inventory, CycloneDX shape, and the cascade graph.

The cascade tests are the point. A flat inventory can tell you a certificate
is RSA-1024; only the dependency graph can tell you which endpoints serve it
and which devices terminate those, which is what a migration is planned from.
"""

from __future__ import annotations

from cbom.nbom import build_nbom, cascade, summarise

SHARED_CERT = {
    "subject": "CN=wildcard.bank.ae",
    "issuer": "CN=Bank Internal CA",
    "serial_number": "01",
    "public_key_algorithm": "RSA",
    "public_key_size": 1024,
}


def _estate():
    return build_nbom(
        [
            {"host": "ib.bank.ae", "port": 443, "tls_version": "TLS1.2",
             "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
             "certificate": SHARED_CERT, "device": "f5-edge-01"},
            {"host": "api.bank.ae", "port": 443, "tls_version": "TLS1.0",
             "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
             "certificate": SHARED_CERT, "device": "f5-edge-01"},
            {"host": "legacy.bank.ae", "port": 8443, "observed": False},
        ],
        tunnels=[{"name": "ipx-alpha", "kind": "ipsec", "peer": "10.0.0.1",
                  "encryption": "3DES-CBC", "integrity": "HMAC-SHA1",
                  "key_exchange": "DH", "key_exchange_bits": 1024,
                  "device": "fw-core-01"}],
        estate="bank-ae",
    )


def _findings(nbom, code):
    return [f for c in nbom["components"] for f in c["cryptoscan:findings"] if f["code"] == code]


# --------------------------------------------------------- CycloneDX shape


def test_nbom_is_valid_cyclonedx_1_5():
    n = _estate()
    assert n["bomFormat"] == "CycloneDX" and n["specVersion"] == "1.5"
    assert n["serialNumber"].startswith("urn:uuid:")
    assert n["metadata"]["component"]["name"] == "bank-ae"
    assert n["components"] and n["dependencies"]


def test_refs_are_stable_across_runs_so_boms_diff_cleanly():
    a = {c["bom-ref"] for c in _estate()["components"]}
    b = {c["bom-ref"] for c in _estate()["components"]}
    assert a == b


def test_a_shared_certificate_is_one_component_not_two():
    n = _estate()
    certs = [c for c in n["components"]
             if any(p["value"] == "certificate" and p["name"] == "cryptoscan:kind"
                    for p in c["properties"])
             and c["name"] == "CN=wildcard.bank.ae"]
    assert len(certs) == 1, "the same cert on two endpoints must deduplicate"


# ------------------------------------------------------------- assessment


def test_disallowed_tls_version_is_critical():
    assert _findings(_estate(), "nbom.tls_version_disallowed")[0]["severity"] == "critical"


def test_3des_suite_is_high():
    assert _findings(_estate(), "nbom.weak_cipher_suite")[0]["severity"] == "high"


def test_suite_without_forward_secrecy_is_flagged():
    assert _findings(_estate(), "nbom.no_forward_secrecy")


def test_short_rsa_certificate_is_critical():
    assert _findings(_estate(), "nbom.rsa_key_too_short")[0]["severity"] == "critical"


def test_shor_vulnerability_is_recorded_as_inventory_not_alarm():
    assert all(f["severity"] == "info" for f in _findings(_estate(), "nbom.shor_vulnerable"))


def test_weak_tunnel_algorithms_are_flagged():
    assert _findings(_estate(), "nbom.weak_tunnel_algorithm")


def test_an_unobserved_endpoint_contributes_no_verdict():
    """Absence of evidence is not a pass — and not a failure either."""
    n = _estate()
    legacy = next(c for c in n["components"] if c["name"] == "legacy.bank.ae:8443")
    assert legacy["cryptoscan:findings"] == []
    assert {"name": "cryptoscan:observed", "value": "False"} in legacy["properties"]
    assert summarise(n)["unobserved"] == 1


# ---------------------------------------------------------------- cascade


def test_cascade_from_a_shared_certificate_reaches_every_dependent():
    """The number a migration is planned from."""
    n = _estate()
    cert_ref = next(c["bom-ref"] for c in n["components"] if c["name"] == "CN=wildcard.bank.ae")
    result = cascade(n, cert_ref)

    assert result["found"] is True
    names = {a["name"] for a in result["affected"]}
    assert {"ib.bank.ae:443", "api.bank.ae:443", "f5-edge-01"} <= names
    assert result["by_kind"]["endpoint"] == 2


def test_cascade_walks_backwards_not_down_to_the_issuer():
    n = _estate()
    cert_ref = next(c["bom-ref"] for c in n["components"] if c["name"] == "CN=wildcard.bank.ae")
    assert "CN=Bank Internal CA" not in {a["name"] for a in cascade(n, cert_ref)["affected"]}


def test_cascade_from_the_issuer_reaches_the_leaf_and_beyond():
    n = _estate()
    ca_ref = next(c["bom-ref"] for c in n["components"] if c["name"] == "CN=Bank Internal CA")
    names = {a["name"] for a in cascade(n, ca_ref)["affected"]}
    assert "CN=wildcard.bank.ae" in names and "ib.bank.ae:443" in names


def test_cascade_on_an_unknown_ref_is_reported_not_raised():
    assert cascade(_estate(), "certificate:deadbeef")["found"] is False


def test_summary_ranks_migration_by_severity_then_blast_radius():
    s = summarise(_estate())
    assert s["by_severity"]["critical"] >= 2
    assert s["by_kind"]["endpoint"] == 3
    top = s["migration_priority"][0]
    assert top["worst_severity"] == "critical"
    # Ranked entries carry their blast radius, which is what makes them orderable.
    assert "affected_count" in top


def test_empty_estate_is_a_valid_empty_bom():
    n = build_nbom([])
    assert n["bomFormat"] == "CycloneDX" and n["components"] == []
    assert summarise(n)["components"] == 0


# ------------------------------------------- cross-BOM correlation (xBOM)

from cbom.assurance import correlate_xbom  # noqa: E402


def _state_with_network():
    """A CBOM asset that is also exposed on the wire."""
    nbom = build_nbom([
        {"host": "api.bank.ae", "port": 443, "tls_version": "TLS1.0",
         "certificate": SHARED_CERT, "device": "f5-edge-01"},
    ])
    return {
        "layers": {
            "cbom": {"components": [
                {"bom-ref": "crypto:1", "algorithm": "RSA", "key_size": 1024,
                 "purpose": "TLS", "asset": "api.bank.ae"},
            ]},
            "sbom": {"components": []},
            "hbom": {"components": []},
            "vendor": {"components": []},
            "nbom": {"components": nbom["components"]},
        }
    }


def test_correlation_links_a_crypto_asset_to_its_network_exposure():
    """'We use RSA-1024 somewhere' vs 'api.bank.ae:443 presents it'."""
    result = correlate_xbom(_state_with_network())
    trace = result["traces"][0]
    names = {n["name"] for n in trace["network"]}
    assert "api.bank.ae:443" in names
    assert trace["impact_count"]["network_exposure"] >= 1


def test_correlation_without_an_nbom_layer_is_unchanged():
    """An estate with no network scan must correlate exactly as before."""
    state = _state_with_network()
    del state["layers"]["nbom"]
    trace = correlate_xbom(state)["traces"][0]
    assert trace["network"] == []
    assert trace["impact_count"]["network_exposure"] == 0
