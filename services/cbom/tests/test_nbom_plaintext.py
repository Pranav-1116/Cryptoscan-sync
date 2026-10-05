"""No transport encryption is the worst posture, not a neutral one.

assess_tls_version() grades the version it is handed and returns [] when
there is nothing to grade. That left a hole exactly where it mattered: an
endpoint speaking TLS 1.0 was critical, and an endpoint speaking no TLS at
all was silent.

Found by scanning a real host rather than a fixture. Fourteen listening
services — PostgreSQL, MySQL, Redis, AMQP, RabbitMQ management, InfluxDB
and the product's own API among them — every one plaintext, and the NBOM
returned `findings: 0`.

It also contradicted the module's own stated rule: absence of evidence is
never a pass. An observed endpoint with no negotiated version is not
missing data; the probe succeeded and the answer was "none". Unprobed
endpoints are a separate case and are already excluded by observed=false.
"""

from __future__ import annotations

import pytest

from cbom.nbom import (
    assess_cipher_suite, assess_transport_encryption, build_nbom, summarise,
)


def _codes(bom: dict, kind: str | None = None) -> list[str]:
    out = []
    for c in bom["components"]:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if kind and props.get("cryptoscan:kind") != kind:
            continue
        for f in c.get("cryptoscan:findings", []):
            out.append(f["code"])
    return out


# ── the assessor itself ────────────────────────────────────────────────

def test_absent_tls_and_suite_is_plaintext():
    findings = assess_transport_encryption(None, None)
    assert [f["code"] for f in findings] == ["nbom.no_transport_encryption"]
    assert findings[0]["severity"] == "critical"


def test_a_negotiated_version_is_not_plaintext():
    assert assess_transport_encryption("TLSv1.3", None) == []


def test_a_negotiated_suite_alone_is_not_plaintext():
    """Some probes record the suite but not the version; that is still TLS."""
    assert assess_transport_encryption(None, "TLS_AES_256_GCM_SHA384") == []


def test_empty_strings_count_as_absent():
    assert assess_transport_encryption("", "  ") != []


# ── through build_nbom ─────────────────────────────────────────────────

def test_plaintext_endpoint_is_now_flagged():
    bom = build_nbom([
        {"host": "127.0.0.1", "port": 5432, "service": "postgresql",
         "observed": True, "protocol": "PLAINTEXT"},
    ])
    assert "nbom.no_transport_encryption" in _codes(bom)
    assert summarise(bom)["by_severity"]["critical"] == 1


def test_unprobed_endpoint_is_still_scored_by_nothing():
    """The honesty rule must not be traded away to close the hole."""
    bom = build_nbom([
        {"host": "10.0.0.9", "port": 443, "observed": False},
    ])
    assert _codes(bom) == []
    assert summarise(bom)["unobserved"] == 1


def test_tls13_endpoint_stays_clean():
    bom = build_nbom([
        {"host": "10.0.0.1", "port": 443, "observed": True,
         "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
    ])
    assert _codes(bom) == []


# ── TLS 1.3 was being told it had no forward secrecy ───────────────────

@pytest.mark.parametrize("suite", [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
])
def test_tls13_suites_are_not_accused_of_lacking_forward_secrecy(suite):
    """RFC 8446 §B.4 names carry no key-exchange token.

    (EC)DHE is mandatory in TLS 1.3 — the handshake has no static-key mode
    — so the names omit it. Matching on the absence of "ecdhe"/"dhe"
    therefore flagged every TLS 1.3 endpoint, which is a false positive on
    exactly the configuration an estate is being moved toward. Caught by a
    test asserting a clean TLS 1.3 endpoint, not by reading the rule.
    """
    assert [f["code"] for f in assess_cipher_suite(suite)] == []


def test_static_rsa_still_lacks_forward_secrecy():
    """The check must keep catching the case it was written for."""
    codes = [f["code"] for f in assess_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA")]
    assert "nbom.no_forward_secrecy" in codes


def test_ecdhe_suite_remains_clean():
    codes = [f["code"] for f in assess_cipher_suite(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]
    assert "nbom.no_forward_secrecy" not in codes


def test_the_real_localhost_estate_no_longer_reports_zero():
    """The scan that exposed this: every service plaintext, findings 0."""
    ports = [3003, 3306, 3310, 5432, 5672, 6379, 8010, 8086,
             10000, 11434, 15672, 55440, 55441]
    endpoints = [{"host": "127.0.0.1", "port": p, "observed": True,
                  "protocol": "PLAINTEXT"} for p in ports]
    # One endpoint timed out: inventoried, scored by nothing.
    endpoints.append({"host": "127.0.0.1", "port": 3000, "observed": False})

    summary = summarise(build_nbom(endpoints))
    assert summary["by_severity"]["critical"] == len(ports)
    assert summary["unobserved"] == 1


# ── tunnels had the same blind spot ────────────────────────────────────

def test_tunnel_declaring_no_encryption_is_flagged():
    bom = build_nbom([], tunnels=[
        {"name": "site-to-site", "kind": "ipsec", "peer": "10.1.1.1"},
    ])
    codes = _codes(bom)
    assert "nbom.no_tunnel_encryption" in codes
    assert "nbom.no_tunnel_integrity" in codes


def test_unobserved_tunnel_is_scored_by_nothing_and_counted():
    bom = build_nbom([], tunnels=[
        {"name": "unreachable", "kind": "ipsec", "observed": False},
    ])
    assert _codes(bom) == []
    assert summarise(bom)["unobserved"] == 1


def test_a_configured_tunnel_keeps_its_existing_verdict():
    bom = build_nbom([], tunnels=[
        {"name": "strong", "kind": "ipsec", "encryption": "AES-256-GCM",
         "integrity": "SHA-256"},
    ])
    codes = _codes(bom)
    assert "nbom.no_tunnel_encryption" not in codes
    assert "nbom.no_tunnel_integrity" not in codes
