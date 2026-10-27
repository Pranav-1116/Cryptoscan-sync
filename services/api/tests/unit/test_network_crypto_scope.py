"""Cryptographic Network Intelligence — approved scope and evidence normalization.

Spec: ``docs/bank-environment/67-network-crypto-discovery-engine.md`` §3, §23,
§24, §29, §30.

These tests never open a socket. They pin the fail-closed scope contract and the
honesty rules of the evidence record: an unobserved endpoint stays UNKNOWN, and
a server-only handshake never claims mTLS was disabled.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.security.network_scope import ScopeViolation, check_scope, normalize_endpoint, scope_key
from network_scanner.inventory.network_evidence import (
    EVIDENCE_TYPES,
    build_evidence,
    evidence_type_for,
    summarize,
)

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def scope(**overrides):
    document = {
        "name": "payments-prod",
        "type": "network",
        "destinations": ["10.20.10.15:443", "10.20.10.16:443"],
        "protocols": ["TLS"],
        "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        "traffic_budget": {"max_connections": 20, "max_bytes": 10485760},
        "valid_until": (NOW + timedelta(hours=6)).isoformat(),
    }
    document.update(overrides)
    return document


# --------------------------------------------------------------------------- #
# scope key + normalization
# --------------------------------------------------------------------------- #


def test_scope_key_is_tenant_scoped():
    assert scope_key("bank-a") == "network:crypto-scope:bank-a:default"
    assert scope_key(None, "core") == "network:crypto-scope:default:core"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.20.10.15", "10.20.10.15:443"),
        ("10.20.10.15:8443", "10.20.10.15:8443"),
        ("PAYMENTS.Bank.", "payments.bank:443"),
        ("[2001:db8::1]:443", "[2001:db8::1]:443"),
    ],
)
def test_endpoint_normalization(raw, expected):
    assert normalize_endpoint(raw) == expected


# --------------------------------------------------------------------------- #
# fail-closed scope enforcement
# --------------------------------------------------------------------------- #


def test_no_scope_refuses():
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(None, ["10.20.10.15:443"], now=NOW)
    assert excinfo.value.code == "scope_not_configured"


def test_empty_destinations_refused():
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(scope(), [], now=NOW)
    assert excinfo.value.code == "empty_targets"


def test_expired_scope_refuses():
    expired = scope(valid_until=(NOW - timedelta(minutes=1)).isoformat())
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(expired, ["10.20.10.15:443"], now=NOW)
    assert excinfo.value.code == "scope_expired"


def test_destination_outside_scope_refuses():
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(scope(), ["10.20.10.15:443", "10.99.99.99:443"], now=NOW)
    assert excinfo.value.code == "destination_outside_scope"
    assert excinfo.value.detail["outside"] == ["10.99.99.99:443"]


def test_wildcard_cidr_is_not_a_destination():
    # A /8 is never an approved destination: it cannot match an exact host:port.
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(scope(), ["10.0.0.0/8"], now=NOW)
    assert excinfo.value.code == "destination_outside_scope"


def test_protocol_outside_scope_refuses():
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(scope(), ["10.20.10.15:443"], protocol="SSH", now=NOW)
    assert excinfo.value.code == "protocol_not_allowed"


def test_operation_outside_scope_refuses():
    limited = scope(allowed_operations=["CONNECT"])
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(limited, ["10.20.10.15:443"], protocol="TLS", now=NOW)
    assert excinfo.value.code == "operation_not_allowed"


def test_traffic_budget_refuses_oversized_run():
    tight = scope(traffic_budget={"max_connections": 1, "max_bytes": 10485760})
    with pytest.raises(ScopeViolation) as excinfo:
        check_scope(tight, ["10.20.10.15:443", "10.20.10.16:443"], now=NOW)
    assert excinfo.value.code == "traffic_budget_exceeded"


def test_permitted_run_returns_receipt():
    receipt = check_scope(scope(), ["10.20.10.15:443"], protocol="TLS", now=NOW)
    assert receipt["decision"] == "PERMITTED"
    assert receipt["destinations"] == ["10.20.10.15:443"]
    assert receipt["protocol"] == "TLS"
    assert receipt["operations"] == ["CERTIFICATE_READ", "CONNECT", "TLS_HANDSHAKE"]
    assert receipt["schema"] == "cryptoscan.network-scope-admission/1"


# --------------------------------------------------------------------------- #
# evidence records — spec §24 / §29
# --------------------------------------------------------------------------- #


def observed_finding():
    return {
        "finding_id": "evidence-1",
        "endpoint": "10.20.10.15:443",
        "status": "OK",
        "ip_address": "10.20.10.15",
        "crypto": {
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange_algorithm": "ECDHE",
            "authentication_algorithm": "ECDSA",
            "encryption_algorithm": "AES-256",
            "encryption_mode": "GCM",
            "mac_algorithm": "SHA384",
            "key_size": 256,
        },
        "certificates": [
            {
                "fingerprint_sha256": "sha256:abc",
                "subject": "CN=payments.bank",
                "issuer": "CN=Bank Intermediate CA",
                "public_key_algorithm": "ECDSA",
                "public_key_bits": 256,
                "curve": "P-256",
                "signature_algorithm": "ecdsa-with-SHA256",
                "san": ["payments.bank"],
            }
        ],
        "chain_validation": {"structural_status": "OK", "trust_status": "NOT_VERIFIED", "chain_completeness": "COMPLETE"},
        "policy_issues": [],
        "metadata": {"confidence": "HIGH", "endpoint_hostname": "10.20.10.15"},
    }


def test_observed_record_is_decomposed_and_typed():
    record = build_evidence(observed_finding(), scope_name="payments-prod", scope_revision="rev-1")
    assert record["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert record["evidence_type"] in EVIDENCE_TYPES
    assert record["schema"] == "cryptoscan.network-evidence/1"
    assert record["decomposition"]["key_exchange"] == "ECDHE"
    assert record["decomposition"]["encryption"] == "AES-256"
    assert record["certificate"]["curve"] == "P-256"
    assert record["target"]["port"] == 443
    assert record["scope_name"] == "payments-prod"


def test_unobserved_endpoint_is_unknown_not_no_crypto():
    finding = {"finding_id": "f-2", "endpoint": "10.20.10.16:443", "status": "PORT_CLOSED", "certificates": []}
    record = build_evidence(finding)
    assert record["evidence_type"] == "UNKNOWN"
    assert record["tls_version"] is None
    assert any("not proof of absence" in line for line in record["limitations"])


def test_mtls_reports_not_required_only_after_a_completed_handshake():
    record = build_evidence(observed_finding())
    # A completed handshake with no client certificate proves mTLS was not
    # *required* on this path; optional client-cert requests stay unobservable.
    assert record["mutual_tls"] == "NOT_REQUIRED"
    assert record["mtls_evidence"] == "HANDSHAKE_WITHOUT_CLIENT_CERT"
    assert any("mTLS was not required" in line for line in record["limitations"])


def test_unobserved_endpoint_never_claims_mtls_absent():
    record = build_evidence({"finding_id": "f-3", "endpoint": "10.20.10.16:443", "status": "TIMEOUT"})
    assert record["mutual_tls"] == "UNKNOWN"
    assert record["mtls_evidence"] == "NOT_PROBED"


def test_record_never_carries_secrets_or_payload():
    record = build_evidence(observed_finding())
    flat = repr(record).lower()
    for forbidden in ("private_key", "password", "authorization:", "payload"):
        assert forbidden not in flat


def test_summary_separates_observed_from_not_observed():
    records = [
        build_evidence(observed_finding()),
        build_evidence({"finding_id": "f-2", "endpoint": "10.20.10.16:443", "status": "TIMEOUT", "certificates": []}),
    ]
    summary = summarize(records)
    assert summary["records"] == 2
    assert summary["observed"] == 1
    assert summary["not_observed"] == 1
    assert summary["tls_versions"] == {"TLSv1.3": 1}
    assert summary["key_exchange"] == {"ECDHE": 1}
    assert "NOT_OBSERVED" in summary["unknown_note"]


def test_evidence_classification_helper():
    assert evidence_type_for({"status": "OK", "crypto": {"cipher_suite": "TLS_AES_128_GCM_SHA256"}}) == "NETWORK_ACTIVE_OBSERVED"
    assert evidence_type_for({"status": "OK", "crypto": {}, "certificates": [{"fingerprint_sha256": "x"}]}) == "CERTIFICATE_OBSERVED"
    assert evidence_type_for({"status": "PORT_CLOSED"}) == "UNKNOWN"
    assert evidence_type_for({}) == "UNKNOWN"


# --------------------------------------------------------------------------- #
# §28 — CBOM projection
# --------------------------------------------------------------------------- #


def test_cbom_projection_keeps_transport_layer_and_context():
    from network_scanner.inventory.network_evidence import to_cbom_assets

    record = build_evidence(observed_finding(), scope_name="payments-prod")
    cbom = to_cbom_assets([record])
    algorithms = cbom["algorithms"]
    assert "AES-256" in algorithms
    assert "ECDHE" in algorithms
    assert "ECDSA" in algorithms
    assert cbom["layer"] == "NETWORK_TRANSPORT"
    asset = next(item for item in cbom["assets"] if item["algorithm"] == "AES-256")
    assert asset["role"] == "tls-bulk-encryption"
    assert asset["layer"] == "NETWORK_TRANSPORT"
    assert asset["context"]["endpoint"] == "10.20.10.15:443"
    assert asset["evidence"]["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert "application" in cbom["boundary"]


def test_cbom_projection_never_invents_assets_for_unobserved_endpoints():
    from network_scanner.inventory.network_evidence import to_cbom_assets

    record = build_evidence({"finding_id": "f-9", "endpoint": "10.20.10.16:443", "status": "TIMEOUT"})
    cbom = to_cbom_assets([record])
    assert cbom["asset_count"] == 0
    assert cbom["not_observed"] == ["10.20.10.16:443"]


# --------------------------------------------------------------------------- #
# §25 — crypto hop path
# --------------------------------------------------------------------------- #


def test_crypto_path_annotates_observed_hop_and_marks_unknown_hop():
    from network_scanner.inventory.network_evidence import build_crypto_path

    record = build_evidence(observed_finding())
    path = build_crypto_path(
        [record],
        [
            {"from": "10.20.10.15:443", "to": "api-gateway", "label": "client → LB"},
            {"from": "api-gateway", "to": "payments-db"},
        ],
    )
    assert path["edge_count"] == 2
    assert path["observed_edges"] == 1
    assert path["unknown_edges"] == 1
    assert path["complete"] is False
    first, second = path["edges"]
    assert first["tls_version"] == "TLSv1.3"
    assert first["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert second["evidence_type"] == "UNKNOWN"
    assert "UNKNOWN, not absent" in second["note"]


def test_crypto_path_reports_complete_only_when_every_hop_is_observed():
    from network_scanner.inventory.network_evidence import build_crypto_path

    record = build_evidence(observed_finding())
    path = build_crypto_path([record], [{"from": "10.20.10.15:443", "to": "internal-lb"}])
    assert path["complete"] is True
    assert path["unknown_edges"] == 0
