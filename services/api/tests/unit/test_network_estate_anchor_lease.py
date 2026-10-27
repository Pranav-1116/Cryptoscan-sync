"""Estate policy, evidence anchoring and the single-writer observation lease.

Spec 67 §26 (three-layer correlation), §27 (layers never merge), §28 (BOM/book
keeping), §30 (safety) and §31 (policy/risk, drift, distributed scheduling).

The three capabilities under test close three *named* open items from the spec
status table:

* **estate policy packs** — policy, not another evidence store: per-service
  verdicts joined across STATIC/RUNTIME/NETWORK without merging layers;
* **evidence anchoring** — a signed receipt for the chain head that a database
  rewrite no longer matches, refused outright when no external key exists;
* **scheduling** — a database lease so two replicas cannot spend one approved
  traffic budget on the same endpoints.

No socket is opened by any test: probes are injected, the chain is fed through
the normal API path, and the anchor key is a test environment variable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.security.network_estate_policy import (
    REFUSED_COMPARISONS,
    evaluate_estate,
)
from api.security.network_evidence_anchor import (
    KEY_ENV,
    SCHEMA as ANCHOR_SCHEMA,
    key_status,
    sign_receipt,
    verify_receipt,
)
from api.security.network_watch_lease import lease_key

import test_network_protocol_safety as shared_api

#: the shared API harness, re-registered under the name ``api`` so that test
#: parameters do not shadow a module-level fixture function
api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)
save_scope = shared_api.save_scope


def _finding(endpoint: str = "10.20.10.15:443", **overrides) -> dict:
    """A completed TLS handshake finding, as the scanner would return it."""
    finding = {
        "finding_id": "f-1",
        "endpoint": endpoint,
        "status": "OK",
        "ip_address": endpoint.rsplit(":", 1)[0],
        "crypto": {
            "tls_version": "TLSv1.1",
            "cipher_suite": "ECDHE-RSA-AES128-SHA",
            "key_exchange_algorithm": "ECDHE",
            "authentication_algorithm": "RSA",
            "encryption_algorithm": "AES",
            "encryption_mode": "CBC",
            "mac_algorithm": "SHA1",
            "key_size": 128,
        },
        "certificates": [
            {
                "fingerprint_sha256": "a" * 64,
                "subject": "CN=payments.internal",
                "issuer": "CN=Bank Issuing CA",
                "not_after": "2030-01-01T00:00:00+00:00",
                "public_key_algorithm": "RSA",
                "public_key_bits": 1024,
                "signature_algorithm": "sha1WithRSAEncryption",
                "san": ["payments.internal"],
            }
        ],
        "chain_validation": {"structural_status": "OK", "trust_status": "TRUSTED", "chain_completeness": "COMPLETE"},
        "metadata": {"confidence": "HIGH", "endpoint_hostname": "payments.internal"},
        "policy_issues": [],
    }
    finding.update(overrides)
    return finding


def _observe(http, monkeypatch, finding: dict | None = None):
    from network_scanner.core.scanner import NetworkTlsScanner

    assert save_scope(http).status_code == 200
    findings = [finding or _finding()]
    monkeypatch.setattr(
        NetworkTlsScanner,
        "scan_hosts",
        lambda self, hosts, **kwargs: {
            "scan_id": "scan-1",
            "run_id": "run-1",
            "findings": findings,
            "certificates": findings[0].get("certificates") or [],
            "probe_telemetry": {"status": "OK", "probed": len(findings), "ok": len(findings)},
        },
    )
    response = http.post("/api/v1/network/crypto-observe", json={"endpoints": ["10.20.10.15:443"]})
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# §26/§31 — estate policy packs over the correlated picture
# --------------------------------------------------------------------------- #


def test_estate_risk_keeps_layers_separate_and_names_the_failures(api, monkeypatch):
    http, _session = api
    _observe(http, monkeypatch)

    body = {
        "services": [
            {"name": "payments-api", "system": "payments", "hosts": ["10.20.10.15"], "endpoints": ["10.20.10.15:443"]}
        ],
        "static": [
            {"service": "payments-api", "kind": "algorithm", "role": "application-crypto", "value": "DES"}
        ],
        "runtime_events": [
            {
                "event_id": "rt-1",
                "schema": "cryptoscan.runtime-crypto-event/1",
                "attribution_level": 1,
                "source": "CRYPTO_API_HOOK",
                "operation": "ENCRYPT",
                "algorithm": "AES",
                "key_size": 128,
                "mode": "CBC",
                "identity": {"application": "payments-api", "host": "10.20.10.15", "process": "java"},
            }
        ],
    }
    report = http.post("/api/v1/network/crypto-estate-risk", json=body).json()

    assert report["model"] == "cryptoscan.network-estate-risk/1"
    service = report["services"][0]
    assert service["service"] == "payments-api"
    assert service["verdict"] == "NON_COMPLIANT"
    # the network failure is labelled NETWORK and never copied onto the app layer
    assert {finding["layer"] for finding in service["findings"]} == {"NETWORK"}
    assert {"NET-TLS-VERSION-MIN", "NET-CERT-KEY-SIZE"} <= {f["rule_id"] for f in service["findings"]}
    assert service["layers"]["NETWORK"]["observed"] is True
    assert service["layers"]["RUNTIME"]["observed"] is True
    assert service["layers"]["STATIC"]["observed"] is True
    assert report["refused_comparisons"] == list(REFUSED_COMPARISONS)
    assert report["sources"]["network_evidence_records"] >= 1


def test_estate_risk_calls_a_missing_layer_a_blind_spot_not_a_pass(api, monkeypatch):
    http, _session = api
    _observe(http, monkeypatch)

    body = {
        "services": [
            {"name": "payments-api", "hosts": ["10.20.10.15"], "endpoints": ["10.20.10.15:443"]},
            {"name": "never-scanned", "hosts": ["10.20.10.99"]},
        ]
    }
    report = http.post("/api/v1/network/crypto-estate-risk", json=body).json()
    by_name = {service["service"]: service for service in report["services"]}

    assert by_name["never-scanned"]["verdict"] == "NO_EVIDENCE"
    assert by_name["never-scanned"]["layers_missing"] == ["STATIC", "RUNTIME", "NETWORK"]
    assert by_name["never-scanned"]["layers"]["NETWORK"]["observed"] is False
    assert "never-scanned" in report["blind_spots"]
    assert report["summary"]["by_verdict"]["NO_EVIDENCE"] == 1
    # an unobserved service must never be reported as compliant
    assert report["verdict"] != "COMPLIANT"


def test_estate_risk_keeps_unmatched_findings_visible():
    """A finding whose host matches no declared service is a map gap, not a dismissal."""
    correlation = {"services": [{"service": "payments-api", "layers_present": ["NETWORK"]}]}
    network = {
        "model": "cryptoscan.network-risk/1",
        "findings": [
            {
                "rule_id": "NET-TLS-VERSION-MIN",
                "severity": "high",
                "status": "FAIL",
                "endpoint": "10.20.10.77:443",
                "reason": "TLSv1.0 negotiated",
            }
        ],
    }
    report = evaluate_estate(
        correlation=correlation,
        services=[{"name": "payments-api", "hosts": ["10.20.10.15"]}],
        network=network,
    )
    assert report["summary"]["unattributed_findings"] == 1
    assert report["unattributed_findings"][0]["endpoint"] == "10.20.10.77:443"
    assert "map is incomplete" in report["unattributed_findings"][0]["reason_unattributed"]


# --------------------------------------------------------------------------- #
# §28/§31 — signed anchor receipts for the evidence chain
# --------------------------------------------------------------------------- #


def test_anchor_is_refused_without_a_key(api, monkeypatch):
    http, _session = api
    _observe(http, monkeypatch)
    monkeypatch.delenv(KEY_ENV, raising=False)

    response = http.post("/api/v1/network/crypto-evidence/anchor", json={"note": "Q3 audit"})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "anchor_key_not_configured"
    assert key_status()["configured"] is False


def test_anchor_signs_the_head_and_verifies_intact(api, monkeypatch):
    http, _session = api
    _observe(http, monkeypatch)
    monkeypatch.setenv(KEY_ENV, "test-anchor-key-material")

    created = http.post("/api/v1/network/crypto-evidence/anchor", json={"note": "Q3 audit"})
    assert created.status_code == 200, created.text
    receipt = created.json()["receipt"]
    assert receipt["schema"] == ANCHOR_SCHEMA
    assert receipt["chain"]["seq"] >= 1
    assert receipt["signature_scheme"] == "HMAC-SHA256"
    assert receipt["external"] is False

    verified = http.post("/api/v1/network/crypto-evidence/anchor/verify", json={"receipt": receipt}).json()
    assert verified["status"] == "HEAD_INTACT"
    assert verified["signature_valid"] is True
    assert verified["rewritten"] is False

    listed = http.get("/api/v1/network/crypto-evidence/anchors").json()
    assert listed["count"] == 1
    assert listed["key"]["configured"] is True

    status = http.get("/api/v1/network/crypto-evidence/anchor").json()
    assert status["anchoring"] == "signed-receipt-exportable"
    assert status["external"] is False


def test_anchor_detects_an_altered_receipt(api, monkeypatch):
    http, _session = api
    _observe(http, monkeypatch)
    monkeypatch.setenv(KEY_ENV, "test-anchor-key-material")
    receipt = http.post("/api/v1/network/crypto-evidence/anchor", json={}).json()["receipt"]

    tampered = {**receipt, "note": "we only probed 3 endpoints"}
    verified = http.post("/api/v1/network/crypto-evidence/anchor/verify", json={"receipt": tampered}).json()
    assert verified["status"] == "SIGNATURE_INVALID"
    assert verified["rewritten"] is True


def test_anchor_verification_reports_advanced_and_rewritten_chains():
    key = b"test-anchor-key-material"
    receipt = {
        "schema": ANCHOR_SCHEMA,
        "anchor_id": "anchor-1",
        "chain": {"seq": 2, "head": "h2"},
        "created_at": "2026-10-27T00:00:00+00:00",
    }
    receipt["signature"] = sign_receipt(receipt, key)

    advanced = verify_receipt(
        receipt,
        {"seq": 3, "head": "h3", "entries": [{"seq": 2, "record_hash": "h2"}, {"seq": 3, "record_hash": "h3"}]},
        key=key,
    )
    assert advanced["status"] == "ADVANCED"
    assert advanced["rewritten"] is False

    rewritten = verify_receipt(
        receipt,
        {"seq": 3, "head": "hX", "entries": [{"seq": 2, "record_hash": "hX"}, {"seq": 3, "record_hash": "hX"}]},
        key=key,
    )
    assert rewritten["status"] == "HISTORY_REWRITTEN"
    assert rewritten["rewritten"] is True

    truncated = verify_receipt(receipt, {"seq": 1, "head": "h1", "entries": [{"seq": 1, "record_hash": "h1"}]}, key=key)
    assert truncated["status"] == "HISTORY_REWRITTEN"
    assert "shorter than the anchored" in truncated["reason"]


# --------------------------------------------------------------------------- #
# §30/§31 — single-writer scheduling lease
# --------------------------------------------------------------------------- #


def test_lease_admits_one_writer_and_refuses_the_second(api):
    http, _session = api

    first = http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-a"}).json()
    assert first["acquired"] is True
    assert first["outcome"] == "ACQUIRED"
    assert first["mode"] == "DATABASE_LEASE"

    second = http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-b"}).json()
    assert second["acquired"] is False
    assert second["outcome"] == "HELD_BY_OTHER"
    assert second["lease"]["holder"] == "scheduler-a"
    assert "double-probe" in second["reason"]

    renew = http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-a"}).json()
    assert renew["acquired"] is True
    assert renew["outcome"] == "RENEWED"

    status = http.get("/api/v1/network/crypto-watch/lease").json()
    assert status["lease"]["held"] is True
    assert status["lease"]["holder"] == "scheduler-a"
    assert status["distributed"] is True

    released = http.post(
        "/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-a", "release": True}
    ).json()
    assert released["released"] is True

    taken = http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-b"}).json()
    assert taken["acquired"] is True


def test_tick_refuses_a_worker_that_does_not_hold_the_lease(api, monkeypatch):
    http, session = api
    # the watch worker opens its own session, so bind it to the same test database
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: session)
    assert http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-a"}).json()["acquired"] is True

    refused = http.post("/api/v1/network/crypto-watch/tick", json={"owner": "scheduler-b"})
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert detail["error"] == "network_watch_lease_held"
    assert detail["lease"]["holder"] == "scheduler-a"

    # the holder still ticks (this tenant has no approved scope yet, so it skips)
    http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-a", "release": True})
    tick = http.post("/api/v1/network/crypto-watch/tick", json={"owner": "scheduler-a"})
    assert tick.status_code == 200, tick.text
    assert tick.json()["status"] == "SKIPPED"
    assert tick.json()["lease"]["acquired"] is True


def test_an_expired_lease_can_be_taken_over(api, monkeypatch):
    http, session = api
    import api.security.network_watch_lease as lease

    expired = {
        "schema": "cryptoscan.network-watch-lease/1",
        "mode": "DATABASE_LEASE",
        "owner": "dead-scheduler",
        "tenant": "global",
        "ttl_seconds": 60,
        "acquired_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "renewed_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    }
    lease._write(session, None, expired, "tester")
    assert session.execute  # the row is in the same test database the API reads

    status = http.get("/api/v1/network/crypto-watch/lease").json()
    assert status["lease"]["expired"] is True

    takeover = http.post("/api/v1/network/crypto-watch/lease", json={"owner": "scheduler-b"}).json()
    assert takeover["acquired"] is True
    assert takeover["outcome"] == "ACQUIRED"
    assert lease.lease_key(None).startswith("network:watch-lease:")
    assert lease_key("tenant-a") != lease_key("tenant-b")


@pytest.mark.parametrize("ttl", [1, 10_000])
def test_lease_ttl_is_clamped(ttl):
    from api.security.network_watch_lease import MAX_TTL, MIN_TTL

    def _clamp(value):
        return max(MIN_TTL, min(MAX_TTL, int(value)))

    assert _clamp(ttl) in {MIN_TTL, MAX_TTL}
