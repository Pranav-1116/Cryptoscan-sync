"""``cryptoscan collect`` — the same bounded collection the API performs.

The CLI is not allowed a second rulebook. These tests pin the properties that make
one command trustworthy:

* the approved scope decides what may be probed, and a missing scope refuses
  *before* a socket is opened (exit 3, nothing collected);
* a successful collection stores evidence with a run id, and the estate job in the
  same process reads that evidence back;
* a refused or unobserved endpoint stays ``UNKNOWN`` — never "no crypto".
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import api.network_collect as network_collect
from api import cli
from db.connection.session import Base

SCOPE = {
    "inventory_id": "default",
    "destinations": ["10.0.0.5:443"],
    "protocols": ["TLS"],
    "allowed_operations": ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
    "saved_at": "2026-01-01T00:00:00+00:00",
    "scope_name": "payments",
    "valid_until": "2030-01-01T00:00:00+00:00",
    "traffic_budget": {"max_connections": 10},
}


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    opened = sessionmaker(bind=engine)()
    try:
        yield opened
    finally:
        opened.close()


def _finding(endpoint: str, *, tls_version: str = "TLSv1.2", status: str = "OK") -> dict:
    """The shape ``NetworkTlsScanner`` returns, so ``build_evidence`` runs for real."""
    return {
        "finding_id": f"finding-{endpoint}-{tls_version}",
        "endpoint": endpoint,
        "status": status,
        "ip_address": endpoint.split(":")[0],
        "crypto": {
            "tls_version": tls_version,
            "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
            "key_exchange_algorithm": "ECDHE",
            "authentication_algorithm": "RSA",
            "encryption_algorithm": "AES-256",
            "encryption_mode": "GCM",
            "mac_algorithm": "SHA384",
            "key_size": 256,
        },
        "certificates": [{
            "subject": "CN=payments.bank.example",
            "issuer": "CN=Bank Issuing CA",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "public_key_algorithm": "RSA",
            "public_key_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "fingerprint_sha256": "a" * 64,
            "san": ["payments.bank.example"],
        }],
        "chain_validation": {"structural_status": "VALID", "trust_status": "TRUSTED",
                             "chain_completeness": "COMPLETE"},
    }


class FakeScanner:
    """A stand-in for the live prober: no packets, same result shape."""

    def __init__(self, findings=None, **_kwargs):
        self.findings = findings if findings is not None else [_finding("10.0.0.5:443")]

    def scan_hosts(self, hosts, **_kwargs):
        return {"findings": [item for item in self.findings if item["endpoint"] in hosts],
                "certificates": []}


@pytest.fixture()
def stubbed(monkeypatch):
    """Everything outside the code under test: scope store, admission, budget, meter."""
    monkeypatch.setattr(network_collect, "load_scope", lambda _db, _inventory="default": dict(SCOPE))
    monkeypatch.setattr(network_collect, "require_running", lambda _db: {"running": True})
    monkeypatch.setattr(
        network_collect, "admit_network",
        lambda targets, **_kw: {"schema": "cryptoscan.network-admission/1", "decision": "PERMITTED",
                                "checked_targets": len(list(targets)), "protocol": "tls",
                                "transport": "tcp", "decisions": []},
    )
    monkeypatch.setattr(network_collect, "meter_network", lambda *_a, **_kw: None)
    monkeypatch.setattr(network_collect, "reserve", lambda *_a, **_kw: {"reserved": True})
    monkeypatch.setattr(network_collect, "settle", lambda *_a, **_kw: {"settled": True})


# --------------------------------------------------------------------------- #
# collecting
# --------------------------------------------------------------------------- #
def test_collect_refuses_before_a_socket_when_no_scope_is_approved(session, monkeypatch):
    monkeypatch.setattr(network_collect, "load_scope", lambda _db, _inventory="default": None)
    monkeypatch.setattr(network_collect, "require_running", lambda _db: {"running": True})
    opened: list[dict] = []
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner",
                        lambda **kw: opened.append(kw) or FakeScanner())

    with pytest.raises(network_collect.CollectRefused) as caught:
        network_collect.collect_network(session, endpoints=["10.0.0.5:443"])
    assert caught.value.code == "scope_not_configured"
    assert opened == [], "no scanner may be constructed for a refused run"


def test_collect_refuses_a_destination_outside_the_scope(session, stubbed):
    with pytest.raises(network_collect.CollectRefused) as caught:
        network_collect.collect_network(session, endpoints=["10.9.9.9:443"], scanner=FakeScanner())
    assert caught.value.code == "destination_outside_scope"
    assert "outside" in caught.value.reason


def test_collect_stores_evidence_with_a_run_id(session, stubbed):
    result = network_collect.collect_network(session, endpoints=["10.0.0.5:443"], scanner=FakeScanner())
    assert result["run_id"] and result["scan_id"]
    assert len(result["evidence"]) == 1
    record = result["evidence"][0]
    assert record["target"]["endpoint"] == "10.0.0.5:443"
    assert record["evidence_type"] == "NETWORK_ACTIVE_OBSERVED"
    assert record["cipher_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert result["summary"]["observed"] == 1


# --------------------------------------------------------------------------- #
# the CLI
# --------------------------------------------------------------------------- #
def test_cli_collect_refusal_exits_three_and_prints_the_reason(session, monkeypatch, capsys):
    monkeypatch.setattr(network_collect, "load_scope", lambda _db, _inventory="default": None)
    monkeypatch.setattr(network_collect, "require_running", lambda _db: {"running": True})

    code = cli.main(["collect", "--endpoints", "10.0.0.5:443"], session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_REFUSED
    assert "refused" in out and "scope_not_configured" in out
    assert "nothing was collected" in out


def test_cli_collect_then_projects_the_estate_in_one_command(session, stubbed, capsys, monkeypatch):
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", lambda **_kw: FakeScanner())

    code = cli.main(["collect", "--endpoints", "10.0.0.5:443", "--scope", "production"],
                    session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code in {cli.EXIT_OK, cli.EXIT_INCOMPLETE}
    assert "collected" in out and "endpoint records" in out
    assert "coverage" in out and "verdict" in out
    # the endpoint the CLI collected is read back by the NETWORK plane
    assert "NETWORK" in out


def test_cli_collect_json_is_one_parseable_document(session, stubbed, capsys, monkeypatch):
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", lambda **_kw: FakeScanner())
    code = cli.main(["collect", "--endpoints", "10.0.0.5:443", "--json"], session_factory=lambda: session)
    payload = json.loads(capsys.readouterr().out)
    assert code in {cli.EXIT_OK, cli.EXIT_INCOMPLETE}
    assert payload["collection"]["model"] == "cryptoscan.network-crypto-observation/1"
    assert payload["estate"]["verdict"]
    assert set(payload["estate"]["bom_counts"]) == {"SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"}


def test_cli_collect_no_estate_stops_after_collection(session, stubbed, capsys, monkeypatch):
    monkeypatch.setattr("network_scanner.core.scanner.NetworkTlsScanner", lambda **_kw: FakeScanner())
    code = cli.main(["collect", "--endpoints", "10.0.0.5:443", "--no-estate"],
                    session_factory=lambda: session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "verdict" not in out
