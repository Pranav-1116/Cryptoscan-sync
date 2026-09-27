"""GET /api/v1/cbom/nbom — the Network BOM derived from stored network scans.

The point of these tests is that the NBOM is *derived*, not declared. A bank
does not hand this tool a list of its listeners; the network scanner finds
them, and the BOM has to come out of those stored results with no further
input. So these seed real `network_scan_runs` rows and assert the BOM matches.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.network_scan_run import NetworkScanRun

API = "/api/v1/cbom/nbom"
AUTH = {"Authorization": "Bearer test-session-token"}

WEAK_PROBE = {
    "endpoint": "api.bank.ae:443",
    "status": "TLS_OK",
    "tls_version": "TLSv1.0",
    "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "certificates": [{
        "subject": "CN=wildcard.bank.ae", "issuer": "CN=Bank Internal CA",
        "serial_number": "01", "public_key_algorithm": "RSA", "public_key_size": 1024,
    }],
}
STRONG_PROBE = {
    "endpoint": "ib.bank.ae:443",
    "status": "TLS_OK",
    "tls_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "certificates": [{
        "subject": "CN=wildcard.bank.ae", "issuer": "CN=Bank Internal CA",
        "serial_number": "01", "public_key_algorithm": "RSA", "public_key_size": 1024,
    }],
}
UNREACHABLE_PROBE = {"endpoint": "legacy.bank.ae:8443", "status": "TIMEOUT"}


@pytest.fixture()
def ctx(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    with TestClient(app) as c:
        yield c, session
    session.close()
    engine.dispose()


def _seed(session, *probes):
    session.add(NetworkScanRun(target_kind="hosts", verdict="OK",
                               probed=len(probes), ok=len(probes),
                               result={"probes": list(probes)}))
    session.commit()


def test_an_unscanned_estate_renders_zeroes_not_a_fabricated_inventory(ctx):
    client, _ = ctx
    body = client.get(API, headers=AUTH).json()
    assert body["source"] == "empty"
    assert body["summary"]["components"] == 0
    assert body["nbom"]["bomFormat"] == "CycloneDX"


def test_the_bom_is_derived_from_stored_probes(ctx):
    client, session = ctx
    _seed(session, WEAK_PROBE, STRONG_PROBE)

    body = client.get(API, headers=AUTH).json()
    assert body["source"] == "live"
    names = {c["name"] for c in body["nbom"]["components"]}
    assert "api.bank.ae:443" in names and "ib.bank.ae:443" in names
    # One shared certificate across both endpoints, not two.
    assert body["summary"]["by_kind"]["certificate"] == 2   # leaf + its issuer
    assert body["summary"]["by_kind"]["endpoint"] == 2


def test_weak_tls_and_short_keys_are_found_without_being_declared(ctx):
    client, session = ctx
    _seed(session, WEAK_PROBE)

    body = client.get(API, headers=AUTH).json()
    codes = {f["code"] for c in body["nbom"]["components"]
             for f in c["cryptoscan:findings"]}
    assert "nbom.tls_version_disallowed" in codes
    assert "nbom.weak_cipher_suite" in codes
    assert "nbom.rsa_key_too_short" in codes


def test_an_unreachable_endpoint_is_inventoried_but_not_judged(ctx):
    """Absence of evidence is neither a pass nor a failure."""
    client, session = ctx
    _seed(session, UNREACHABLE_PROBE)

    body = client.get(API, headers=AUTH).json()
    legacy = next(c for c in body["nbom"]["components"]
                  if c["name"] == "legacy.bank.ae:8443")
    assert legacy["cryptoscan:findings"] == []
    assert body["summary"]["unobserved"] == 1


def test_a_rescan_supersedes_rather_than_duplicates(ctx):
    """Newest run wins per endpoint."""
    client, session = ctx
    _seed(session, WEAK_PROBE)
    fixed = {**WEAK_PROBE, "tls_version": "TLSv1.3",
             "cipher_suite": "TLS_AES_256_GCM_SHA384"}
    _seed(session, fixed)

    body = client.get(API, headers=AUTH).json()
    endpoints = [c for c in body["nbom"]["components"]
                 if c["name"] == "api.bank.ae:443"]
    assert len(endpoints) == 1
    version = next(p["value"] for p in endpoints[0]["properties"]
                   if p["name"] == "cryptoscan:tls_version")
    assert version == "TLSv1.3", "the newer scan must supersede the older one"


def test_migration_priority_ranks_the_shared_certificate_first(ctx):
    """The cert both endpoints depend on has the widest blast radius."""
    client, session = ctx
    _seed(session, WEAK_PROBE, STRONG_PROBE)

    top = client.get(API, headers=AUTH).json()["summary"]["migration_priority"][0]
    assert top["worst_severity"] == "critical"
    assert top["affected_count"] >= 2
