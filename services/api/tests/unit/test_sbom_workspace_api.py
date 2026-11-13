"""SBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §1).

Real sqlite + real sessions. The workspace answers what software exists and
how it depends on other software — and the working rules are pinned as
behaviour: an SBOM entry never claims runtime crypto usage, manifest
declarations stay capability, and operation_observed requires a durable
monitor observation. Empty deployments get honest empty states, never
fabricated packages.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.vulnerability import Vulnerability
from db.repositories.crypto_repository import CryptoRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture()
def client(session):
    repo = UserRepository(session)
    repo.create_user("viewer", hash_password("x"), ["viewer"])
    session.commit()
    app = create_app()
    c = TestClient(app)
    token = SessionManager().create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer",
                        datetime.now(timezone.utc) + timedelta(hours=1),
                        ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


def _seed_scan_cascade(session, *, with_runtime_algo=False, tenant_id=None):
    from db.models.scan import Scan

    scan = Scan(target_type="GIT_REPOSITORY", tenant_id=tenant_id,
               target_location="https://example.invalid/payments",
               status="COMPLETED",
               scan_start=datetime.now(timezone.utc),
               scan_end=datetime.now(timezone.utc),
               statistics={"cascade": {
                   "libraries": [
                       {"library": "openssl", "versions": ["3.0.2"], "algorithms": ["AES-256-GCM"],
                        "files_using": 1, "manifests": ["Cargo.lock"]},
                   ],
                   "package_dependencies": [
                       {"name": "cryptography", "ecosystem": "pypi", "version": "42.0.0",
                        "source": "requirements.txt", "direct": True, "crypto_algorithms": ["RSA"]},
                       {"name": "pyca-resources", "ecosystem": "pypi", "version": "1.0.0",
                        "source": "requirements.txt", "direct": False, "parent": "cryptography"},
                   ],
               }})
    session.add(scan)
    session.commit()
    return scan


def test_empty_deployment_reports_honest_empty_state(client):
    for path in ("/overview", "/components", "/dependencies", "/licenses",
                 "/vulnerabilities", "/versions", "/containers", "/binaries",
                 "/evidence", "/history", "/export"):
        r = client.get(f"/api/v1/sbom{path}")
        assert r.status_code == 200, (path, r.text)
    overview = client.get("/api/v1/sbom/overview").json()
    assert overview["component_count"] == 0
    assert overview["state"] in {"NO_SCAN", "NO_CASCADE"}
    components = client.get("/api/v1/sbom/components").json()
    assert components["rows"] == []


def test_inventory_carries_the_spec_columns(client, session):
    _seed_scan_cascade(session)
    body = client.get("/api/v1/sbom/components").json()
    assert body["state"] == "OBSERVED"
    row = next(r for r in body["rows"] if r["name"] == "cryptography")
    for column in ("coordinate", "name", "version", "ecosystem", "application",
                   "source", "license", "vulnerability", "evidence", "last_observed"):
        assert column in row, column
    assert row["ecosystem"] == "pypi"
    assert row["purl"] == "pkg:pypi/cryptography@42.0.0"
    assert row["dependency_type"] == "direct"
    # license is not collected by current scanners — the field is null, never a guess
    assert row["license"] is None


def test_canonical_detail_resolves_stored_package_without_invented_links(client, session):
    _seed_scan_cascade(session)
    rows = client.get("/api/v1/sbom/components").json()["rows"]
    package = next(r for r in rows if r["name"] == "cryptography")
    ref = package["asset_ref"]
    assert ref.startswith("sbom:") and "/" not in ref
    header = client.get(f"/api/v1/asset-detail/{ref}")
    assert header.status_code == 200, header.text
    body = header.json()
    assert body["primary_bom"] == "SBOM"
    assert body["name"] == "cryptography"
    assert next(r for r in body["related"] if r["bom"] == "TechBOM")["state"] == \
        "NOT_ESTABLISHED"
    for tab in ("overview", "components", "cryptography", "hardware",
                "network", "vendors", "dependencies", "evidence", "history"):
        result = client.get(f"/api/v1/asset-detail/{ref}/{tab}")
        assert result.status_code == 200, (tab, result.text)
    assert "per-component evidence ID" in client.get(
        f"/api/v1/asset-detail/{ref}/evidence").json()["note"]
    wrong = ref[:-1] + ("0" if ref[-1] != "0" else "1")
    assert client.get(f"/api/v1/asset-detail/{wrong}").status_code == 404


def test_canonical_package_detail_refuses_foreign_scan(client, session):
    from db.tenancy import tenant_scope

    scan = _seed_scan_cascade(session, tenant_id="bank-a")
    with tenant_scope("bank-a"):
        ref = next(r["asset_ref"] for r in client.get(
            "/api/v1/sbom/components").json()["rows"] if r["name"] == "cryptography")
    assert scan.tenant_id == "bank-a"
    with tenant_scope("bank-b"):
        foreign = client.get(f"/api/v1/asset-detail/{ref}")
    assert foreign.status_code == 404
    with tenant_scope("bank-a"):
        owned = client.get(f"/api/v1/asset-detail/{ref}")
    assert owned.status_code == 200


def test_component_detail_reports_dependencies_and_usage_states(client, session):
    _seed_scan_cascade(session)
    body = client.get("/api/v1/sbom/components/library/openssl").json()
    assert body["component"]["name"] == "openssl"
    usage = {u["algorithm"]: u["usage_state"] for u in body["usage_states"]}
    # seen in code but nothing observed at runtime → configuration, never operation
    assert usage == {"AES-256-GCM": "configuration_observed"}
    body = client.get("/api/v1/sbom/components/pypi/cryptography@42.0.0").json()
    usage = {u["algorithm"]: u["usage_state"] for u in body["usage_states"]}
    assert usage == {"RSA": "capability_detected"}  # manifest declaration only
    assert body["dependencies"]["direct"][0]["target"] == "pypi/pyca-resources@1.0.0"


def test_operation_observed_requires_runtime_monitor_evidence(client, session):
    _seed_scan_cascade(session)
    repo = CryptoRepository(session)
    repo.upsert_state({
        "tenant_id": None,
        "asset_id": "platform:monitor:runtime:algorithm:AES-256-GCM:",
        "cbom_version": 1,
        "algorithms": ["AES-256-GCM"],
        "last_event": "MONITOR_OBSERVED",
    })
    session.commit()
    body = client.get("/api/v1/sbom/components/library/openssl").json()
    usage = {u["algorithm"]: u for u in body["usage_states"]}
    assert usage["AES-256-GCM"]["usage_state"] == "configuration_observed", \
        "an algorithm-only monitor observation is not a component link"

    ref = next(r["asset_ref"] for r in client.get(
        "/api/v1/sbom/components").json()["rows"] if r["name"] == "openssl")
    repo.upsert_state({"tenant_id": None, "asset_id": ref,
                       "cbom_version": 1, "algorithms": ["AES-256-GCM"],
                       "last_event": "MONITOR_OBSERVED"})
    session.commit()
    body = client.get("/api/v1/sbom/components/library/openssl").json()
    usage = {u["algorithm"]: u for u in body["usage_states"]}
    assert usage["AES-256-GCM"]["usage_state"] == "operation_observed"
    assert usage["AES-256-GCM"]["runtime_evidence"] == [ref]
    # the manifest-declared RSA still must NOT inherit runtime proof
    body = client.get("/api/v1/sbom/components/pypi/cryptography@42.0.0").json()
    usage = {u["algorithm"]: u["usage_state"] for u in body["usage_states"]}
    assert usage["RSA"] == "capability_detected"


def test_same_algorithm_in_unrelated_library_is_not_runtime_use(client, session):
    scan = _seed_scan_cascade(session)
    from db.models.crypto_live import CryptoLiveState

    cascade = dict(scan.statistics["cascade"])
    cascade["libraries"] = [*cascade["libraries"], {
        "library": "unrelated", "versions": ["1.0"],
        "algorithms": ["AES-256-GCM"], "files_using": 1,
        "manifests": ["other.lock"]}]
    scan.statistics = {**scan.statistics, "cascade": cascade}
    ref = next(r["asset_ref"] for r in client.get(
        "/api/v1/sbom/components").json()["rows"] if r["name"] == "openssl")
    session.add(CryptoLiveState(
        asset_id=ref, algorithms=["AES-256-GCM"],
        last_event="MONITOR_OBSERVED"))
    session.commit()
    linked = client.get("/api/v1/sbom/components/library/openssl").json()
    unrelated = client.get("/api/v1/sbom/components/library/unrelated").json()
    assert linked["usage_states"][0]["usage_state"] == "operation_observed"
    assert unrelated["usage_states"][0]["usage_state"] == "configuration_observed"
    assert unrelated["usage_states"][0]["runtime_evidence"] == []


def test_vulnerabilities_join_and_unmatched_are_separate(client, session):
    _seed_scan_cascade(session)
    session.add(Vulnerability(cve="CVE-2024-0001", package="cryptography",
                              severity="HIGH", summary="test", scan_id="s1"))
    session.add(Vulnerability(cve="CVE-2024-0002", package="not-in-inventory",
                              severity="LOW", summary="other", scan_id="s1"))
    session.commit()
    body = client.get("/api/v1/sbom/vulnerabilities").json()
    assert [v["cve"] for v in body["matched"]] == ["CVE-2024-0001"]
    assert [v["cve"] for v in body["unmatched"]] == ["CVE-2024-0002"]
    components = client.get("/api/v1/sbom/components").json()
    row = next(r for r in components["rows"] if r["name"] == "cryptography")
    assert row["vulnerability"] == {"count": 1, "max_severity": "HIGH"}


def test_unknown_component_is_404_never_invented(client, session):
    _seed_scan_cascade(session)
    r = client.get("/api/v1/sbom/components/pkg:npm/nope@1.0.0")
    assert r.status_code == 404
