"""TechBOM workspace API (docs/boms/01_PRODUCT_SPEC.md §6 + §9).

Real sqlite + real sessions. The workspace answers which technologies the
estate runs and how the six BOMs relate — and the working rules are pinned
as behaviour: a relationship exists only where stored evidence establishes
it (system_assets, SystemVendor, SystemDependency); reconciliation connects
records only when the evidence establishes the relationship and never
assumes the application performs an operation a component is capable of;
evidence states (Measured / Imported / Inferred / Unknown / Contradicted)
and freshness are never collapsed. Empty estates get honest empty states.
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
from db.models.crypto_asset import CryptoAsset
from db.models.hardware_live import HardwareAsset
from db.models.network_scan_run import NetworkScanRun
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.models.vendor import SystemVendor, Vendor
from db.models.vendor_profile import VendorProfileRevision
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


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
    repo.create_session(token, "viewer", NOW + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


def _seed_estate(session) -> None:
    """A tiny estate exercising every verified link and every evidence state."""
    pay = System(id="sys-pay", name="payments", owner="payments-team",
                 environment="Production", criticality="HIGH")
    lone = System(id="sys-lone", name="lone-app", owner="x",
                  environment="UAT", criticality="LOW")
    session.add_all([pay, lone])

    linked_crypto = CryptoAsset(id="cr-linked", algorithm="AES", key_size=256,
                                file_path="/opt/pay/libcrypto.so", line_number=10,
                                confidence="HIGH", occurrence_count=1)
    orphan_crypto = CryptoAsset(id="cr-orphan", algorithm="RSA", key_size=2048,
                                file_path="/tmp/orphan.o", line_number=1,
                                confidence="LOW", occurrence_count=1)
    session.add_all([linked_crypto, orphan_crypto])
    session.add(SystemAsset(system_id="sys-pay", asset_id="cr-linked"))

    hsm = HardwareAsset(asset_id="hsm-1", manufacturer="Thales", model="payHSM",
                        device_type="hsm", last_verified=NOW - timedelta(days=10),
                        evidence_history=[{"state": "MEASURED"}])
    session.add(hsm)

    session.add(Vendor(id="ven-thales", name="Thales", criticality="HIGH",
                       vendor_type="hardware", data_classifications=[]))
    session.add(SystemVendor(system_id="sys-pay", vendor_id="ven-thales"))
    session.add(VendorProfileRevision(vendor_id="ven-thales", revision=1,
                                      schema_version=1, status="DRAFT",
                                      profile_json={}, completeness_json={},
                                      content_sha256="a" * 64, captured_at=NOW - timedelta(days=5)))
    session.add(SystemDependency(parent_id="sys-pay", child_id="sys-lone"))

    session.add(NetworkScanRun(
        target_kind="hosts", verdict="TLS_OK", probed=1, ok=1,
        result={"probes": [{"endpoint": "payments-1:443", "status": "TLS_OK",
                            "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
                            "alpn": "h2"}]},
    ))
    session.commit()


SPEC_COLUMNS = ["asset_ref", "name", "category", "vendor", "product_version",
                "environment", "related", "dependencies", "evidence", "last_observed"]


def test_empty_estate_is_honest_not_zeroed_nonsense(client):
    r = client.get("/api/v1/techbom/workspace/inventory")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["rows"] == []
    assert "stored record" in body["note"] or "verified links" in body["note"]

    r = client.get("/api/v1/techbom/workspace/overview")
    assert r.status_code == 200
    assert r.json()["total_assets"] == 0


def test_inventory_columns_and_related_boms_stay_apart(client, session):
    _seed_estate(session)
    r = client.get("/api/v1/techbom/workspace/inventory")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 5
    for col in SPEC_COLUMNS:
        assert col in body["rows"][0], col

    by_ref = {row["asset_ref"]: row for row in body["rows"]}

    # A system with a stored crypto link and a stored vendor link: those BOMs
    # are LINKED — and nothing else becomes linked without evidence.
    pay = by_ref["app:sys-pay"]
    assert pay["related"]["SBOM"] == "PRIMARY_RECORD"
    assert pay["related"]["CBOM"] == "LINKED"
    assert pay["related"]["VBOM"] == "LINKED"
    assert pay["related"]["HBOM"] == "NOT_ESTABLISHED"
    assert pay["related"]["NBOM"] == "NOT_ESTABLISHED"
    assert pay["dependencies"] >= 3  # crypto link + vendor link + system dependency

    # Hardware is its own primary record and is NOT linked to the SBOM: no
    # stored hardware-system mapping exists, and none is invented.
    hsm = by_ref["hw:hsm-1"]
    assert hsm["related"]["HBOM"] == "PRIMARY_RECORD"
    assert hsm["related"]["SBOM"] == "NOT_ESTABLISHED"
    assert hsm["evidence"]["state"] == "MEASURED"  # agent-verified

    # An observed network endpoint is measured; an unobserved one is unknown —
    # a port scan alone proves nothing.
    ep = by_ref["net:payments-1:443"]
    assert ep["related"]["NBOM"] == "PRIMARY_RECORD"
    assert ep["evidence"]["state"] == "MEASURED"

    # An orphan crypto asset is inferred (discovered by analysis), never
    # measured and never "used by the app".
    orphan = by_ref["crypto:cr-orphan"]
    assert orphan["evidence"]["state"] == "INFERRED"
    assert orphan["related"]["SBOM"] == "NOT_ESTABLISHED"

    # The vendor is imported (profile supplied), the unlinked app is unknown.
    assert by_ref["vendor:ven-thales"]["evidence"]["state"] == "IMPORTED"
    assert by_ref["app:sys-lone"]["evidence"]["state"] == "UNKNOWN"


def test_reconciliation_screens_and_the_evidence_rule(client, session):
    _seed_estate(session)
    r = client.get("/api/v1/techbom/workspace/reconciliation")
    assert r.status_code == 200
    body = r.json()
    names = [s["screen"] for s in body["screens"]]
    assert names == [
        "duplicate_asset_detection", "unmatched_sbom_components",
        "cbom_assets_without_owner", "hbom_devices_without_mapping",
        "nbom_endpoints_without_owner", "vbom_products_without_relationship",
        "conflicting_versions", "missing_evidence", "stale_records",
        "relationship_validation",
    ]
    by_name = {s["screen"]: s for s in body["screens"]}
    # the orphan crypto asset has no mapped owner
    assert by_name["cbom_assets_without_owner"]["count"] >= 1
    # the HSM has no approved system mapping — honestly counted, never invented
    assert by_name["hbom_devices_without_mapping"]["count"] >= 1
    # the linked vendor is NOT in the unlinked list
    assert by_name["vbom_products_without_relationship"]["count"] == 0
    # validated relationships are exactly the stored links
    assert by_name["relationship_validation"]["count"] == 2  # system_assets + SystemVendor
    # the rule itself: capability is never an operation claim
    assert "never taken as proof" in body["rule"]


def test_asset_detail_cross_bom_states_and_404(client, session):
    _seed_estate(session)
    r = client.get("/api/v1/techbom/workspace/inventory/app:sys-pay")
    assert r.status_code == 200
    body = r.json()
    states = {rel["bom"]: rel["state"] for rel in body["related"]}
    assert states["SBOM"] == "PRIMARY_RECORD"
    assert states["CBOM"] == "LINKED"
    assert states["HBOM"] == "NOT_ESTABLISHED"
    for rel in body["related"]:
        assert rel["basis"]  # every state carries its basis
    assert any(d["type"] == "system_asset" for d in body["dependencies"])
    assert any(d["type"] == "system_vendor" for d in body["dependencies"])

    r = client.get("/api/v1/techbom/workspace/inventory/app:nope")
    assert r.status_code == 404
