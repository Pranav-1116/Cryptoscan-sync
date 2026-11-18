"""Crypto dependency map + system cascade (Twin & dependencies).

Real sqlite + real sessions. Pins the accuracy rules: every edge comes from a
stored record, unowned assets are reported unattributed (never guessed onto a
system), the declared key size decides key-strength policy, cascade
direction follows consumer → provider semantics, and edges that are not
ACTIVE never propagate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from api.crypto_dependency_map import algorithm_identity, build_dependency_map, component_identity, simulate_cascade
from api.main import create_app
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.repositories.user_repository import UserRepository

NOW = datetime.now(timezone.utc)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
    c = TestClient(create_app())
    token = SessionManager().create_session("viewer", roles=["viewer"])
    repo.create_session(token, "viewer", NOW + timedelta(hours=1), ip="127.0.0.1")
    session.commit()
    c.cookies.set("cryptoscan_session", token)
    return c


def _estate(session):
    """mobile → ibank → core → hsm, atm → hsm, plus a retired dwh → core edge."""
    names = {"mobile": "Mobile", "ibank": "Internet Banking", "core": "Core Ledger", "hsm": "Payment HSM",
             "atm": "ATM Switch", "dwh": "Data Warehouse"}
    systems = {k: System(name=v, criticality="CRITICAL" if k in {"core", "hsm"} else "HIGH") for k, v in names.items()}
    session.add_all(systems.values())
    session.flush()

    def dep(a, b, relation="CALLS", **kw):
        session.add(SystemDependency(parent_id=systems[a].id, child_id=systems[b].id, relation=relation,
                                     source="imported", evidence_ref=f"{a} uses {b}", **kw))

    dep("mobile", "ibank")
    dep("ibank", "core")
    dep("core", "hsm", "DEPENDS_ON")
    dep("atm", "hsm", "DEPENDS_ON")
    dep("dwh", "core", "DEPENDS_ON", lifecycle_state="RETIRED")

    def asset(system, algorithm, size, path, line=10, libraries=None):
        row = CryptoAsset(algorithm=algorithm, key_size=size, purpose="SIGNING", file_path=path,
                          line_number=line, confidence="HIGH", libraries=libraries or [])
        session.add(row)
        session.flush()
        if system:
            session.add(SystemAsset(system_id=systems[system].id, asset_id=row.id))
        return row

    asset("ibank", "RSA", 2048, "portal/src/TlsContextFactory.java", 41, [{"name": "BouncyCastle", "version": "1.78"}])
    asset("ibank", "ECDSA", 256, "portal/src/TlsContextFactory.java", 77, [{"name": "BouncyCastle", "version": "1.78"}])
    asset("atm", "RSA", 1024, "atm-switch/src/dukpt/bdk_loader.cpp", 12)
    asset("atm", "3DES", 112, "atm-switch/src/iso8583/field52_pin.cpp", 343)
    asset("core", "RSA", 1024, "tls://10.210.0.7:5432", 0)
    asset(None, "AES", 128, "tls://10.99.0.1:443", 0)  # no owner recorded
    session.add(CryptoAsset(algorithm="MARKER", purpose="seed", file_path="/MARKER", line_number=0, confidence="LOW"))
    session.commit()
    return systems


def test_algorithm_identity_uses_declared_size_and_registry_policy():
    assert algorithm_identity("RSA", 1024)["risk"] == "disallowed"
    assert algorithm_identity("RSA", 2048)["risk"] == "quantum_vulnerable"
    assert algorithm_identity("3DES", 112)["label"] == "3DES-112"
    assert algorithm_identity("3DES", 112)["risk"] == "deprecated"
    assert algorithm_identity("DES", 56)["risk"] == "disallowed"
    assert algorithm_identity("DHE", 1024)["label"] == "DHE-1024"
    assert algorithm_identity("ML-KEM", 768)["risk"] == "quantum_safe"
    assert algorithm_identity("AES-GCM", 256)["risk"] == "acceptable"
    assert algorithm_identity("MARKER", None) is None


def test_component_identity_collapses_endpoint_forms():
    assert component_identity("tls://10.210.0.2:443")["id"] == component_identity("10.210.0.2:443")["id"]
    assert component_identity("tls://10.210.0.2:443")["kind"] == "tls_endpoint"
    assert component_identity("cms/src/hsm/payshield_commands.py")["kind"] == "source"
    assert component_identity("swift-hub/keys/swift.jks")["kind"] == "keystore"
    assert component_identity("portal/config/nginx/ibank.conf")["kind"] == "config"


def test_map_links_algorithms_to_owning_software_only(session):
    systems = _estate(session)
    m = build_dependency_map(session)
    assert m["coverage"]["assets"] == 6  # marker excluded
    assert m["coverage"]["unattributed_assets"] == 1
    algos = {a["label"]: a for a in m["algorithms"]}
    assert set(algos["RSA-1024"]["system_ids"]) == {systems["atm"].id, systems["core"].id}
    assert algos["RSA-2048"]["system_ids"] == [systems["ibank"].id]
    assert algos["AES-128"]["system_ids"] == ["unattributed"]  # shown, never guessed
    # the library edge only names algorithms resolved through it
    lib = m["libraries"][0]
    assert lib["label"] == "BouncyCastle 1.78"
    assert {algos[a]["label"] for a in [x["label"] for x in m["algorithms"]] if algos[a]["id"] in lib["algorithm_ids"]} == {"RSA-2048", "ECDSA-256"}
    uses = [e for e in m["edges"]["uses"] if e["to"] == algos["3DES-112"]["id"]]
    assert uses[0]["locations"][0]["line_number"] == 343
    # system risk is the worst algorithm it touches
    sys_nodes = {s["system_id"]: s for s in m["systems"]}
    assert sys_nodes[systems["atm"].id]["risk"] == "disallowed"
    assert sys_nodes[systems["mobile"].id]["risk"] is None  # no crypto recorded
    # retired edge is shown but does not propagate
    retired = [e for e in m["edges"]["depends_on"] if e["from"] == f"system:{systems['dwh'].id}"]
    assert retired and retired[0]["propagates"] is False


def test_cascade_dependents_follow_consumer_edges_with_witness_paths(session):
    systems = _estate(session)
    m = build_dependency_map(session)
    r = simulate_cascade(m, system_ids=[systems["hsm"].id], direction="dependents", hops=6)
    reached = {row["name"]: row for row in r["impacted"]}
    assert set(reached) == {"Core Ledger", "ATM Switch", "Internet Banking", "Mobile"}
    assert reached["Mobile"]["hops"] == 3
    assert reached["Mobile"]["chain_names"] == ["Mobile", "Internet Banking", "Core Ledger", "Payment HSM"]
    assert [e["relation"] for e in reached["Mobile"]["path_edges"]] == ["DEPENDS_ON", "CALLS", "CALLS"]
    assert "Data Warehouse" not in reached  # retired edge never propagates
    assert r["summary"]["edges_not_propagating"] == 1


def test_cascade_providers_and_hop_limit(session):
    systems = _estate(session)
    m = build_dependency_map(session)
    r = simulate_cascade(m, system_ids=[systems["mobile"].id], direction="providers", hops=2)
    assert [(x["name"], x["hops"]) for x in r["impacted"]] == [("Internet Banking", 1), ("Core Ledger", 2)]


def test_cascade_from_algorithm_seeds_every_user(session):
    systems = _estate(session)
    m = build_dependency_map(session)
    rsa1024 = next(a for a in m["algorithms"] if a["label"] == "RSA-1024")
    r = simulate_cascade(m, algorithm_ids=[rsa1024["id"]], direction="dependents")
    assert {s["name"] for s in r["seeds"]} == {"ATM Switch", "Core Ledger"}
    assert {s["name"] for s in r["impacted"]} == {"Internet Banking", "Mobile"}
    assert r["algorithm_seeds"][0]["locations"] == 2


def test_api_endpoints(client, session):
    systems = _estate(session)
    res = client.get("/api/v1/graph/dependency-map")
    assert res.status_code == 200
    assert res.json()["policy"]["direction"] == "consumer_to_provider"
    res = client.post("/api/v1/graph/dependency-map/cascade",
                      json={"system_ids": [systems["core"].id], "direction": "both", "hops": 4})
    assert res.status_code == 200
    names = {row["name"] for row in res.json()["impacted"]}
    assert {"Payment HSM", "Internet Banking", "Mobile"} <= names
    assert client.post("/api/v1/graph/dependency-map/cascade", json={}).status_code == 400
