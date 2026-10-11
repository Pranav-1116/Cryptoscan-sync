"""Per-algorithm business-impact attribution (advanced/56, round 32).

Graph-derived projection: CryptoAsset <- USES <- System -> SUPPORTS ->
BusinessProcess. Sums are over distinct processes per algorithm.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path}/impact.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()

    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, db_url


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed_graph(db_url):
    eng = create_engine(db_url)
    Session = sessionmaker(bind=eng)
    session = Session()
    from db.models.business_process import BusinessProcess
    from db.models.crypto_asset import CryptoAsset
    from db.models.system import System
    from db.models.system_asset import SystemAsset
    from db.models.system_business_process import SystemBusinessProcess

    pay = System(id="sys-pay", name="Payments", environment="PROD")
    chat = System(id="sys-chat", name="Chat", environment="PROD")
    session.add_all([pay, chat])

    p1 = BusinessProcess(id="bp-payments", name="Card payments",
                         revenue_daily=100000.0, customer_count=5000)
    p2 = BusinessProcess(id="bp-support", name="Customer support",
                         revenue_daily=1000.0, customer_count=200)
    session.add_all([p1, p2])

    # two RSA assets on the same system — one algorithm, two dependencies
    session.add_all([
        CryptoAsset(id="asset-rsa-1", algorithm="RSA", file_path="/a.py", line_number=1),
        CryptoAsset(id="asset-rsa-2", algorithm="RSA", file_path="/b.py", line_number=2),
        CryptoAsset(id="asset-des", algorithm="3DES", file_path="/c.py", line_number=3),
        CryptoAsset(id="asset-orphan", algorithm="RC4", file_path="/d.py", line_number=4),
    ])

    # payments uses both RSA assets and 3DES; chat also supports payments
    session.add_all([
        SystemAsset(system_id="sys-pay", asset_id="asset-rsa-1"),
        SystemAsset(system_id="sys-pay", asset_id="asset-rsa-2"),
        SystemAsset(system_id="sys-pay", asset_id="asset-des"),
        SystemBusinessProcess(system_id="sys-pay", process_id="bp-payments"),
        # chat: second system on 3DES? no — chat uses nothing here except the
        # process link below; it proves process-link joins, not algorithm fan-in
        SystemBusinessProcess(system_id="sys-chat", process_id="bp-support"),
    ])
    session.commit()
    session.close()
    eng.dispose()


def test_impact_by_algorithm_sums_distinct_processes(sqlite_app):
    client, db_url = sqlite_app
    _seed_graph(db_url)

    r = client.get("/api/v1/business/impact/by-algorithm")
    assert r.status_code == 401  # anon rejected before login

    _login(client)
    r = client.get("/api/v1/business/impact/by-algorithm")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "business-impact/by-algorithm-v1"
    assert "graph-derived" in body["derivation"]

    impacts = {i["algorithm"]: i for i in body["impacts"]}
    # RSA: two assets, one system, one process — counted once
    rsa = impacts["RSA"]
    assert rsa["asset_count"] == 2 and rsa["system_count"] == 1
    assert rsa["process_count"] == 1
    assert rsa["revenue_daily_total"] == 100000.0
    assert rsa["customer_count_total"] == 5000

    # 3DES: one asset, same system, same process
    des = impacts["3DES"]
    assert des["asset_count"] == 1
    assert des["revenue_daily_total"] == 100000.0

    # RC4 has no system/process link: no attribution row at all (not zero)
    assert "RC4" not in impacts
    assert body["algorithm_count"] == 2


def test_impact_by_algorithm_empty_graph(sqlite_app):
    client, _ = sqlite_app
    _login(client)
    r = client.get("/api/v1/business/impact/by-algorithm")
    assert r.status_code == 200
    assert r.json()["algorithm_count"] == 0 and r.json()["impacts"] == []
