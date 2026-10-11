"""Code-level fact graph slice (advanced/48 P1#11 + 58, round 34).

``file DEFINES fact OBSERVED_BY evidence`` — live projection, CALLS
honestly absent.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from api.facts.projection import code_graph_facts, project_facts


def _row(algorithm, path, line=1, purpose="ENCRYPTION", key_size=None,
         scanner="ast-scanner"):
    return {
        "id": f"ev-{algorithm}-{path}-{line}-{scanner}".replace("/", "_"),
        "algorithm": algorithm, "purpose": purpose, "file_path": path,
        "line_number": line, "key_size": key_size, "mode": None,
        "confidence": "HIGH", "is_hardcoded_key": False,
        "finding_data": {"scanner_id": scanner},
        "created_at": datetime(2026, 10, 1, tzinfo=timezone.utc),
    }


def test_code_graph_edges_and_nodes():
    rows = [
        _row("RSA-2048", "src/pay/Keys.java", line=11, key_size=2048),
        _row("RSA-2048", "src/pay/Keys.java", line=44, key_size=2048,
             scanner="regex-scanner"),  # same fact, second observation
        _row("AES-128", "src/old/Legacy.java", line=7, key_size=128,
             purpose="ENCRYPTION"),
        _row("SHA-1", "src/old/Legacy.java", line=30, purpose="HASHING"),
    ]
    facts = project_facts(rows)
    graph = code_graph_facts(facts)

    assert graph["model"] == "code-fact-graph/read-projection-v1"
    assert graph["file_count"] == 2
    assert graph["fact_count" if "fact_count" in graph else "node_count"] >= 3

    node_ids = {n["id"] for n in graph["nodes"]}
    assert "file:src/pay/Keys.java" in node_ids
    assert "file:src/old/Legacy.java" in node_ids
    assert any(n["id"].startswith("fact:RSA-2048:") for n in graph["nodes"])

    relations = {e["relation"] for e in graph["edges"]}
    assert relations == {"DEFINES", "OBSERVED_BY"}
    # one fact per file-algorithm identity: Keys.java defines one fact
    defines_keys = [e for e in graph["edges"]
                    if e["relation"] == "DEFINES"
                    and e["from"] == "file:src/pay/Keys.java"]
    assert len(defines_keys) == 1
    # the fact cites BOTH evidence rows (lines 11 + 44)
    fact_id = defines_keys[0]["to"]
    observed = [e for e in graph["edges"]
                if e["relation"] == "OBSERVED_BY" and e["from"] == fact_id]
    assert len(observed) == 2
    # Legacy.java defines two facts (two algorithms)
    defines_legacy = [e for e in graph["edges"]
                      if e["relation"] == "DEFINES"
                      and e["from"] == "file:src/old/Legacy.java"]
    assert len(defines_legacy) == 2

    # CALLS is honestly absent, stated as absent
    assert "CALLS" not in relations
    assert "call-graph parsing" in graph["open_relations"]["CALLS"]


def test_code_graph_empty():
    graph = code_graph_facts([])
    assert graph["file_count"] == 0 and graph["nodes"] == []
    assert graph["edges"] == []


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/codegraph.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/codegraph.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed(db_url):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.evidence_record import EvidenceRecord

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    for index, (algo, path, line, purpose) in enumerate([
        ("RSA-2048", "src/pay/Keys.java", 11, "ENCRYPTION"),
        ("RSA-2048", "src/pay/Keys.java", 44, "ENCRYPTION"),
        ("SHA-1", "src/hash/Digest.java", 3, "HASHING"),
    ]):
        session.add(EvidenceRecord(
            scan_id="scan-cg", content_hash=f"{index}" * 64,
            chain_hash=f"{index}" + "0" * 63, chain_position=index,
            algorithm=algo, purpose=purpose, key_size=None,
            file_path=path, line_number=line,
            finding_data={"scanner_id": "ast-scanner"}, confidence="HIGH",
            compliance_status="FAIL",
        ))
    session.commit()
    session.close()
    eng.dispose()


def test_code_graph_api(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)

    r = client.get("/api/v1/facts/code-graph")
    assert r.status_code == 401  # anon first

    admin = _login(client)
    r = client.get("/api/v1/facts/code-graph", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "code-fact-graph/read-projection-v1"
    assert body["file_count"] == 2 and body["fact_count"] == 2
    assert {e["relation"] for e in body["edges"]} == {"DEFINES", "OBSERVED_BY"}
    assert body["evidence_rows_read"] == 3

    # file_prefix filter narrows the graph
    r = client.get("/api/v1/facts/code-graph",
                   params={"file_prefix": "src/pay"}, headers=admin)
    body = r.json()
    assert body["file_count"] == 1 and body["fact_count"] == 1
    assert all(n["id"] == "file:src/pay/Keys.java"
               for n in body["nodes"] if n["type"] == "file")

    # algorithm filter narrows the graph too
    r = client.get("/api/v1/facts/code-graph",
                   params={"algorithm": "SHA-1"}, headers=admin)
    body = r.json()
    assert body["fact_count"] == 1
    assert body["file_count"] == 1
