"""Unified BOM query layer (advanced/46, round 37)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings
from cbom.bom_query import query_boms
from cbom.cross_bom import cross_boms, index_bom
from cbom.generator import CbomGenerator
from cbom.nbom import build_nbom
from cbom.technology_bom import materialize_technology_bom
from universal_vendor.hardware.hbom import HbomGenerator
from universal_vendor.hardware.models import HardwareObservation
from vendor_intel.vbom import VbomGenerator


def _boms():
    return {
        "cbom": {"components": [
            {"type": "cryptographic-asset", "name": "RSA 2048", "bom-ref": "c1",
             "cryptoProperties": {"algorithmProperties": {
                 "algorithm": "RSA-2048", "parameterSetIdentifier": "2048"}}},
            {"type": "cryptographic-asset", "name": "AES 256", "bom-ref": "c2",
             "cryptoProperties": {"algorithmProperties": {
                 "algorithm": "AES-256", "parameterSetIdentifier": "256"}}},
            {"type": "application", "name": "Payment API", "bom-ref": "c3"},
        ]},
        "techbom": {"layers": {
            "cbom": {"components": [
                {"type": "crypto", "algorithm": "RSA-2048", "key_size": 1024,
                 "bom-ref": "t1"},
                {"type": "crypto", "algorithm": "SHA-1", "bom-ref": "t2"},
            ]},
            "sbom": {"components": [
                {"type": "application", "name": "payment api", "bom-ref": "t3"},
            ]},
        }},
        "vbom": {"components": [
            {"type": "vendor", "name": "Thales", "bom-ref": "v1",
             "risk_level": "HIGH"},
        ]},
    }


def test_nbom_certificate_and_suite_names_are_not_algorithm_links():
    nbom = build_nbom([{
        "host": "example.test", "port": 443, "tls_version": "TLS 1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificate": {"subject": "AES", "issuer": "Example CA"},
    }])
    indexed = index_bom("nbom", nbom)
    assert not any(row["kind"] == "crypto" for row in indexed)
    assert any(row["identity"] == "endpoint:example.test:443" for row in indexed)
    cbom = CbomGenerator().from_records([{"id": "c1", "algorithm": "AES"}])
    assert cross_boms({"cbom": cbom, "nbom": nbom})["linked_identities"] == 0


def test_techbom_hardware_rows_without_names_remain_indexable():
    techbom = materialize_technology_bom({
        "hardware": [{"id": "h1", "asset_id": "board-001", "model": "X100"}],
    })
    hardware = [row for row in index_bom("techbom", techbom)
                if row["kind"] == "hardware"]
    assert len(hardware) == 1
    assert hardware[0]["ref"] == "hw:board-001"
    assert hardware[0]["identity"] == "hardware:board-001"
    hbom = HbomGenerator()
    hbom.add(HardwareObservation(asset_id="board-001", manufacturer="Acme", model="X100"))
    result = cross_boms({"hbom": hbom.to_cyclonedx(), "techbom": techbom})
    assert result["linked_identities"] == 1
    assert {(m["bom"], m["ref"]) for m in result["links"][0]["present_in"]} == {
        ("hbom", "hw:board-001"), ("techbom", "hw:board-001")}
    assert result["links"][0]["asset_identity_confirmed"] is False


def test_vbom_empty_inventory_service_is_vendor_not_application():
    vbom = VbomGenerator()
    vbom.add_vendor({"id": "v1", "name": "Acme"})
    techbom = materialize_technology_bom({"vendors": [{"name": "Acme"}]})
    result = cross_boms({"vbom": vbom.to_cyclonedx(), "techbom": techbom})
    assert [(link["identity"], link["kind"]) for link in result["links"]] == [
        ("vendor:acme", "vendor")]


def test_generated_aes_variation_is_not_cross_bom_disagreement():
    # Both generators consume inventory-shaped records; bom-refs are distinct.
    # AES is an algorithm association, not proof of the same key or device.
    cbom = CbomGenerator().from_records([
        {"id": "c128", "algorithm": "AES", "key_size": 128},
        {"id": "c256", "algorithm": "AES", "key_size": 256},
    ])
    techbom = materialize_technology_bom({
        "crypto": [{"id": "t256", "algorithm": "AES", "key_size": 256}],
    })
    boms = {"cbom": cbom, "techbom": techbom}
    result = cross_boms(boms)
    link = result["links"][0]
    assert link["identity"] == "crypto:AES"
    assert link["relationship"] == "algorithm_association"
    assert link["asset_identity_confirmed"] is False
    assert {(m["bom"], m["ref"]) for m in link["present_in"]} == {
        ("cbom", "c128"), ("cbom", "c256"), ("techbom", "crypto:t256:")}
    assert result["conflicts"] == []
    assert result["conflict_count"] == 0
    assert result["variations"] == [{
        "identity": "crypto:AES", "field": "key size", "bom": "cbom",
        "values": [
            {"bom": "cbom", "ref": "c128", "value": "128"},
            {"bom": "cbom", "ref": "c256", "value": "256"},
        ],
    }]

    dossier = query_boms(boms, identity="crypto:AES")["matches"][0]
    assert dossier["relationship"] == "algorithm_association"
    assert dossier["asset_identity_confirmed"] is False
    assert dossier["conflicts"] == []
    assert dossier["variations"] == result["variations"]
    assert query_boms(boms, conflicts_only=True)["matches"] == []


def test_unambiguous_cross_bom_disagreement_keeps_each_ref():
    cbom = CbomGenerator().from_records([
        {"id": "c1", "algorithm": "AES", "key_size": 128},
        {"id": "c2", "algorithm": "AES", "key_size": 128},
    ])
    techbom = materialize_technology_bom({
        "crypto": [{"id": "t256", "algorithm": "AES", "key_size": 256}],
    })
    boms = {"cbom": cbom, "techbom": techbom}
    assert cross_boms(boms)["variations"] == []
    conflicts = cross_boms(boms)["conflicts"]
    assert conflicts == [{
        "identity": "crypto:AES", "field": "key size",
        "values": [
            {"bom": "cbom", "ref": "c1", "value": "128"},
            {"bom": "cbom", "ref": "c2", "value": "128"},
            {"bom": "techbom", "ref": "crypto:t256:", "value": "256"},
        ],
    }]
    assert query_boms(boms, conflicts_only=True)["matches"][0]["conflicts"] == [
        {k: v for k, v in conflicts[0].items() if k != "identity"}
    ]


def test_single_bom_variation_is_visible_without_a_link_or_conflict():
    cbom = CbomGenerator().from_records([
        {"id": "c128", "algorithm": "AES", "key_size": 128},
        {"id": "c256", "algorithm": "AES", "key_size": 256},
    ])
    result = query_boms({"cbom": cbom})
    assert result["matches"][0]["linked"] is False
    assert result["matches"][0]["conflicts"] == []
    assert result["matches"][0]["variations"][0]["field"] == "key size"


def test_query_by_identity_returns_the_full_dossier():
    result = query_boms(_boms(), identity="crypto:RSA-2048")
    assert result["identities_matching"] == 1
    match = result["matches"][0]
    assert match["linked"] is True
    assert match["bom_count"] == 2
    refs = {entry["bom"]: entry["ref"] for entry in match["present_in"]}
    assert refs == {"cbom": "c1", "techbom": "t1"}
    # the disagreement is right there with the values that produced it
    conflict = match["conflicts"][0]
    assert conflict["field"] == "key size"
    values = {v["bom"]: v["value"] for v in conflict["values"]}
    assert values == {"cbom": "2048", "techbom": "1024"}


def test_kind_and_algorithm_filters():
    crypto = query_boms(_boms(), kind="crypto")
    assert {m["identity"] for m in crypto["matches"]} == {
        "crypto:RSA-2048", "crypto:AES-256", "crypto:SHA-1"}
    aes = query_boms(_boms(), algorithm="aes 256")  # survives spacing
    assert [m["identity"] for m in aes["matches"]] == ["crypto:AES-256"]
    vendors = query_boms(_boms(), kind="vendor")
    assert [m["label"] for m in vendors["matches"]] == ["Thales"]


def test_linked_unlinked_and_coverage_gaps():
    result = query_boms(_boms(), unlinked_only=True)
    identities = {m["identity"] for m in result["matches"]}
    # AES-256, SHA-1 (crypto in one BOM each) and Thales (vendor only)
    assert identities == {"crypto:AES-256", "crypto:SHA-1", "vendor:thales"}
    linked = query_boms(_boms(), linked_only=True)
    assert {m["identity"] for m in linked["matches"]} == {
        "crypto:RSA-2048", "application:payment api"}


def test_bom_filter_and_unknown_bom_error():
    result = query_boms(_boms(), bom="vbom")
    assert {m["identity"] for m in result["matches"]} == {"vendor:thales"}
    result = query_boms(_boms(), bom="nbom")
    assert result["matches"] == []
    assert "unknown BOM" in result["error"]


def test_conflicts_only():
    result = query_boms(_boms(), conflicts_only=True)
    assert result["conflict_count"] >= 1
    assert all(m["conflicts"] for m in result["matches"])
    assert [m["identity"] for m in result["matches"]] == ["crypto:RSA-2048"]


def test_empty_inputs_answer_cleanly():
    result = query_boms({})
    assert result["identities_total"] == 0
    assert result["matches"] == []
    result = query_boms({"cbom": {}})
    assert result["identities_matching"] == 0


def test_query_echoes_its_own_parameters():
    result = query_boms(_boms(), kind="crypto", linked_only=True)
    assert result["query"] == {
        "identity": None, "kind": "crypto", "bom": None, "algorithm": None,
        "linked_only": True, "unlinked_only": False, "conflicts_only": False,
    }


# ── API end to end ───────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/bomq.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/bomq.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_query_endpoint_over_live_inventory(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add(CryptoAsset(algorithm="RSA-2048", key_size=2048,
                            purpose="ENCRYPTION", file_path="a.py",
                            line_number=1, confidence="HIGH"))
    session.commit()
    session.close()
    eng.dispose()

    r = client.get("/api/v1/cbom/query")
    assert r.status_code == 401

    admin = _login(client)
    r = client.get("/api/v1/cbom/query", headers=admin,
                   params={"identity": "crypto:RSA-2048"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "cross-bom/query-v1"
    assert body["identities_matching"] == 1
    assert body["matches"][0]["bom_count"] == 2
    assert body["live"] is True

    # filters work end to end too
    r = client.get("/api/v1/cbom/query", headers=admin,
                   params={"kind": "crypto", "unlinked_only": "true"})
    assert r.status_code == 200
    assert r.json()["identities_matching"] == 0  # RSA is associated across BOMs


def test_live_endpoints_distinguish_inventory_variation(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add_all([
        CryptoAsset(algorithm="AES", key_size=128, file_path="a.py", line_number=1),
        CryptoAsset(algorithm="AES", key_size=256, file_path="b.py", line_number=2),
    ])
    session.commit()
    session.close()
    eng.dispose()

    admin = _login(client)
    links = client.get("/api/v1/cbom/cross-links", headers=admin)
    assert links.status_code == 200, links.text
    assert links.json()["conflict_count"] == 0
    assert links.json()["variation_count"] == 2  # CBOM and TechBOM each saw both assets
    assert links.json()["links"][0]["relationship"] == "algorithm_association"

    query = client.get("/api/v1/cbom/query", headers=admin,
                       params={"identity": "crypto:AES"})
    assert query.status_code == 200, query.text
    dossier = query.json()["matches"][0]
    assert dossier["conflicts"] == []
    assert {row["value"] for variation in dossier["variations"]
            for row in variation["values"]} == {"128", "256"}
    assert {variation["bom"] for variation in dossier["variations"]} == {"cbom", "techbom"}


# ── Estate-wide summary (the CBOM page's headline cards) ─────────────


def test_summary_counts_every_identity_not_the_filtered_result():
    """A filtered table must not relabel a subset total as the estate total."""
    result = query_boms(_boms(), identity="crypto:RSA-2048")
    assert result["identities_matching"] == 1
    summary = result["summary"]
    # five canonical identities exist: AES-256, RSA-2048, SHA-1, payment api, Thales
    assert summary["identities"] == 5
    assert result["identities_total"] == summary["identities"]
    assert summary["linked"] == 2          # RSA-2048, payment api
    assert summary["single_source"] == 3   # AES-256, SHA-1, Thales
    assert summary["linked"] + summary["single_source"] == summary["identities"]
    assert summary["asset_identity_confirmed"] is False
    assert "estate-wide" in summary["scope"]


def test_summary_kind_and_bom_participation_are_ranked_and_complete():
    summary = query_boms(_boms())["summary"]
    kinds = {row["kind"]: row["identities"] for row in summary["by_kind"]}
    assert kinds == {"crypto": 3, "application": 1, "vendor": 1}
    counts = [row["identities"] for row in summary["by_kind"]]
    assert counts == sorted(counts, reverse=True)  # largest first, deterministic
    # an identity is counted once per BOM that actually observed it
    participation = {row["bom"]: row["identities"] for row in summary["by_bom"]}
    assert participation == {"cbom": 3, "techbom": 3, "vbom": 1}


def test_summary_conflicts_match_the_unfiltered_conflict_count():
    unfiltered = query_boms(_boms())
    filtered = query_boms(_boms(), unlinked_only=True)
    assert unfiltered["summary"]["conflict_count"] == unfiltered["conflict_count"]
    assert filtered["summary"]["conflict_count"] == unfiltered["conflict_count"]
    assert filtered["conflict_count"] == 0  # the filtered rows hold none
    assert (filtered["summary"]["variation_count"]
            == unfiltered["variation_count"] == unfiltered["summary"]["variation_count"])


def test_empty_estate_summary_is_zero_not_missing():
    summary = query_boms({})["summary"]
    assert summary["identities"] == 0
    assert summary["linked"] == 0
    assert summary["single_source"] == 0
    assert summary["conflict_count"] == 0
    assert summary["by_kind"] == []
    assert summary["by_bom"] == []


def test_query_endpoint_returns_the_estate_summary(sqlite_app):
    client, db_url = sqlite_app
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.crypto_asset import CryptoAsset

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    session.add_all([
        CryptoAsset(algorithm="RSA-2048", key_size=2048, purpose="ENCRYPTION",
                    file_path="a.py", line_number=1, confidence="HIGH"),
        CryptoAsset(algorithm="AES-256", key_size=256, purpose="ENCRYPTION",
                    file_path="b.py", line_number=2, confidence="HIGH"),
    ])
    session.commit()
    session.close()
    eng.dispose()

    admin = _login(client)
    body = client.get("/api/v1/cbom/query", headers=admin,
                      params={"algorithm": "rsa"}).json()
    summary = body["summary"]
    assert summary["identities"] >= 1
    assert any(row["bom"] == "techbom" for row in summary["by_bom"])
    # the filter narrowed the rows but not the estate arithmetic
    assert summary["identities"] >= body["identities_matching"]
