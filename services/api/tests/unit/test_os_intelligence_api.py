"""OS & Kernel Intelligence API — acceptance tests.

The request payload is a REAL collection: the collector runs against
the recorded local-host corpus (fixtures of the actual Linux
configuration) and the API records and serves it end to end
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §10/§12).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base, configure_session

_SERVICES = Path(__file__).resolve().parents[3]
_FIXTURE = (_SERVICES / "os_intelligence" / "tests" / "fixtures" /
            "host-linux-sample.txt").read_text()
_EMPTY_ROOT = _SERVICES / "os_intelligence" / "tests" / "fixtures" / \
    "empty-root"


def _section(name: str) -> str:
    return _FIXTURE.split(f"--- {name}")[1].split("\n---")[0].strip("\n")


@pytest.fixture()
def app_db():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session
    application.dependency_overrides.clear()


def _real_inventory(tmp_path: Path) -> dict:
    """Run the collector against the recorded local-host corpus."""
    import sys
    sys.path.insert(0, str(_SERVICES / "os_intelligence"))
    from os_intelligence.collector import collect_linux

    root = tmp_path / "root"
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "proc/version").write_text(
        "Linux version 6.1.158+ (user@host) (gcc 12) #1 SMP "
        "PREEMPT_DYNAMIC Mon May 11 18:48:24 UTC 2026\n")
    (root / "etc/os-release").write_text(_section("os-release"))
    (root / "proc/cmdline").write_text(_section("cmdline"))
    (root / "proc/sys/kernel/tainted").write_text(_section("tainted"))
    (root / "proc/crypto").write_text(_section("proc-crypto"))
    (root / "proc/modules").write_text(_section("proc-modules"))
    (root / "proc/config.gz-or-boot-config").write_text(
        _section("config-crypto"))
    # deliberately leave proc/lsblk-f unwritten: one source must be
    # genuinely unavailable so the round trip proves honest degradation
    return collect_linux("host-under-test",
                         source_root=str(root),
                         collect_hardware_trust=False).as_dict()


async def _post_collection(client, inventory, asset_id="host-under-test"):
    return await client.post(
        "/api/v1/os-intelligence/collections",
        json={"tenant_id": "t1", "asset_id": asset_id,
              "inventory": inventory})


class TestCollectionLifecycle:

    @pytest.mark.asyncio
    async def test_real_collection_round_trip(self, app_db, tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(client, inventory)
            assert resp.status_code == 201, resp.text
            body = resp.json()
            assert body["outcome"] == "recorded"
            assert "never confirmed" in body["note"]

            listed = await client.get("/api/v1/os-intelligence/assets",
                                      params={"tenant_id": "t1"})
            assert listed.status_code == 200
            assets = listed.json()["assets"]
            assert len(assets) == 1
            asset = assets[0]
            assert asset["kernel_release"] == "6.1.158+"
            assert asset["os_id"] == "debian"
            assert asset["environment_development_only"] is True
            assert "enterprise qualification" in asset["qualification_note"]

    @pytest.mark.asyncio
    async def test_capabilities_carry_the_decisive_field(self, app_db,
                                                         tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            resp = await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/"
                "crypto-capabilities",
                params={"tenant_id": "t1"})
            assert resp.status_code == 200
            data = resp.json()
            assert "not proof of runtime use" in data["note"]
            caps = data["capabilities"]
            assert caps, "the recorded host has registered implementations"
            for cap in caps:
                assert cap["runtime_usage_confirmed"] is False, \
                    "a registered implementation is never usage (§2.2)"
            # one algorithm, several implementations — kept distinct
            sha384 = [c for c in caps if c["algorithm"] == "sha384"]
            assert len(sha384) >= 2
            assert len({c["driver"] for c in sha384}) >= 2
            # unknown key sizes are never guessed
            shash = [c for c in caps if c["type"] == "shash"]
            assert any(c["key_size_range"] is None for c in shash)

    @pytest.mark.asyncio
    async def test_coverage_never_zero_never_clean(self, app_db, tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            resp = await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/coverage",
                params={"tenant_id": "t1"})
            assert resp.status_code == 200
            cov = resp.json()
            # the storage source was deliberately not written: the
            # unavailable read must be recorded with its reason
            assert cov["sources_unavailable"], \
                "unavailable sources are recorded, never dropped"
            assert any("storage" in e["source"]
                       for e in cov["sources_unavailable"])
            assert "storage" not in cov["sources_collected"]
            for entry in cov["sources_unavailable"]:
                assert entry["reason"], "reason present, never bare zero"
            assert "never treated as" in (cov["note"] or "").lower()
            assert cov["source_digests"], \
                "collected sources carry evidence digests"

    @pytest.mark.asyncio
    async def test_inventory_views_present(self, app_db, tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            base = "/api/v1/os-intelligence/assets/host-under-test/"
            mods = (await client.get(base + "modules",
                                     params={"tenant_id": "t1"})).json()
            assert "may be built into the kernel" in mods["note"]
            flags = (await client.get(base + "config-flags",
                                      params={"tenant_id": "t1"})).json()
            assert "never reported as" in flags["note"]
            storage = (await client.get(base + "storage",
                                        params={"tenant_id": "t1"})).json()
            assert "no recovery keys" in storage["note"]
            trust = (await client.get(base + "hardware-trust",
                                      params={"tenant_id": "t1"})).json()
            assert "never a trust verdict" in trust["note"]

    @pytest.mark.asyncio
    async def test_missing_asset_never_clean(self, app_db):
        app, _db = app_db
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/os-intelligence/assets/no-such-host",
                params={"tenant_id": "t1"})
            assert resp.status_code == 404
            assert "never a clean asset" in resp.text

    @pytest.mark.asyncio
    async def test_package_without_coverage_rejected(self, app_db):
        app, _db = app_db
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(
                client, {"identity": {"kernel_release": "6.1.0"}})
            assert resp.status_code == 422
            assert "never recorded as valid" in resp.text

    @pytest.mark.asyncio
    async def test_package_without_identity_rejected(self, app_db):
        app, _db = app_db
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(client, {"coverage": {}})
            assert resp.status_code == 422
            assert "validated, never assumed" in resp.text


class TestLiveHost:

    @pytest.mark.asyncio
    async def test_live_collection_accepted(self, app_db):
        """§15 step 7: the actual local Linux configuration, collected
        live, is accepted and served back without fabrication."""
        import sys
        sys.path.insert(0, str(_SERVICES / "os_intelligence"))
        from os_intelligence.collector import collect_linux

        if not Path("/proc/crypto").exists():
            pytest.skip("live host exposes no /proc/crypto")
        inventory = collect_linux("live-host").as_dict()
        app, _db = app_db
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(client, inventory,
                                         asset_id="live-host")
            assert resp.status_code == 201, resp.text
            caps = (await client.get(
                "/api/v1/os-intelligence/assets/live-host/"
                "crypto-capabilities",
                params={"tenant_id": "t1"})).json()["capabilities"]
            assert caps
            assert all(c["runtime_usage_confirmed"] is False for c in caps)

class TestRuleFindingsAtIntake:

    @pytest.mark.asyncio
    async def test_rule_findings_persisted_with_computed_severity(
            self, app_db, tmp_path):
        """§9: catalogue detections are stored at intake as findings —
        detections, never verdicts — with computed severity factors."""
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(client, inventory)
            assert resp.status_code == 201, resp.text
            findings = (await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/findings",
                params={"tenant_id": "t1"})).json()["findings"]
            rule_rows = [f for f in findings
                         if f["finding_type"].startswith("OS-CRYPTO-")]
            assert rule_rows, "catalogue detections persisted at intake"
            for f in rule_rows:
                assert f["runtime_usage_confirmed"] is False
                if f["severity_label"]:
                    assert f["risk_model_version"] == "os-risk/1.0"
                    factors = f["severity_factors"]["factors"]
                    assert "S_security_significance" in factors
                    assert "score" not in f["severity_factors"], \
                        "never a multiplied numeric score"

    @pytest.mark.asyncio
    async def test_rule_catalogue_is_typed_and_never_verdicts(self, app_db):
        app, _db = app_db
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await client.get("/api/v1/os-intelligence/rules")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data["rules"]) == 18
            assert [r["rule_id"] for r in data["rules"]][0] == \
                "OS-CRYPTO-001"
            assert "never a multiplied" in data["note"] or \
                "not automatic" in data["note"]

    @pytest.mark.asyncio
    async def test_rule_evaluation_route_reports_not_evaluable_honestly(
            self, app_db, tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            resp = await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/"
                "rule-evaluation",
                params={"tenant_id": "t1"})
            assert resp.status_code == 200
            results = resp.json()["results"]
            assert len(results) == 18
            not_evaluable = [r for r in results
                             if r["status"] == "not_evaluable"]
            assert not_evaluable, "missing sources are honest"
            for r in not_evaluable:
                assert "never" in r["evaluation_note"].lower()

class TestBomProjection:

    @pytest.mark.asyncio
    async def test_bom_projection_round_trip(self, app_db, tmp_path):
        """§15 step 6: one recorded collection projects into the shared
        BOM ecosystem — no 'uses' edge, no fabricated versions."""
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            resp = await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/bom",
                params={"tenant_id": "t1", "kind": "cbom"})
            assert resp.status_code == 200, resp.text
            bom = resp.json()
            assert bom["schema"] == "cryptoscan.os-bom/1"
            assert bom["kind"] == "cbom"
            assert bom["components"], "the recorded host registers "
            assert all(c["properties"]["runtime_usage_confirmed"] is False
                       for c in bom["components"])
            assert all(r["relationship"] != "uses"
                       for r in bom["relationships"])
            assert "co-location" in bom["note"]
            tech = (await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/bom",
                params={"tenant_id": "t1", "kind": "techbom"})).json()
            assert tech["coverage"]["projections"] == \
                ["sbom", "cbom", "hbom"]

    @pytest.mark.asyncio
    async def test_unknown_bom_kind_refused_never_guessed(self, app_db,
                                                          tmp_path):
        app, _db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            resp = await client.get(
                "/api/v1/os-intelligence/assets/host-under-test/bom",
                params={"tenant_id": "t1", "kind": "vbom"})
            assert resp.status_code == 422
            assert "validated, never assumed" in resp.text

class TestTwinEdges:

    @pytest.mark.asyncio
    async def test_intake_writes_evidence_backed_twin_edges(
            self, app_db, tmp_path):
        """§8: collection intake derives digital-twin edges with
        provenance — provides/contains/anchors only, never 'uses'."""
        app, db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
        import sys
        sys.path.insert(0, str(_SERVICES / "database"))
        from db.repositories.os_intelligence_repository import (
            OSIntelligenceRepository,
        )
        repo = OSIntelligenceRepository(db)
        asset = repo.get_asset("t1", "host-under-test")
        edges = repo.list_twin_edges("t1", asset["collection_id"])
        assert edges, "the recorded host yields relationship edges"
        for e in edges:
            assert e["predicate"] in ("provides", "contains", "anchors"), \
                f"forbidden predicate {e['predicate']!r} — this engine " \
                "never emits 'uses' or indicator predicates (§8)"
            assert e["provenance"] in (
                "directly_observed", "static_dependency",
                "configuration_derived", "inferred", "unresolved")
            assert e["evidence_class"]
            assert isinstance(e["limitations"], list)

    @pytest.mark.asyncio
    async def test_twin_snapshot_carries_os_relationships(
            self, app_db, tmp_path):
        """The captured twin snapshot round-trips the OS edges: an
        immutable twin version answers with evidence-backed
        relationships (§8)."""
        app, db = app_db
        inventory = _real_inventory(tmp_path)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            await _post_collection(client, inventory)
            created = await client.post("/api/v1/digital-twin/snapshot")
            assert created.status_code in (200, 201), created.text
            version = created.json()["version"]
            resp = await client.get(
                f"/api/v1/digital-twin/snapshots/{version}")
            assert resp.status_code == 200, resp.text
            state = resp.json().get("state") or resp.json()
            rels = state.get("os_relationships")
            assert rels is not None, "the twin state exposes os_relationships"
            assert rels, "the recorded host yields edges into the twin"
            for e in rels:
                assert e["predicate"] in ("provides", "contains",
                                          "anchors")
                assert e["provenance"]
                assert e["evidence_class"]
            coverage = state["source_coverage"]["collections"]
            assert "os_relationships" in coverage

class TestWindowsPackage:

    @pytest.mark.asyncio
    async def test_windows_collection_round_trips_the_canonical_model(
            self, app_db):
        """§15 step 4/step 9: one canonical model — a Windows package
        records and serves through the same os_assets…os_coverage
        path. PROVENANCE: fixture data reconstructed from documented
        output formats — NOT a Windows fleet qualification (§12)."""
        import sys
        sys.path.insert(0, str(_SERVICES / "os_intelligence"))
        from os_intelligence.windows import collect_windows

        app, _db = app_db
        win_fixtures = (_SERVICES / "os_intelligence" / "tests" /
                        "fixtures" / "windows")
        captured = {
            "systeminfo": (win_fixtures / "systeminfo.txt").read_text(),
            "certutil_csplist":
                (win_fixtures / "certutil_csplist.txt").read_text(),
            "reg_schannel_protocols":
                (win_fixtures / "reg_schannel.txt").read_text(),
            "manage_bde": (win_fixtures / "manage_bde.txt").read_text(),
            "get_tpm": (win_fixtures / "get_tpm.txt").read_text(),
            "confirm_secureboot":
                (win_fixtures / "confirm_secureboot.txt").read_text(),
            "driverquery": (win_fixtures / "driverquery.txt").read_text(),
        }
        inventory = collect_windows("win-host-under-test", captured)
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url="http://test") as client:
            resp = await _post_collection(
                client, inventory, asset_id="win-host-under-test")
            assert resp.status_code == 201, resp.text
            assets = (await client.get(
                "/api/v1/os-intelligence/assets",
                params={"tenant_id": "t1"})).json()["assets"]
            win = [a for a in assets
                   if a["asset_id"] == "win-host-under-test"][0]
            assert win["kernel_release"] == "10.0.20348"
            assert win["environment_development_only"] is True
            caps = (await client.get(
                "/api/v1/os-intelligence/assets/win-host-under-test/"
                "crypto-capabilities",
                params={"tenant_id": "t1"})).json()["capabilities"]
            assert caps
            assert all(c["runtime_usage_confirmed"] is False
                       for c in caps)
            findings = (await client.get(
                "/api/v1/os-intelligence/assets/win-host-under-test/"
                "findings",
                params={"tenant_id": "t1"})).json()["findings"]
            rule_rows = [f for f in findings
                         if f["finding_type"].startswith("OS-CRYPTO-")]
            assert rule_rows, "the shared rule catalogue evaluated"
            tls = [f for f in rule_rows
                   if f["finding_type"] == "OS-CRYPTO-006"]
            assert tls, "weak TLS permitted by configuration fires"
            assert tls[0]["details"]["observed_runtime_negotiation"] == \
                "Not established"
