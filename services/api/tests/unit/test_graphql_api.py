"""``POST /graphql`` — the same facts the REST endpoints serve, in one query.

The tests that matter here are the cross-checks: a scan run over REST, then read
through GraphQL, must report the same artifact id, the same counts and the same
findings. If the two surfaces can disagree, an operator comparing them has to
decide which one is lying.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

_SERVICES = Path(__file__).resolve().parents[3]
if str(_SERVICES / "devsecops") not in sys.path:
    sys.path.insert(0, str(_SERVICES / "devsecops"))


def _binary_fixtures():
    path = _SERVICES / "devsecops" / "tests" / "test_binary_scan.py"
    name = "binary_scan_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _binary_fixtures()
_elf64 = fixtures._elf64
OPENSSL_BANNER = "OpenSSL 3.0.20 7 Apr 2026"


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    # The scan-admission seam (round 9) opens the GLOBAL SessionLocal, not
    # the overridden request session — bind it to this test's engine so the
    # gate reads this test's (empty) control plane instead of depending on
    # whichever test file configured the factory earlier in the process.
    from db.connection.session import configure_session

    configure_session(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("CRYPTOSCAN_KNOWLEDGE_DIR", str(tmp_path / "knowledge"))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session, tmp_path
    application.dependency_overrides.clear()


def _viewer_app(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    from db.models.user import User

    session.add(User(username="viewer1", password_hash="x", roles="readonly"))
    session.commit()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "viewer1"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application


async def _post(application, url, payload):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(url, json=payload, headers={"Authorization": "Bearer test"})


async def _get(application, url):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(url, headers={"Authorization": "Bearer test"})


async def _gql(application, query: str, variables=None):
    return await _post(application, "/api/v1/graphql", {"query": query, "variables": variables})


def _scan_target(tmp_path: Path) -> Path:
    directory = tmp_path / "images"
    directory.mkdir()
    (directory / "libcrypto.so.3").write_bytes(
        _elf64(deps=("libc.so.6", "libssl.so.3"), soname="libcrypto.so.3",
               comment=b"GCC: (Ubuntu 13.2.0) 13.2.0\x00",
               imports=("EVP_EncryptInit_ex", "EVP_sha256"),
               exports=("RSA_sign", "EVP_md5"),
               strings=(OPENSSL_BANNER,)))
    return directory


def _stub_inline_runner(monkeypatch, session):
    """Stand in for the worker process.

    The inline runner opens its own ``SessionLocal``. For a job-row test that is
    noise rather than signal: the GraphQL surface reads the row, and the row is
    what this stub completes. The real worker path — a separate process writing
    the same row — is exercised by the live drill and by the pipeline's own tests.
    """
    from types import SimpleNamespace

    import api.routers.trigger as trigger
    from db.repositories.job_repository import JobRepository

    monkeypatch.setattr(trigger, "get_settings", lambda: SimpleNamespace(
        REDIS_URL="", SCAN_JOB_QUEUE_KEY="cryptoscan:jobs:queue"))

    def _run_inline(payload: dict) -> None:
        options = (payload.get("progress") or {}).get("scan_options") or {}
        artifact_id = options.get("artifact_id") or payload["job_id"]
        JobRepository(session).update_status(
            payload["job_id"], "COMPLETED",
            progress={"current_stage": "binary_ingest", "percent": 100, "stages_complete": 5,
                      "total_stages": 5, "scan_options": options,
                      "binary": {
                          "artifact_id": artifact_id, "binaries_scanned": 1, "findings": 2,
                          "yara_matches": 0,
                          "report_url": f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown",
                          "download_url": f"/api/v1/devsecops/sbom/{artifact_id}/download"}})
        session.commit()

    monkeypatch.setattr(trigger, "_run_inline", _run_inline)


async def _scan(application, target: Path) -> dict:
    response = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(target)})
    assert response.status_code == 201, response.text
    return response.json()


# ------------------------------------------------------------ access ------ #

@pytest.mark.asyncio
async def test_an_unauthenticated_query_is_401(app_db):
    application, _session, _tmp = app_db
    application.dependency_overrides.clear()  # no identity override
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/graphql", json={"query": "{ knowledge { packs { name } } }"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_a_read_only_role_can_query(tmp_path, monkeypatch):
    application = _viewer_app(tmp_path, monkeypatch)
    response = await _gql(application, "{ knowledge { builtinRules rulesetRules } }")
    assert response.status_code == 200, response.text
    assert response.json()["data"]["knowledge"]["builtinRules"] > 0


# ------------------------------------------------------------ refusal ----- #

@pytest.mark.asyncio
async def test_a_mutation_is_refused_with_400_and_the_reason(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "mutation { deleteEverything }")
    assert response.status_code == 400
    body = response.json()
    assert body["data"] is None
    assert body["errors"][0]["extensions"]["code"] == "INVALID_QUERY"
    assert "not supported" in body["errors"][0]["message"]
    assert "read-only" in body["errors"][0]["message"]


@pytest.mark.asyncio
async def test_a_subscription_is_refused(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "subscription { binaryJobs { jobId } }")
    assert response.status_code == 400
    assert "subscription operations are not supported" in response.json()["errors"][0]["message"]


@pytest.mark.asyncio
async def test_a_syntax_error_is_400_with_the_offset(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "{ binaryArtifacts { artifactId ")
    assert response.status_code == 400
    assert "unterminated selection set" in response.json()["errors"][0]["message"]


@pytest.mark.asyncio
async def test_put_is_405_and_names_where_writes_live(app_db):
    application, _session, _tmp = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.put("/api/v1/graphql", json={"query": "{ knowledge }"},
                                        headers={"Authorization": "Bearer test"})
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, POST"
    assert response.json()["errors"][0]["extensions"]["code"] == "READ_ONLY_SURFACE"


# ------------------------------------------------------------- shape ------ #

@pytest.mark.asyncio
async def test_a_field_that_is_not_in_the_schema_is_reported_not_guessed(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "{ knowledge { nope } }")
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["knowledge"]["nope"] is None
    assert body["errors"][0]["path"] == ["knowledge", "nope"]
    assert body["errors"][0]["extensions"]["code"] == "FIELD_NOT_IN_SCHEMA"


@pytest.mark.asyncio
async def test_variables_round_trip(app_db):
    application, _session, tmp_path = app_db
    await _scan(application, _scan_target(tmp_path))
    response = await _gql(
        application,
        "query Q($n: Int, $q: String) { binaryArtifacts(limit: $n, q: $q) { artifactId } }",
        {"n": 5, "q": "images"})
    assert response.status_code == 200
    assert len(response.json()["data"]["binaryArtifacts"]) == 1


@pytest.mark.asyncio
async def test_an_undeclared_variable_in_the_request_is_400(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "query Q($n: Int) { binaryArtifacts(limit: $n) { artifactId } }",
                          {"nope": 1})
    assert response.status_code == 400
    assert "not declared" in response.json()["errors"][0]["message"]


# -------------------------------------------------- the same facts as REST -- #

@pytest.mark.asyncio
async def test_a_scan_then_a_query_reports_the_same_artifact(app_db):
    application, _session, tmp_path = app_db
    scan = await _scan(application, _scan_target(tmp_path))
    artifact_id = scan["artifact_id"]

    response = await _gql(application, """
      query {
        binaryArtifact(id: "%s") {
          artifactId kind target format sha256 binaryCount componentCount
          compliant minimumElements rulesetDigest
          findingsBySeverity
          posture { signaturePosture keyMaterial }
        }
      }
    """ % artifact_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["errors"] is None
    card = body["data"]["binaryArtifact"]
    assert card["artifactId"] == artifact_id
    assert card["kind"] == "binary"
    assert card["binaryCount"] == scan["manifest"]["binary_count"]
    assert card["componentCount"] == scan["manifest"]["component_count"]
    assert card["compliant"] == scan["manifest"]["compliant"]
    assert card["sha256"] == scan["manifest"]["sha256"]
    assert card["posture"]["keyMaterial"] == scan["manifest"]["binary_summary"]["key_material"]


@pytest.mark.asyncio
async def test_findings_through_graphql_match_the_rest_scan(app_db):
    application, _session, tmp_path = app_db
    scan = await _scan(application, _scan_target(tmp_path))
    artifact_id = scan["artifact_id"]

    response = await _gql(application, """
      query {
        binaryArtifact(id: "%s") {
          findings(limit: 50) { returned total truncated items { code severity title } }
        }
      }
    """ % artifact_id)
    page = response.json()["data"]["binaryArtifact"]["findings"]
    assert page["total"] == len(scan["findings"])
    assert page["items"], "the fixture scan must produce findings"
    assert {row["code"] for row in page["items"]} == {row["code"] for row in scan["findings"]}
    assert {row["severity"] for row in page["items"]} == {row["severity"] for row in scan["findings"]}


@pytest.mark.asyncio
async def test_the_severity_filter_narrows_the_excerpt(app_db):
    application, _session, tmp_path = app_db
    scan = await _scan(application, _scan_target(tmp_path))
    high = [row for row in scan["findings"] if row["severity"] == "HIGH"]
    response = await _gql(application, """
      query {
        binaryArtifact(id: "%s") {
          all: findings { returned }
          high: findings(severity: "HIGH") { returned total items { severity } }
        }
      }
    """ % scan["artifact_id"])
    data = response.json()["data"]["binaryArtifact"]
    assert data["high"]["returned"] == len(high)
    assert all(item["severity"] == "HIGH" for item in data["high"]["items"])
    assert data["high"]["total"] == data["all"]["returned"]


@pytest.mark.asyncio
async def test_crypto_and_yara_resolve_from_the_stored_artifact(app_db):
    application, _session, tmp_path = app_db
    scan = await _scan(application, _scan_target(tmp_path))
    response = await _gql(application, """
      query {
        binaryArtifact(id: "%s") {
          crypto { algorithms libraryCount cbomPresent libraries { name algorithms } }
          yara { matches byRule { rule count } rules digest sources }
          cbom { present count }
        }
      }
    """ % scan["artifact_id"])
    data = response.json()["data"]["binaryArtifact"]
    algorithms = scan["manifest"]["binary_summary"]["algorithms"]
    assert data["crypto"]["algorithms"] == algorithms
    assert data["crypto"]["cbomPresent"] is True
    assert data["crypto"]["libraries"], "the CBOM carries the crypto implementations"
    assert data["cbom"]["count"] == len(scan["cbom"]["components"])
    assert data["yara"]["matches"] == 0
    assert data["yara"]["digest"] == scan["manifest"]["binary_summary"]["yara"]["digest"]


@pytest.mark.asyncio
async def test_an_unknown_artifact_is_null_not_an_error(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, '{ binaryArtifact(id: "00000000-0000-0000-0000-000000000000") '
                                       "{ artifactId } }")
    assert response.status_code == 200
    assert response.json()["data"]["binaryArtifact"] is None
    assert response.json()["errors"] is None


@pytest.mark.asyncio
async def test_listing_reports_how_many_were_seen_and_how_many_returned(app_db):
    application, _session, tmp_path = app_db
    for index in range(3):
        target = tmp_path / f"img{index}"
        target.mkdir()
        (target / "app.bin").write_bytes(_elf64(soname=f"app{index}.so", strings=(OPENSSL_BANNER,)))
        await _scan(application, target)
    response = await _gql(application, """
      { binaryArtifacts(limit: 2) { artifactId label } }
    """)
    body = response.json()
    assert len(body["data"]["binaryArtifacts"]) == 2
    assert body["extensions"]["artifacts_seen"] == 3
    assert body["extensions"]["artifacts_returned"] == 2
    assert body["extensions"]["limits"] == {"depth": 12, "fields": 500, "list": 200}


@pytest.mark.asyncio
async def test_a_search_term_filters_the_listing(app_db):
    application, _session, tmp_path = app_db
    await _scan(application, _scan_target(tmp_path))
    response = await _gql(application, '{ binaryArtifacts(q: "nothing-matches-this") { artifactId } }')
    assert response.json()["data"]["binaryArtifacts"] == []
    assert response.json()["extensions"]["artifacts_seen"] == 0


# ------------------------------------------------- jobs, batch, knowledge -- #

@pytest.mark.asyncio
async def test_a_queued_job_is_readable_through_graphql(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_inline_runner(monkeypatch, session)
    queued = await _post(application, "/api/v1/devsecops/binary/jobs",
                         {"target": str(_scan_target(tmp_path))})
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["job_id"]

    response = await _gql(application, """
      query { binaryJob(id: "%s") { jobId jobType status stage percent artifactId reportUrl
                                    stagesComplete totalStages target terminal } }
    """ % job_id)
    card = response.json()["data"]["binaryJob"]
    assert card["jobId"] == job_id
    assert card["jobType"] == "BINARY"
    assert card["status"] == "COMPLETED"
    assert card["terminal"] is True
    assert card["stage"] == "binary_ingest"
    assert card["percent"] == 100
    assert card["stagesComplete"] == card["totalStages"] == 5
    assert card["artifactId"] == queued.json()["artifact_id"]
    assert card["target"].endswith("images")
    assert card["reportUrl"].endswith("/report?fmt=markdown")


@pytest.mark.asyncio
async def test_an_unknown_job_is_an_error_that_says_so(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, '{ binaryJob(id: "no-such-job") { jobId } }')
    assert response.status_code == 200
    assert response.json()["data"]["binaryJob"] is None
    assert response.json()["errors"] is None  # not found is not an error, it is an answer


@pytest.mark.asyncio
async def test_listing_jobs_filters_by_type(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_inline_runner(monkeypatch, session)
    await _post(application, "/api/v1/devsecops/binary/jobs", {"target": str(_scan_target(tmp_path))})
    response = await _gql(application,
                          '{ binaryJobs(jobType: "BINARY") { jobId jobType status batchId } }')
    rows = response.json()["data"]["binaryJobs"]
    assert rows and all(row["jobType"] == "BINARY" for row in rows)
    assert rows[0]["status"] == "COMPLETED"
    none = await _gql(application, '{ binaryJobs(jobType: "CHECK") { jobId } }')
    assert none.json()["data"]["binaryJobs"] == []


@pytest.mark.asyncio
async def test_a_batch_is_readable_with_its_totals(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_inline_runner(monkeypatch, session)
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / "app.bin").write_bytes(_elf64(soname="app.so", strings=(OPENSSL_BANNER,)))
    pass_result = await _post(application, "/api/v1/devsecops/binary/batch",
                              {"spool": str(spool), "dry_run": False})
    assert pass_result.status_code == 200, pass_result.text
    batch_id = pass_result.json()["batch_id"]

    response = await _gql(application, """
      query { binaryBatch(batchId: "%s") {
        batchId jobs byStatus { status count } totals { binariesScanned findings }
        files { jobId status artifactId batchId }
        window { lookedAt limit truncated }
      } }
    """ % batch_id)
    body = response.json()
    assert body["errors"] is None, body
    batch = body["data"]["binaryBatch"]
    assert batch["jobs"] == 1
    assert batch["byStatus"] == [{"status": "COMPLETED", "count": 1}]
    assert batch["totals"]["binariesScanned"] == 1
    assert batch["files"][0]["status"] == "COMPLETED"
    assert batch["files"][0]["artifactId"] == pass_result.json()["queued_files"][0]["artifact_id"]
    assert batch["window"]["truncated"] is False
    assert batch["files"][0]["batchId"] == batch_id


@pytest.mark.asyncio
async def test_knowledge_reports_the_set_a_scan_uses(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, """
      { knowledge { builtinRules rulesetRules rulesetDigest packs { name version } } }
    """)
    knowledge = response.json()["data"]["knowledge"]
    assert knowledge["builtinRules"] > 0
    assert knowledge["rulesetRules"] == knowledge["builtinRules"]
    assert knowledge["packs"] == []


@pytest.mark.asyncio
async def test_an_installed_pack_shows_up_in_the_graphQL_schema(app_db):
    application, _session, tmp_path = app_db
    from devsecops import knowledge as kb

    built = kb.build_pack("acme-fips", rules={"acme.yar": "rule acme_dsa { condition: filesize > 0 }"},
                          version="2026.09", out_dir=tmp_path / "built")
    kb.sign_pack(built["pack_dir"], secret="secret-value", key_id="offline-2026")
    install = await _post(application, "/api/v1/devsecops/knowledge/install",
                          {"pack": built["pack_dir"], "secret": "secret-value"})
    assert install.status_code == 200, install.text

    response = await _gql(application, """
      { knowledge { builtinRules rulesetRules packs { name version signedBy rules } } }
    """)
    knowledge = response.json()["data"]["knowledge"]
    assert knowledge["packs"] == [{"name": "acme-fips", "version": "2026.09",
                                   "signedBy": "offline-2026", "rules": ["acme_dsa"]}]
    assert knowledge["rulesetRules"] > knowledge["builtinRules"]  # the pack's rule joined the set


@pytest.mark.asyncio
async def test_runtime_findings_are_queryable(app_db):
    application, _session, _tmp = app_db
    ingest = await _post(application, "/api/v1/scans/runtime-findings", {
        "scanner_id": "ld-preload-agent-v1.0",
        "findings": [{"process_name": "sample.elf", "algorithm": "MD5", "observation_count": 3,
                      "extra": {"kind": "binary-dynamic", "source": "ld-preload"}}]})
    assert ingest.status_code in (200, 201), ingest.text

    response = await _gql(application, """
      { runtimeFindings(limit: 10, kind: "session") {
          returned items { process algorithm status weakTls observations source }
          summary } }
    """)
    body = response.json()
    assert body["errors"] is None, body
    rows = body["data"]["runtimeFindings"]["items"]
    assert [row["algorithm"] for row in rows] == ["MD5"]
    assert rows[0]["weakTls"] is True
    assert rows[0]["source"] == "ld-preload"
    assert body["data"]["runtimeFindings"]["summary"]


# ----------------------------------------------------------- discovery ----- #

@pytest.mark.asyncio
async def test_the_schema_endpoint_lists_what_it_resolves(app_db):
    application, _session, _tmp = app_db
    response = await _get(application, "/api/v1/graphql/schema")
    assert response.status_code == 200
    body = response.json()
    assert set(body["root_fields"]) >= {"binaryArtifacts", "binaryArtifact", "binaryJobs",
                                        "binaryBatch", "knowledge", "runtimeFindings"}
    assert "BinaryArtifact" in body["types"]
    assert body["refused"] == ["mutation", "subscription",
                              "directives other than @skip/@include"]


@pytest.mark.asyncio
async def test_introspection_lite_lists_fields_from_the_query_surface(app_db):
    application, _session, _tmp = app_db
    response = await _gql(application, "{ __schema { types { name fields } note } }")
    types = {row["name"]: row for row in response.json()["data"]["__schema"]["types"]}
    assert "BinaryArtifact" in types
    assert "findings" in types["BinaryArtifact"]["fields"]
    note = response.json()["data"]["__schema"]["note"].lower()
    assert "mutations" in note and "refused" in note


@pytest.mark.asyncio
async def test_a_get_query_with_variables_works(app_db):
    application, _session, tmp_path = app_db
    await _scan(application, _scan_target(tmp_path))
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/v1/graphql",
                params={"query": "query Q($n: Int) { binaryArtifacts(limit: $n) { artifactId } }",
                        "variables": json.dumps({"n": 1})},
                headers={"Authorization": "Bearer test"})
    assert response.status_code == 200, response.text
    assert len(response.json()["data"]["binaryArtifacts"]) == 1


@pytest.mark.asyncio
async def test_bad_variables_in_a_get_query_are_400(app_db):
    application, _session, _tmp = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/graphql",
                                        params={"query": "{ knowledge { builtinRules } }",
                                                "variables": "[1,2]"},
                                        headers={"Authorization": "Bearer test"})
    assert response.status_code == 400
    assert response.json()["errors"][0]["extensions"]["code"] == "BAD_VARIABLES"
