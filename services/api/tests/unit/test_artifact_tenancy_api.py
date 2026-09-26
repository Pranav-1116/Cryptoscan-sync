"""Binary artifacts belong to a tenant: the API enforces it and says how they are sealed.

Two tenants scan into one store here, which is what makes the isolation testable
rather than asserted: tenant A writes, tenant B is refused (as *absent*, because an
id that exists elsewhere is not something B needs to learn), and the operator's own
view shows the sealing that protects both.
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
from db.models.tenant import Tenant, TenantMembership
from db.models.user import User

# services/api/tests/unit/<this file> -> services/
_SERVICES = Path(__file__).resolve().parents[3]


def _binary_fixtures():
    """The devsecops unit suite's byte-level fixture builders (shared with it)."""
    path = _SERVICES / "devsecops" / "tests" / "test_binary_scan.py"
    name = "binary_scan_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MASTER = "api-tenancy-master"
#: the banner the shared fixtures use, so the scan finds a real version to cite
OPENSSL_BANNER = "OpenSSL 3.0.20 14 Aug 2024"


def _target_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "images"
    directory.mkdir(exist_ok=True)
    fixtures = _binary_fixtures()
    (directory / "libcrypto.so.3").write_bytes(
        fixtures._elf64(deps=("libc.so.6", "libssl.so.3"), soname="libcrypto.so.3",
                        comment=b"GCC: (Ubuntu 13.2.0) 13.2.0\x00",
                        build_id=bytes.fromhex("7d90f38412d00023e58392b03612a24b62fcaede"),
                        imports=("EVP_EncryptInit_ex", "EVP_sha256"),
                        exports=("RSA_sign", "EVP_md5"),
                        strings=(OPENSSL_BANNER,)))
    return directory


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add(User(username="operator1", password_hash="x", roles="superadmin"))
    session.add(Tenant(id="acme", name="Acme Bank", slug="acme"))
    session.add(Tenant(id="globex", name="Globex", slug="globex"))
    session.add(TenantMembership(tenant_id="acme", username="operator1", tenant_role="admin"))
    session.add(TenantMembership(tenant_id="globex", username="operator1", tenant_role="admin"))
    session.commit()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator1"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("CRYPTOSCAN_ARTIFACT_KEY", MASTER)
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)
    monkeypatch.setattr(ds, "_INDEX_CACHE", {"signature": None, "at": 0.0, "rows": None})

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session, tmp_path
    application.dependency_overrides.clear()


def _headers(tenant: str | None) -> dict[str, str]:
    headers = {"Authorization": "Bearer test-token"}
    if tenant:
        headers["X-Tenant-ID"] = tenant
    return headers


async def _scan(client: AsyncClient, tenant: str | None, target: str = "images") -> dict:
    response = await client.post("/api/v1/devsecops/binary/scan",
                                 json={"target": target, "recursive": True, "format": "cyclonedx"},
                                 headers=_headers(tenant))
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_a_scan_is_stored_for_the_tenant_that_asked(app_db):
    application, _session, tmp_path = app_db
    _target_dir(tmp_path)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = await _scan(client, "acme")
            artifact_id = body["artifact_id"]
            assert body["tenant"] == "acme"
            assert body["at_rest"]["algorithm"] == "AES-256-GCM"
            assert body["manifest"]["storage_key"].startswith("tenants/acme/")
            assert body["manifest"]["at_rest"]["key_id"] == body["at_rest"]["key_id"]

            # the object on disk is not the document
            blob_path = (tmp_path / "sboms"
                         / (body["manifest"]["storage_key"].replace("/", "__") + ".enc"))
            assert b"CycloneDX" not in blob_path.read_bytes()

            # and what the API serves back is the plaintext one, verified over it
            report = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=json",
                                      headers=_headers("acme"))
            assert report.status_code == 200, report.text
            report_body = report.json()
            # the auditor report is a document about this artifact, and it names
            # the same target the manifest does
            assert body["manifest"]["target"] in json.dumps(report_body)
            verify = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/verify",
                                      headers=_headers("acme"))
            assert verify.status_code == 200, verify.text
            # verification is over the plaintext, so sealing the artifact did not
            # change its verdict
            verdict = verify.json()
            assert verdict["signed"] is True
            assert verdict["verdict"] == "OK", verdict
            download = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/download",
                                        headers=_headers("acme"))
            assert download.status_code == 200
            assert json.loads(download.content)["bomFormat"] == "CycloneDX"


@pytest.mark.asyncio
async def test_another_tenant_cannot_read_it_and_does_not_see_it_listed(app_db):
    application, _session, tmp_path = app_db
    _target_dir(tmp_path)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            artifact_id = (await _scan(client, "acme"))["artifact_id"]

            for path in (f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=json",
                         f"/api/v1/devsecops/sbom/{artifact_id}/download",
                         f"/api/v1/devsecops/sbom/{artifact_id}/verify",
                         f"/api/v1/devsecops/binary/artifacts/{artifact_id}/cbom"):
                other = await client.get(path, headers=_headers("globex"))
                assert other.status_code == 404, (path, other.status_code, other.text)
                mine = await client.get(path, headers=_headers("acme"))
                assert mine.status_code == 200, (path, mine.status_code, mine.text)

            diff = await client.post("/api/v1/devsecops/sbom/diff",
                                     json={"from_artifact": artifact_id, "to_artifact": artifact_id},
                                     headers=_headers("globex"))
            assert diff.status_code == 404

            listed = (await client.get("/api/v1/devsecops/sbom/artifacts",
                                       headers=_headers("globex"))).json()
            assert [row["artifact_id"] for row in listed["artifacts"]] == []
            owned = (await client.get("/api/v1/devsecops/sbom/artifacts",
                                      headers=_headers("acme"))).json()
            assert [row["artifact_id"] for row in owned["artifacts"]] == [artifact_id]


@pytest.mark.asyncio
async def test_the_at_rest_endpoint_answers_what_is_encrypted_and_with_which_key(app_db):
    application, _session, tmp_path = app_db
    _target_dir(tmp_path)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await _scan(client, "acme")
            body = (await client.get("/api/v1/devsecops/binary/at-rest",
                                     headers=_headers("acme"))).json()
            assert body["tenant"] == "acme"
            assert body["artifacts"] == 1
            assert body["by_algorithm"] == {"AES-256-GCM": 1}
            assert body["plaintext_artifacts"] == 0
            assert body["at_rest"]["encrypted"] is True
            assert list(body["by_key_id"]) == [body["at_rest"]["key_id"]]
            assert MASTER not in json.dumps(body)

            other = (await client.get("/api/v1/devsecops/binary/at-rest",
                                      headers=_headers("globex"))).json()
            assert other["artifacts"] == 0
            assert other["at_rest"]["key_id"] != body["at_rest"]["key_id"]


@pytest.mark.asyncio
async def test_a_session_caller_cannot_name_a_tenant_it_is_not_a_member_of(app_db):
    application, _session, tmp_path = app_db
    _target_dir(tmp_path)
    application.dependency_overrides[get_current_user] = lambda: "outsider"
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/devsecops/sbom/artifacts", headers=_headers("acme"))
    assert response.status_code == 403
    assert "not a member of tenant acme" in response.text


@pytest.mark.asyncio
async def test_a_platform_scan_is_readable_without_a_tenant_header(app_db):
    """An install with no tenants keeps working: the estate is a bucket too."""
    application, _session, tmp_path = app_db
    _target_dir(tmp_path)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            body = await _scan(client, None)
            assert body["tenant"] is None
            assert body["manifest"]["tenant_bucket"] == "platform"
            report = await client.get(f"/api/v1/devsecops/sbom/{body['artifact_id']}/report",
                                      headers=_headers(None))
            assert report.status_code == 200
            # the platform estate's artifacts are not visible in a tenant's list
            tenants_view = (await client.get("/api/v1/devsecops/sbom/artifacts",
                                             headers=_headers("acme"))).json()
            assert [row["artifact_id"] for row in tenants_view["artifacts"]] == []
            estate = (await client.get("/api/v1/devsecops/sbom/artifacts",
                                       headers=_headers(None))).json()
            assert [row["artifact_id"] for row in estate["artifacts"]] == [body["artifact_id"]]
