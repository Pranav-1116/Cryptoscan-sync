"""Detection knowledge over the API: verify, install, and prove the next scan loads it.

The install endpoint is a gate, not a copy: a pack that fails verification comes
back with the reasons and nothing changes on disk. The end-to-end test is the one
that matters most — install a signed pack, scan a binary, and see the pack's rule
match, which is how a disconnected install gets new detections.
"""
from __future__ import annotations

import hashlib
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

from devsecops import crypto_constants as cc  # noqa: E402
from devsecops import knowledge as kb  # noqa: E402

SECRET = "offline-transport-key"
TABLE_BYTES = bytes(range(1, 65))
TABLE_DOCUMENT = {
    "algorithm": "ACME-Cipher", "table": "rounds", "encoding": "hex",
    "bytes": TABLE_BYTES.hex(), "minimum": 32,
}
MARKER = b"ACME-BANNED-CIPHER-MARKER"
PACK_RULE = """
rule acme_banned_cipher
{
    meta:
        namespace = "acme-fips"
        description = "Acme policy: this cipher is not approved for the payment estate"
        severity = "HIGH"
    strings:
        $marker = "ACME-BANNED-CIPHER-MARKER" ascii
    condition:
        $marker
}
"""


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


def _signed_pack(tmp_path: Path, *, name: str = "acme-fips", version: str = "1.0.0",
                 text: str = PACK_RULE, secret: str = SECRET,
                 tables: dict | None = None) -> Path:
    built = kb.build_pack(name, rules={"acme.yar": text} if text else {},
                          tables=tables, version=version, out_dir=tmp_path / "built")
    pack = Path(built["pack_dir"])
    kb.sign_pack(pack, secret=secret, key_id="offline-2026")
    return pack


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
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

    session.add(User(username="viewer1", password_hash="x", roles="viewer"))
    session.commit()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "viewer1"
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    monkeypatch.setenv("CRYPTOSCAN_KNOWLEDGE_DIR", str(tmp_path / "knowledge"))
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


# --------------------------------------------------------------- reading --- #

@pytest.mark.asyncio
async def test_knowledge_reports_what_a_scan_will_load(app_db):
    application, _session, _tmp = app_db
    response = await _get(application, "/api/v1/devsecops/knowledge")
    assert response.status_code == 200
    body = response.json()
    assert body["builtin"]["rules"] > 0
    assert body["installed"] == {}
    assert body["installed_rule_files"] == []
    assert body["ruleset"]["rules"] == body["builtin"]["rules"]
    assert body["ruleset"]["digest"]
    # the constant database is reported next to the rules: what a scan searches is
    # two sets, and an operator auditing a scan needs both digests
    assert body["tables"]["builtin"] == len(cc.constant_tables())
    assert body["tables"]["installed"] == 0
    assert body["tables"]["digest"] == cc.tableset_digest(cc.constant_tables())
    assert body["tables"]["errors"] == []
    assert "AES" in body["tables"]["algorithms"]


@pytest.mark.asyncio
async def test_reading_the_knowledge_state_is_a_read_only_operation(tmp_path, monkeypatch):
    """A read-only operator can see which rules are loaded — that is the audit answer."""
    application = _viewer_app(tmp_path, monkeypatch)
    response = await _get(application, "/api/v1/devsecops/knowledge")
    assert response.status_code == 200
    assert response.json()["installed"] == {}


@pytest.mark.asyncio
async def test_a_viewer_cannot_install_a_pack(tmp_path, monkeypatch):
    application = _viewer_app(tmp_path, monkeypatch)
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(tmp_path / "whatever"), "secret": SECRET})
    assert response.status_code == 403
    assert kb.installed_rule_files() == []


# -------------------------------------------------------------- install --- #

@pytest.mark.asyncio
async def test_installing_a_signed_pack_makes_the_next_scan_load_it(app_db):
    application, _session, tmp_path = app_db
    pack = _signed_pack(tmp_path)
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(pack), "secret": SECRET})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["action"] == "installed" and body["installed"] is True
    assert body["verified_with"] == "default"
    assert body["loaded_rules"]["names"] == ["acme_banned_cipher"]
    assert kb.installed_rule_files()

    state = (await _get(application, "/api/v1/devsecops/knowledge")).json()
    assert state["installed"]["acme-fips"]["version"] == "1.0.0"
    assert state["installed"]["acme-fips"]["signed_by"] == "offline-2026"

    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    scan = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(sample)})
    assert scan.status_code == 201, scan.text
    matches = [row for row in scan.json()["findings"] if row["code"] == "BIN-YARA-MATCH"]
    assert [row["rule"] for row in matches] == ["acme_banned_cipher"]
    assert matches[0]["severity"] == "HIGH"


@pytest.mark.asyncio
async def test_a_scan_of_a_clean_binary_does_not_match_the_pack(app_db):
    application, _session, tmp_path = app_db
    await _post(application, "/api/v1/devsecops/knowledge/install",
                {"pack": str(_signed_pack(tmp_path)), "secret": SECRET})
    sample = tmp_path / "clean.bin"
    sample.write_bytes(_elf64(constants=b"APPROVED-CIPHER"))
    scan = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(sample)})
    assert scan.status_code == 201
    assert not [row for row in scan.json()["findings"] if row["code"] == "BIN-YARA-MATCH"]


@pytest.mark.asyncio
async def test_an_unsigned_pack_is_refused_with_the_reason(app_db):
    application, _session, tmp_path = app_db
    pack = kb.build_pack("acme-fips", rules={"acme.yar": PACK_RULE}, out_dir=tmp_path / "built")
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": pack["pack_dir"], "secret": SECRET})
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["message"].startswith("the pack was refused")
    assert any("pack.sig" in reason for reason in detail["reasons"])
    assert kb.installed_rule_files() == []


@pytest.mark.asyncio
async def test_a_tampered_pack_is_refused_and_names_the_file(app_db):
    application, _session, tmp_path = app_db
    pack = _signed_pack(tmp_path)
    (pack / "rules" / "acme.yar").write_text("rule acme_banned_cipher { condition: true }")
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(pack), "secret": SECRET})
    assert response.status_code == 400
    assert any("acme.yar" in reason for reason in response.json()["detail"]["reasons"])
    assert (await _get(application, "/api/v1/devsecops/knowledge")).json()["installed"] == {}


@pytest.mark.asyncio
async def test_the_wrong_secret_is_refused(app_db):
    application, _session, tmp_path = app_db
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(_signed_pack(tmp_path)), "secret": "not-the-key"})
    assert response.status_code == 400
    assert any("signature does not match" in reason for reason in response.json()["detail"]["reasons"])


@pytest.mark.asyncio
async def test_a_dry_run_verifies_without_installing(app_db):
    application, _session, tmp_path = app_db
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(_signed_pack(tmp_path)), "secret": SECRET, "dry_run": True})
    assert response.status_code == 200
    assert response.json()["action"] == "would-install"
    assert kb.installed_rule_files() == []


@pytest.mark.asyncio
async def test_a_bundle_on_media_can_be_installed_directly(app_db):
    application, _session, tmp_path = app_db
    bundle = kb.export_bundle(_signed_pack(tmp_path), tmp_path / "acme.tar.gz")
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": bundle["bundle"], "secret": SECRET})
    assert response.status_code == 200, response.text
    assert response.json()["action"] == "installed"
    assert "acme-fips/pack.json" in response.json()["extracted"]["members"]
    assert [path.name for path in kb.installed_rule_files()] == ["acme.yar"]


@pytest.mark.asyncio
async def test_a_pack_that_does_not_exist_is_a_400(app_db):
    application, _session, tmp_path = app_db
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(tmp_path / "not-there.tar.gz"), "secret": SECRET})
    assert response.status_code == 400
    assert "bundle not found" in json.dumps(response.json())


@pytest.mark.asyncio
async def test_installing_is_recorded_in_the_audit_trail(app_db):
    application, session, tmp_path = app_db
    await _post(application, "/api/v1/devsecops/knowledge/install",
                {"pack": str(_signed_pack(tmp_path)), "secret": SECRET})
    from db.models.user import AuditLog

    rows = session.query(AuditLog).filter(AuditLog.action == "devsecops.knowledge_installed").all()
    assert len(rows) == 1
    detail = json.loads(rows[0].detail) if isinstance(rows[0].detail, str) else rows[0].detail
    assert detail["version"] == "1.0.0" and detail["rules"] == ["acme.yar"]


@pytest.mark.asyncio
async def test_a_refusal_is_recorded_too(app_db):
    application, session, tmp_path = app_db
    pack = _signed_pack(tmp_path)
    (pack / "rules" / "acme.yar").write_text("rule acme_banned_cipher { condition: true }")
    await _post(application, "/api/v1/devsecops/knowledge/install",
                {"pack": str(pack), "secret": SECRET})
    from db.models.user import AuditLog

    rows = session.query(AuditLog).filter(AuditLog.action == "devsecops.knowledge_refused").all()
    assert len(rows) == 1


# ------------------------------------------------------------ uninstall --- #

@pytest.mark.asyncio
async def test_uninstalling_stops_the_rules_loading(app_db):
    application, _session, tmp_path = app_db
    await _post(application, "/api/v1/devsecops/knowledge/install",
                {"pack": str(_signed_pack(tmp_path)), "secret": SECRET})
    response = await _post(application, "/api/v1/devsecops/knowledge/uninstall", {"name": "acme-fips"})
    assert response.status_code == 200
    assert response.json()["removed"] is True
    assert kb.installed_rule_files() == []
    again = await _post(application, "/api/v1/devsecops/knowledge/uninstall", {"name": "acme-fips"})
    assert again.json()["removed"] is False


@pytest.mark.asyncio
async def test_uninstalling_something_that_was_never_installed_is_not_an_error(app_db):
    application, _session, _tmp = app_db
    response = await _post(application, "/api/v1/devsecops/knowledge/uninstall", {"name": "ghost"})
    assert response.status_code == 200 and response.json()["removed"] is False


# -------------------------------------------------------------- airgap ---- #

@pytest.mark.asyncio
async def test_an_offline_update_pack_installs_while_air_gapped(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    monkeypatch.setenv("AIRGAP_MODE", "true")
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(_signed_pack(tmp_path)), "secret": SECRET})
    assert response.status_code == 200, response.text
    assert response.json()["action"] == "installed"


@pytest.mark.asyncio
async def test_airgap_mode_still_blocks_an_active_scan(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    monkeypatch.setenv("AIRGAP_MODE", "true")
    sample = tmp_path / "appliance.bin"
    sample.write_bytes(_elf64(constants=MARKER))
    response = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(sample)})
    assert response.status_code == 423


# ------------------------------------------------- constant tables over the API -- #

@pytest.mark.asyncio
async def test_installing_a_table_only_pack_reports_the_table_it_added(app_db, tmp_path):
    """A pack with no rules is a valid update — it updates the constant database."""
    application, _session, _tmp = app_db
    pack = _signed_pack(tmp_path, name="acme-tables", text="",
                        tables={"acme.json": TABLE_DOCUMENT})
    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(pack), "secret": SECRET})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["action"] == "installed" and body["loaded_rules"] is None
    assert [row["algorithm"] for row in body["tables"]] == ["ACME-Cipher"]
    assert body["tables"][0]["bytes"] == 64

    state = (await _get(application, "/api/v1/devsecops/knowledge")).json()
    assert state["tables"]["installed"] == 1
    assert state["tables"]["sources"] == ["pack:acme-tables@1.0.0"]
    assert state["installed"]["acme-tables"]["tables"][0]["table"] == "rounds"


@pytest.mark.asyncio
async def test_a_table_that_would_shadow_the_built_ins_is_refused_with_reasons(app_db, tmp_path):
    """A correctly signed pack can still be refused, and the reason names the table.

    The build refuses this too, so the pack is assembled by hand the way a pack
    built by some other tool would be: signature valid, contents a relabelled
    built-in table. The install gate is what has to catch it.
    """
    application, _session, _tmp = app_db
    pack = _signed_pack(tmp_path, name="shadow", tables={"aes.json": TABLE_DOCUMENT})
    document = {"algorithm": "AES", "table": "S-box", "encoding": "hex",
                "bytes": cc.aes_sbox().hex(), "minimum": 32}
    table_file = pack / kb.TABLES_DIRNAME / "aes.json"
    table_file.write_text(json.dumps(document, indent=1, sort_keys=True))
    manifest = json.loads((pack / kb.MANIFEST_NAME).read_text())
    raw = table_file.read_bytes()
    manifest["tables"][0].update({"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                                  "algorithm": "AES", "table": "S-box", "bytes": 256})
    manifest["digest"] = kb.manifest_digest(manifest)
    (pack / kb.MANIFEST_NAME).write_text(json.dumps(manifest, indent=1, sort_keys=True))
    kb.sign_pack(pack, secret=SECRET, key_id="offline-2026")

    verify = kb.verify_pack(pack, secret=SECRET)
    assert verify["ok"] is False
    assert any("already exists in the database" in reason for reason in verify["reasons"])

    response = await _post(application, "/api/v1/devsecops/knowledge/install",
                           {"pack": str(pack), "secret": SECRET})
    assert response.status_code == 400
    reasons = response.json()["detail"]["reasons"]
    assert any("already exists in the database" in reason for reason in reasons)
    assert (await _get(application, "/api/v1/devsecops/knowledge")).json()["tables"]["installed"] == 0


@pytest.mark.asyncio
async def test_a_scan_over_the_api_names_an_algorithm_from_an_installed_table(app_db, tmp_path):
    """End to end: the update arrives over the API, and the next scan is different."""
    application, _session, _tmp = app_db
    target = tmp_path / "images"
    target.mkdir()
    (target / "app.bin").write_bytes(fixtures._elf64(soname="app.so",
                                                    constants=TABLE_BYTES * 2))

    before = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(target)})
    assert before.status_code == 201
    assert "ACME-Cipher" not in before.json()["manifest"]["binary_summary"]["algorithms"]

    pack = _signed_pack(tmp_path, name="acme-tables", text="",
                        tables={"acme.json": TABLE_DOCUMENT})
    assert (await _post(application, "/api/v1/devsecops/knowledge/install",
                        {"pack": str(pack), "secret": SECRET})).status_code == 200

    after = await _post(application, "/api/v1/devsecops/binary/scan", {"target": str(target)})
    assert after.status_code == 201
    manifest = after.json()["manifest"]
    assert "ACME-Cipher" in manifest["binary_summary"]["algorithms"]
    # the report states the table set it searched, next to the rule set
    tables = manifest["binary_summary"]["constants"]["tables"]
    assert tables["installed"] == 1 and tables["sources"] == ["pack:acme-tables@1.0.0"]
    assert tables["digest"] and tables["error_count"] == 0
    assert tables["total"] == tables["builtin"] + 1
    assert after.json()["artifact_id"] != before.json()["artifact_id"]
