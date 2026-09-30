"""Binary scan database read model: bounded, tenant-scoped, idempotent."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register the full metadata set
from db.connection.session import Base
from db.models.binary_scan import BinaryScanObservation, BinaryScanRecord
from db.tenancy import install_tenant_guard, tenant_scope
from devsecops.artifact_store import persist_binary_scan_index


TENANT = "11111111-1111-1111-1111-111111111111"


@pytest.fixture()
def session():
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _result():
    return {
        "target": "/release/app.apk",
        "files_walked": 3,
        "binaries_scanned": 2,
        "findings": [{"code": "BIN-PACKED", "severity": "MEDIUM", "detail": "packed"}],
        "limits": {"truncated": False, "max_depth": 2},
        "binaries": [
            {
                "path": "app.apk!lib/arm64-v8a/libcrypto.so",
                "format": "elf", "arch": "AArch64", "parsed": True,
                "sha256": "a" * 64, "derived_from": "app.apk", "depth": 1,
                "crypto": {"algorithms": ["AES"], "libraries": [{"library": "OpenSSL"}]},
                "hardening": {"pie": True},
                "signature": {"present": False, "note": "not trust validated"},
                "findings": [], "strings_sampled": 4,
                "fingerprints": {"build_fingerprint": "b" * 64, "code_sha256": "c" * 64},
            },
            {
                "path": "app.apk", "format": "zip", "parsed": True,
                "metadata": {"type": "android-package"},
            },
        ],
    }


def test_binary_index_is_bounded_and_idempotent(session):
    manifest = {
        "artifact_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "job_id": "job-1", "target": "/release/app.apk", "format": "cyclonedx",
        "sha256": "d" * 64, "binary_summary": {"constants": {"tables": 3}},
    }
    with tenant_scope(TENANT):
        assert persist_binary_scan_index(
            db=session, artifact_id=manifest["artifact_id"], scan=_result(),
            result=_result(), manifest=manifest, created_by="tester", tenant_id=TENANT)
        session.commit()

        record = session.query(BinaryScanRecord).one()
        observations = session.query(BinaryScanObservation).all()
        assert record.tenant_id == TENANT
        assert record.observations_count == 2
        assert len(observations) == 2
        assert observations[0].crypto["algorithms"] == ["AES"]
        assert observations[0].parser_metadata.get("sha256") is None  # hash is a first-class column

        # A retry of the same artifact replaces observations rather than duplicating them.
        updated = _result()
        updated["binaries"] = updated["binaries"][:1]
        assert persist_binary_scan_index(
            db=session, artifact_id=manifest["artifact_id"], scan=updated,
            result=updated, manifest=manifest, created_by="tester", tenant_id=TENANT)
        session.commit()
        assert session.query(BinaryScanRecord).count() == 1
        assert session.query(BinaryScanObservation).count() == 1
        assert session.query(BinaryScanRecord).one().observations_truncated is False


def test_index_isolated_for_same_artifact_id_across_tenants(session):
    manifest = {
        "artifact_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "target": "/tenant/app", "format": "cyclonedx", "sha256": "1" * 64,
        "binary_summary": {},
    }
    with tenant_scope(TENANT):
        assert persist_binary_scan_index(db=session, artifact_id=manifest["artifact_id"],
                                         scan=_result(), result=_result(), manifest=manifest,
                                         created_by="a", tenant_id=TENANT)
        session.commit()
    other = "22222222-2222-2222-2222-222222222222"
    with tenant_scope(other):
        assert persist_binary_scan_index(db=session, artifact_id=manifest["artifact_id"],
                                         scan=_result(), result=_result(), manifest=manifest,
                                         created_by="b", tenant_id=other)
        session.commit()
    assert session.query(BinaryScanRecord).filter(BinaryScanRecord.tenant_id == TENANT).count() == 1
    assert session.query(BinaryScanRecord).filter(BinaryScanRecord.tenant_id == other).count() == 1


def test_index_never_copies_key_material(session):
    manifest = {
        "artifact_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "target": "/release/key.bin", "format": "cyclonedx", "sha256": "e" * 64,
        "binary_summary": {},
    }
    result = _result()
    result["binaries"][0]["embedded_keys"] = {
        "keys": [{"material_sha256": "f" * 64, "kind": "private-key"}],
    }
    assert persist_binary_scan_index(
        db=session, artifact_id=manifest["artifact_id"], scan=result,
        result=result, manifest=manifest, created_by="tester", tenant_id=None)
    session.commit()
    observation = session.query(BinaryScanObservation).filter(
        BinaryScanObservation.artifact_id == manifest["artifact_id"]).first()
    assert observation is not None
    assert "embedded_keys" not in (observation.parser_metadata or {})
    assert "material_sha256" not in str(observation.parser_metadata)
