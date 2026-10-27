"""The asset identity spine end-to-end (§4.2, round 57).

crypto_assets rows now carry the canonical ``asset_key`` — the ONE
durable identity shared with evidence rows, fact rows and BOM
components. These tests pin the write-path discipline (maintained on
create, repaired on refresh, stable for cloud re-collection), the
migration backfill, and the reconcile visibility of forks.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register every table
from db.connection.session import Base
from db.fact_projection import reconcile_assets_with_facts
from db.models.crypto_asset import CryptoAsset
from db.repositories.asset_repository import AssetRepository
from shared_models.asset_identity import crypto_asset_key_from_row


def _scan_asset(algorithm="AES-256-GCM", path="src/Keys.java", line=10, **extra):
    return {"algorithm": algorithm, "purpose": "ENCRYPTION", "mode": "GCM",
            "key_size": 256, "file_path": path, "line_number": line,
            "confidence": "HIGH", "evidence_ids": ["ev-1"], **extra}


def test_replace_for_scan_sets_the_spine_key(db_session):
    stored = AssetRepository(db_session).replace_for_scan("scan-1", [_scan_asset()])
    assert stored[0].asset_key == crypto_asset_key_from_row(_scan_asset())


def test_rescan_with_same_merge_tuple_refreshes_one_row(db_session):
    repo = AssetRepository(db_session)
    first = repo.replace_for_scan("scan-1", [_scan_asset()])
    again = repo.replace_for_scan("scan-2", [_scan_asset(confidence="MEDIUM")])
    assert len(db_session.query(CryptoAsset).all()) == 1, "one asset, refreshed"
    assert again[0].id == first[0].id
    assert again[0].asset_key == first[0].asset_key


def test_line_drift_forks_rows_but_shares_the_spine_key(db_session):
    """Today's merge tuple includes line_number, so a line shift between
    scans forks rows — a known identity weakness the single-writer
    cutover must fix. The spine does NOT hide it: both rows carry the
    SAME canonical asset_key, so the fork is countable (reconcile)."""
    repo = AssetRepository(db_session)
    repo.replace_for_scan("scan-1", [_scan_asset(line=10)])
    repo.replace_for_scan("scan-2", [_scan_asset(line=44)])
    rows = db_session.query(CryptoAsset).order_by(CryptoAsset.line_number).all()
    assert len(rows) == 2, "merge-tuple fork (current, documented behavior)"
    assert rows[0].asset_key == rows[1].asset_key, "one canonical identity"
    report = reconcile_assets_with_facts(
        [r.to_dict() for r in rows], [])
    assert report["duplicate_asset_key_count"] == 1


def test_legacy_row_without_spine_is_repaired_on_refresh(db_session):
    """Pre-0092 rows (asset_key NULL) converge on first contact."""
    legacy = CryptoAsset(algorithm="AES", purpose="ENCRYPTION", mode="GCM",
                         key_size=256, file_path="src/Keys.java", line_number=10,
                         confidence="HIGH")
    db_session.add(legacy)
    db_session.flush()
    assert legacy.asset_key is None
    AssetRepository(db_session).replace_for_scan(
        "scan-1", [_scan_asset(algorithm="AES")])
    assert legacy.asset_key == crypto_asset_key_from_row(
        _scan_asset(algorithm="AES"))


def test_cloud_recollection_keeps_one_spine(db_session):
    repo = AssetRepository(db_session)
    ref = "aws-kms://eu-central-1/abcd-1234"
    payload = {"algorithm": "AES", "purpose": "ENCRYPTION", "key_size": 256,
               "file_path": ref}
    first, created = repo.upsert_cloud_asset(payload)
    assert created and first.asset_key == crypto_asset_key_from_row(payload)
    second, created_again = repo.upsert_cloud_asset(payload)
    assert not created_again and second.id == first.id
    assert second.asset_key == first.asset_key


def test_migration_backfill_converges_legacy_rows():
    """The 0092 backfill computes the canonical key for every row that
    lacks one — using the shared derivation, never a re-implementation."""
    import importlib.util
    from pathlib import Path

    migration_file = (
        Path(__file__).resolve().parents[2] / "migrations" / "versions"
        / "0092_crypto_asset_identity_spine.py"
    )
    spec = importlib.util.spec_from_file_location("mig_0092", migration_file)
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        legacy = CryptoAsset(algorithm="RSA", purpose="SIGNING", key_size=2048,
                             file_path="src/Legacy.java", line_number=1,
                             confidence="HIGH")
        from sqlalchemy.orm import Session
        with Session(bind=conn) as s:
            s.add(legacy)
            s.commit()
        updated = mig._backfill_asset_keys(conn)  # noqa: SLF001 — the migration's own seam
        conn.commit()
        row = conn.exec_driver_sql(
            "SELECT asset_key FROM crypto_assets").fetchone()
    expected = crypto_asset_key_from_row(
        {"algorithm": "RSA", "purpose": "SIGNING", "file_path": "src/Legacy.java",
         "key_size": 2048, "mode": None})
    assert updated == 1
    assert row[0] == expected
    engine.dispose()


def test_reconcile_reports_duplicate_spine_keys():
    """Two asset rows claiming one canonical identity — the fork the
    single-writer cutover must disposition — is counted, not hidden."""
    forked = [
        {"algorithm": "AES", "purpose": "ENCRYPTION", "file_path": "src/A.java",
         "key_size": 256, "mode": "GCM"},
        {"algorithm": "AES", "purpose": "ENCRYPTION", "file_path": "src/A.java",
         "key_size": 256, "mode": "GCM"},
        {"algorithm": "RSA", "purpose": "SIGNING", "file_path": "src/B.java",
         "key_size": 2048, "mode": None},
    ]
    facts = [
        {"algorithm": "AES", "purpose": "ENCRYPTION", "file_path": "src/A.java",
         "key_size": 256, "mode": "GCM"},
    ]
    report = reconcile_assets_with_facts(forked, facts)
    assert report["duplicate_asset_key_count"] == 1
    key = crypto_asset_key_from_row(forked[0])
    assert report["duplicate_asset_keys"] == {key: 2}
