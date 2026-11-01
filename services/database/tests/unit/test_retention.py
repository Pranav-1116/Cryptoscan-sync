"""Retention: the present survives, the archive precedes the delete, holds stop it."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from db.models.estate_catalog import EstateEvidenceRecord, EstateObservationRecord


@pytest.fixture()
def db(tmp_path):
    from db.connection.session import Base

    import db.models  # noqa: F401 — registers every model on the metadata

    path = tmp_path / "retention.db"
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, future=True)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=800)


def _observation(db, *, asset: str, fact: str, value: str, state: str,
                 seen: datetime, tenant: str | None = None, evidence: str | None = None):
    row = EstateObservationRecord(
        tenant_id=tenant,
        observation_id=f"{asset}|{fact}|{value}",
        asset_id=asset,
        fact_type=fact,
        value=value,
        lifecycle_state=state,
        first_seen_at=seen,
        last_seen_at=seen,
        observation_count=1,
        evidence_id=evidence,
    )
    db.add(row)
    return row


def _evidence(db, evidence_id: str, *, state: str, seen: datetime,
              tenant: str | None = None):
    db.add(EstateEvidenceRecord(
        tenant_id=tenant, evidence_id=evidence_id, lifecycle_state=state,
        evidence_type="RUNTIME_OBSERVED", source="agent", collector="agent",
        target_id="application:a",
        first_seen_at=seen, last_seen_at=seen, observation_count=1,
    ))


def _settings(**kw):
    base = dict(ESTATE_HISTORY_RETENTION_DAYS=365, ESTATE_EVIDENCE_RETENTION_DAYS=365,
                ESTATE_RETENTION_LEGAL_HOLD=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_only_superseded_facts_are_candidates(db):
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    _observation(db, asset="a", fact="region", value="new", state="CURRENT", seen=OLD)
    _observation(db, asset="b", fact="region", value="recent", state="HISTORICAL",
                 seen=NOW - timedelta(days=2))
    db.commit()

    policy = retention.policies(_settings())[0]
    candidate = retention.select_candidates(db, policy, now=NOW)

    assert candidate.count == 1
    assert candidate.rows[0]["value"] == "old"
    # A CURRENT fact is what the twin believes now; age does not make it history.
    assert all(row["lifecycle_state"] == "HISTORICAL" for row in candidate.rows)


def test_evidence_a_surviving_fact_still_points_at_is_kept(db):
    from db import retention

    _evidence(db, "ev-referenced", state="STALE", seen=OLD)
    _evidence(db, "ev-orphaned", state="STALE", seen=OLD)
    _observation(db, asset="a", fact="region", value="now", state="CURRENT",
                 seen=NOW, evidence="ev-referenced")
    db.commit()

    policy = retention.policies(_settings())[1]
    candidate = retention.select_candidates(db, policy, now=NOW)

    assert [row["evidence_id"] for row in candidate.rows] == ["ev-orphaned"]
    assert candidate.held_back_by_reference == 1


def test_the_archive_exists_before_the_delete_and_matches_it(db, tmp_path):
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    _observation(db, asset="a", fact="region", value="older", state="HISTORICAL", seen=OLD)
    _observation(db, asset="a", fact="region", value="now", state="CURRENT", seen=NOW)
    db.commit()

    receipt = retention.apply(db, now=NOW, archive_dir=tmp_path, settings=_settings())

    assert receipt.deleted["estate_observations"] == 2
    archive = tmp_path / "estate-history-20261101T120000Z.ndjson"
    assert archive.exists()
    lines = [json.loads(line) for line in archive.read_text().splitlines()]
    assert len(lines) == 2 == receipt.archive["rows"]
    assert {line["row"]["value"] for line in lines} == {"old", "older"}
    # the current fact is untouched
    values = {row.value for row in db.execute(select(EstateObservationRecord)).scalars()}
    assert values == {"now"}


def test_a_legal_hold_refuses_everything(db, tmp_path):
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    db.commit()

    receipt = retention.apply(db, now=NOW, archive_dir=tmp_path,
                              settings=_settings(ESTATE_RETENTION_LEGAL_HOLD=True))

    assert receipt.legal_hold is True
    assert receipt.refused and "legal hold" in receipt.refused
    assert receipt.deleted == {}
    assert not list(tmp_path.glob("*.ndjson")), "a hold must not archive anything either"
    assert db.execute(select(EstateObservationRecord)).scalars().all()


def test_a_window_inside_the_floor_is_refused_unless_forced(db, tmp_path):
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL",
                 seen=NOW - timedelta(days=45))
    db.commit()

    refused = retention.apply(db, now=NOW, archive_dir=tmp_path,
                              settings=_settings(ESTATE_HISTORY_RETENTION_DAYS=7))
    assert refused.refused and "floor" in refused.refused
    assert db.execute(select(EstateObservationRecord)).scalars().all()

    forced = retention.apply(db, now=NOW, archive_dir=tmp_path, force=True,
                             settings=_settings(ESTATE_HISTORY_RETENTION_DAYS=7))
    assert forced.deleted["estate_observations"] == 1


def test_a_dry_run_deletes_nothing_and_writes_no_archive(db, tmp_path):
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    db.commit()

    receipt = retention.apply(db, now=NOW, dry_run=True, archive_dir=tmp_path,
                              settings=_settings())

    assert receipt.dry_run is True
    assert receipt.deleted == {"estate_observations": 0, "estate_evidence": 0}
    assert not list(tmp_path.glob("*.ndjson"))
    assert db.execute(select(EstateObservationRecord)).scalars().all()


def test_the_receipt_is_audited(db, tmp_path):
    from db import retention
    from db.models.user import AuditLog

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    db.commit()

    retention.apply(db, now=NOW, archive_dir=tmp_path, settings=_settings())

    rows = db.execute(select(AuditLog).where(AuditLog.action == "estate.retention.apply")
                      ).scalars().all()
    assert rows, "a prune that leaves no trace is an unexplained data loss"
    assert "sha256" in (rows[0].detail or "")


def test_a_flat_store_says_so_instead_of_pretending_to_partition(db, tmp_path):
    """SQLite has no partitioned tables; the receipt must say that, not skip it."""
    from db import retention

    _observation(db, asset="a", fact="region", value="old", state="HISTORICAL", seen=OLD)
    db.commit()

    receipt = retention.apply(db, now=NOW, archive_dir=tmp_path, settings=_settings())

    assert receipt.partitions is not None
    assert receipt.partitions["supported"] is False
    assert "not partitioned" in receipt.partitions["note"]


def test_partition_names_and_bounds_are_monthly_and_utc():
    from db import partitions

    lower, upper = partitions.month_bounds(datetime(2026, 1, 31, 23, 59, tzinfo=timezone.utc))

    assert lower == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert upper == datetime(2026, 2, 1, tzinfo=timezone.utc)
    assert partitions.name_for(lower) == "estate_observations_y2026m01"
    # December rolls the year rather than the month index
    assert partitions.month_bounds(datetime(2026, 12, 5, tzinfo=timezone.utc))[1] == \
        datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_a_table_that_is_not_a_history_partition_is_never_dropped(db):
    from db import partitions

    with pytest.raises(ValueError):
        partitions.drop(db, "estate_observations")
    with pytest.raises(ValueError):
        partitions.drop(db, "estate_observations_y2026m01; DROP TABLE tenants")
