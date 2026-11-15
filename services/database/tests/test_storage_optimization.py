"""Storage optimization engine tests (spec 2.1/7).

The contracts pinned here are the spec's: bytes stored once per tenant,
provenance NEVER merged, deltas instead of copies, compression measured
not claimed, chunking for large evidence, quotas that refuse loudly,
lifecycle that moves tiers before it deletes, GC that touches nothing
referenced, dry-run by default, and restore testing that proves recovery.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

# Register the storage models on Base for create_all.
import db.models.content_object  # noqa: F401
import db.models.evidence_content_link  # noqa: F401
import db.models.snapshot_delta  # noqa: F401
import db.models.storage_policy  # noqa: F401

from db.models.base import utcnow
from db.models.content_object import ContentObject
from db.models.evidence_content_link import EvidenceContentLink
from db.storage import (
    ContentAddressedStore, ContentCorruptionError, ContentGoneError,
    QuotaExceeded, check_quota, diff_items, ensure_default_policies,
    gc_unreferenced, materialize_snapshot, record_evidence_content,
    retention_sweep, run_restore_test, space_alerts, store_snapshot_delta,
    transition_tiers, usage_report, verify_restorable,
)
from db.storage.cas import CHUNK_SIZE, sha256_hex

TENANT = "tenant-a"


# ---------------------------------------------------------------- content store

def test_identical_evidence_stores_once_and_counts_references(db_session):
    cas = ContentAddressedStore(db_session)
    payload = b"RSA-2048 discovered on the gateway" * 10
    first = cas.put(TENANT, payload)
    second = cas.put(TENANT, payload)   # Tuesday
    third = cas.put(TENANT, payload)    # Wednesday
    assert first.deduped is False
    assert second.deduped is True and third.deduped is True
    assert first.sha256 == second.sha256 == third.sha256 == sha256_hex(payload)
    obj = db_session.query(ContentObject).filter_by(sha256=first.sha256).one()
    assert obj.ref_count == 3
    assert db_session.query(ContentObject).count() == 1
    assert cas.get(TENANT, first.sha256) == payload


def test_deduplication_never_crosses_tenants(db_session):
    cas = ContentAddressedStore(db_session)
    payload = b"the same bytes in two banks"
    a = cas.put("tenant-a", payload)
    b = cas.put("tenant-b", payload)
    assert a.sha256 == b.sha256  # same content address…
    assert a.deduped is False and b.deduped is False  # …two separate objects
    assert db_session.query(ContentObject).count() == 2
    assert cas.get("tenant-a", a.sha256) == payload
    assert cas.get("tenant-b", b.sha256) == payload


def test_provenance_survives_deduplication(db_session):
    payload = b"identical evidence bytes"
    ref1 = record_evidence_content(
        db_session, tenant_id=TENANT, data=payload, collector="host-scan",
        source_location="host-a:/etc/ssl", owner="team-pki",
        authorization_context={"grant": "scan:tls"}, observation_ref="obs-1",
    )
    ref2 = record_evidence_content(
        db_session, tenant_id=TENANT, data=payload, collector="ct-monitor",
        source_location="ct-log:example.com", owner="team-identity",
        authorization_context={"grant": "scan:ct"}, observation_ref="obs-2",
    )
    assert ref1.sha256 == ref2.sha256
    assert ref1.deduped is False and ref2.deduped is True
    links = db_session.query(EvidenceContentLink).all()
    assert len(links) == 2  # two collections, two provenance rows — never merged
    owners = {(l.owner, l.collector, l.source_location) for l in links}
    assert ("team-pki", "host-scan", "host-a:/etc/ssl") in owners
    assert ("team-identity", "ct-monitor", "ct-log:example.com") in owners
    # One content object; two references — one per collection event.
    obj = db_session.query(ContentObject).one()
    assert obj.ref_count == 2


def test_compression_saves_space_and_is_measured_not_claimed(db_session):
    cas = ContentAddressedStore(db_session)
    json_payload = json.dumps({"finding": "RSA-2048", "note": "x" * 2000}).encode()
    ref = cas.put(TENANT, json_payload, category="raw_collector_output")
    assert ref.codec == "zstd"
    assert ref.stored_size < ref.plain_size
    assert cas.get(TENANT, ref.sha256) == json_payload

    import os as _os
    random_payload = _os.urandom(5000)  # incompressible
    ref2 = cas.put(TENANT, random_payload)
    assert ref2.codec == "none"
    assert ref2.stored_size == ref2.plain_size


def test_large_evidence_is_chunked_and_shared_chunks_stay(db_session):
    cas = ContentAddressedStore(db_session)
    shared_head = b"A" * (CHUNK_SIZE + 1000)      # forces 2 chunks
    first = shared_head + b"first-tail" * 50_000  # > 1 chunk more
    second = shared_head + b"second-tail" * 50_000
    r1 = cas.put(TENANT, first)
    assert r1.chunk_count >= 2
    r2 = cas.put(TENANT, second)
    assert r2.chunk_count >= 2
    assert r1.sha256 != r2.sha256
    assert cas.get(TENANT, r1.sha256) == first
    assert cas.get(TENANT, r2.sha256) == second
    # The shared head chunk is stored once and referenced by both parents.
    head_sha = sha256_hex(b"A" * CHUNK_SIZE)
    head = db_session.query(ContentObject).filter_by(sha256=head_sha).one()
    assert head.ref_count == 2
    assert head.kind == "chunk"


def test_reads_verify_the_content_address(db_session):
    cas = ContentAddressedStore(db_session)
    ref = cas.put(TENANT, b"honest bytes")
    body = db_session.query(ContentObject).filter_by(sha256=ref.sha256).one()
    from db.models.content_object import ContentObjectBody
    row = db_session.query(ContentObjectBody).filter_by(object_sha256=ref.sha256).one()
    row.ciphertext = b"tampered"
    db_session.flush()
    with pytest.raises(Exception):  # DecryptionError or corruption
        cas.get(TENANT, ref.sha256)
    assert body.sha256 == ref.sha256


def test_retention_tombstone_never_resolves_bytes_but_history_survives(db_session):
    cas = ContentAddressedStore(db_session)
    ref = cas.put(TENANT, b"evidence bytes")
    obj = db_session.query(ContentObject).filter_by(sha256=ref.sha256).one()
    cas.objects.delete(TENANT, ref.sha256)
    obj.body_dropped_at = utcnow()
    db_session.flush()
    with pytest.raises(ContentGoneError):
        cas.get(TENANT, ref.sha256)
    # The metadata row survives as a tombstone: history still resolves.
    assert db_session.query(ContentObject).filter_by(sha256=ref.sha256).count() == 1
    # Re-collection resurrects the content under the same address.
    again = cas.put(TENANT, b"evidence bytes")
    assert again.deduped is True
    assert cas.get(TENANT, ref.sha256) == b"evidence bytes"


# ---------------------------------------------------------------- deltas

def test_snapshots_store_deltas_and_reference_unchanged_content(db_session):
    base_items = {"asset-1": b"RSA-2048", "asset-2": b"AES-256", "asset-3": b"ECC-P256"}
    store_snapshot_delta(
        db_session, tenant_id=TENANT, snapshot_id="snap-1", items=base_items)
    current_items = {
        "asset-1": b"RSA-2048",          # unchanged
        "asset-2": b"AES-128",           # changed
        "asset-4": b"CHACHA20",          # added
        # asset-3 removed
    }
    row = store_snapshot_delta(
        db_session, tenant_id=TENANT, snapshot_id="snap-2",
        items=current_items, base_snapshot_id="snap-1", base_items=base_items)
    assert row.added_count == 1
    assert row.changed_count == 1
    assert row.removed_count == 1
    assert row.unchanged_count == 1

    state1 = materialize_snapshot(db_session, TENANT, "snap-1")
    assert state1 == base_items
    state2 = materialize_snapshot(db_session, TENANT, "snap-2")
    assert state2 == current_items

    # Reference-based storage: the unchanged item's bytes exist once and
    # are shared by both snapshots (baseline put + snapshot-2 reference).
    unchanged_obj = db_session.query(ContentObject).filter_by(
        sha256=sha256_hex(b"RSA-2048")).one()
    assert unchanged_obj.ref_count == 2


def test_diff_items_is_the_pure_difference():
    diff = diff_items({"a": "1", "b": "2"}, {"b": "2", "c": "3"})
    assert diff.added == {"c": "3"}
    assert diff.removed == ["a"]
    assert diff.unchanged == ["b"]
    assert diff.changed == {}


# ---------------------------------------------------------------- quotas

def test_storage_quotas_refuse_loudly_before_the_disk_fills(db_session):
    from db.models.storage_policy import StorageQuota
    db_session.add(StorageQuota(tenant_id=TENANT, scope="tenant",
                                max_bytes=500, max_objects=0))
    db_session.flush()
    cas = ContentAddressedStore(db_session)
    cas.put(TENANT, b"x" * 300)
    with pytest.raises(QuotaExceeded):
        cas.put(TENANT, b"y" * 300)   # 600 > 500
    # Job budgets are checked under the job scope.
    db_session.add(StorageQuota(tenant_id=TENANT, scope="job", job_id="job-9",
                                max_bytes=100, max_objects=0))
    db_session.flush()
    with pytest.raises(QuotaExceeded):
        cas.put(TENANT, b"z" * 300, job_id="job-9")


# ---------------------------------------------------------------- lifecycle

def _backdate(obj, days: int) -> None:
    obj.created_at = utcnow() - timedelta(days=days)
    obj.updated_at = obj.created_at


def test_tiers_move_hot_to_warm_to_cold_by_policy(db_session):
    ensure_default_policies(db_session)
    cas = ContentAddressedStore(db_session)
    young = cas.put(TENANT, b"new")
    old = cas.put(TENANT, b"warm")
    older = cas.put(TENANT, b"cold")
    for sha, days in ((old.sha256, 10), (older.sha256, 100)):
        _backdate(db_session.query(ContentObject).filter_by(sha256=sha).one(), days)
    db_session.flush()

    dry = transition_tiers(db_session)
    assert dry.dry_run is True
    assert {a.detail.split(" -> ")[1].split(" ")[0] for a in dry.actions} == {"warm", "cold"}
    assert db_session.query(ContentObject).filter_by(
        sha256=old.sha256).one().storage_tier == "hot"  # dry-run touches nothing

    wet = transition_tiers(db_session, dry_run=False)
    assert wet.would_change
    assert db_session.query(ContentObject).filter_by(
        sha256=old.sha256).one().storage_tier == "warm"
    assert db_session.query(ContentObject).filter_by(
        sha256=older.sha256).one().storage_tier == "cold"
    assert db_session.query(ContentObject).filter_by(
        sha256=young.sha256).one().storage_tier == "hot"


def test_retention_sweep_is_dry_run_by_default_and_archives_before_drop(db_session, tmp_path):
    ensure_default_policies(db_session)
    cas = ContentAddressedStore(db_session)
    ref = cas.put(TENANT, b"collector output", category="raw_collector_output")
    _backdate(db_session.query(ContentObject).filter_by(sha256=ref.sha256).one(), 200)
    db_session.flush()

    dry = retention_sweep(db_session)
    assert dry.dry_run and dry.would_change
    assert cas.get(TENANT, ref.sha256) == b"collector output"  # untouched

    wet = retention_sweep(db_session, dry_run=False, archive_dir=str(tmp_path))
    assert wet.actions[0].action == "archive"
    with pytest.raises(ContentGoneError):
        cas.get(TENANT, ref.sha256)
    # Metadata tombstone survives; the archive holds verified bytes.
    row = db_session.query(ContentObject).filter_by(sha256=ref.sha256).one()
    assert row.body_dropped_at is not None
    archive = (tmp_path / TENANT / f"{ref.sha256}.ndjson").read_bytes()
    assert b"collector output" in archive


def test_gc_removes_only_unreferenced_objects_and_respects_grace(db_session):
    cas = ContentAddressedStore(db_session)
    keep = cas.put(TENANT, b"referenced")
    drop = cas.put(TENANT, b"orphan")
    orphan = db_session.query(ContentObject).filter_by(sha256=drop.sha256).one()
    orphan.ref_count = 0
    _backdate(orphan, 2)
    db_session.flush()

    dry = gc_unreferenced(db_session)
    assert dry.dry_run and len(dry.actions) == 1
    assert db_session.query(ContentObject).filter_by(sha256=drop.sha256).count() == 1

    gc_unreferenced(db_session, dry_run=False)
    assert db_session.query(ContentObject).filter_by(sha256=drop.sha256).count() == 0
    assert db_session.query(ContentObject).filter_by(sha256=keep.sha256).count() == 1
    assert cas.get(TENANT, keep.sha256) == b"referenced"


# ---------------------------------------------------------------- monitoring + restore

def test_monitoring_reports_savings_and_alerts_before_full(db_session):
    from db.models.storage_policy import StorageQuota
    ensure_default_policies(db_session)
    cas = ContentAddressedStore(db_session)
    cas.put(TENANT, json.dumps({"pad": "y" * 4000}).encode())
    db_session.add(StorageQuota(tenant_id=TENANT, scope="tenant",
                                max_bytes=1000, max_objects=0))
    db_session.flush()
    report = usage_report(db_session, TENANT)
    assert report.object_count == 1
    assert report.stored_bytes < report.plain_bytes  # compression saved space
    assert report.compression_saved_bytes > 0
    alerts = space_alerts(db_session, tenant_id=TENANT, warn_pct=0.1)
    assert any(a.kind == "quota_near_full" for a in alerts)
    assert all(a.level in ("warning", "critical") for a in alerts)


def test_restore_testing_proves_recovery_and_records_itself(db_session):
    cas = ContentAddressedStore(db_session)
    ref = cas.put(TENANT, b"archived evidence")
    record = verify_restorable(db_session, tenant_id=TENANT, object_sha256=ref.sha256)
    assert record.ok is True
    assert record.bytes_verified == len(b"archived evidence")
    db_session.flush()
    from db.models.storage_policy import RestoreTestRecord
    assert db_session.query(RestoreTestRecord).filter_by(ok=True).count() == 1

    # A corrupted body fails the restore test HONESTLY — recorded, not hidden.
    from db.models.content_object import ContentObjectBody
    body = db_session.query(ContentObjectBody).filter_by(object_sha256=ref.sha256).one()
    body.ciphertext = b"garbage"
    db_session.flush()
    bad = verify_restorable(db_session, tenant_id=TENANT, object_sha256=ref.sha256)
    assert bad.ok is False
    assert bad.detail

    results = run_restore_test(db_session, tenant_id=TENANT)
    assert results  # sampled verification runs and records
