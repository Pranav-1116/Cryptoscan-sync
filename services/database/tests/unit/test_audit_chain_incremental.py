"""Incremental audit-chain verification (anchor + suffix) — security tests.

The hash chain is append-only and unbounded (5+ year regulatory retention).
A plain walk is O(chain) per call; the anchor verifies the same tamper
classes in O(new rows), and additionally detects tail truncation, which a
plain walk of the surviving prefix cannot detect at all.
"""
from __future__ import annotations

import datetime as dt

from db.models.user import AuditLog
from db.repositories.user_repository import (
    GENESIS_HASH,
    audit_entry_hash,
    verify_audit_chain,
    verify_audit_chain_incremental,
)
from db.repositories.settings_repository import SettingsRepository


def _stamp(session, n: int, start: int = 1) -> int:
    """Append n chained audit rows; return the new top sequence."""
    prev = GENESIS_HASH
    base = start - 1
    if n:
        last = session.query(AuditLog).filter(AuditLog.chain_sequence != None).order_by(AuditLog.chain_sequence.desc()).first()  # noqa: E711
        if last is not None:
            prev = last.entry_hash
            base = last.chain_sequence
    top = base
    for i in range(n):
        top += 1
        row = AuditLog(
            actor=f"user{i % 7}", action="test.action", target_type="t",
            target_id=f"t{top}", detail=str(top), ip_address="10.0.0.1",
            outcome="SUCCESS",
            created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=top),
            chain_sequence=top, previous_hash=prev,
        )
        row.entry_hash = audit_entry_hash(row, previous_hash=prev)
        session.add(row)
        prev = row.entry_hash
    session.commit()
    return top


def _head(session, seq: int) -> AuditLog:
    return session.query(AuditLog).filter(AuditLog.chain_sequence == seq).one()


# ---------------------------------------------------------------- cold start
def test_cold_start_does_full_walk_and_anchors(db_session):
    _stamp(db_session, 5)
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "OK"
    assert res["mode"] == "full"
    assert res["checked"] == 5 and res["entry_count"] == 5
    assert res["chain_head"] and res["full_verified_at"]
    anchor = SettingsRepository(db_session).get("audit_chain_anchor")
    assert anchor and anchor["sequence"] == 5 and anchor["head"] == res["chain_head"]


# ---------------------------------------------------------- steady state: O(0)
def test_incremental_no_new_rows_is_zero_work(db_session):
    _stamp(db_session, 5)
    first = verify_audit_chain_incremental(db_session)
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "OK"
    assert res["mode"] == "incremental"
    assert res["checked"] == 0            # nothing new to verify
    assert res["entry_count"] == 5
    assert res["chain_head"] == first["chain_head"]
    # anchor did not move
    anchor = SettingsRepository(db_session).get("audit_chain_anchor")
    assert anchor["sequence"] == 5


def test_incremental_verifies_only_the_suffix(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    top = _stamp(db_session, 40)          # 40 new rows
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "OK"
    assert res["mode"] == "incremental"
    assert res["checked"] == 40           # only the new suffix
    assert res["entry_count"] == 45
    assert res["chain_head"] == _head(db_session, top).entry_hash


# ------------------------------------------------------------- tamper classes
def test_suffix_content_tamper_detected(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    _stamp(db_session, 3)
    victim = _head(db_session, 8)
    victim.action = "evil.action"          # edit after anchoring
    db_session.commit()
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "TAMPERED"
    assert res["mode"] == "incremental"
    assert res["break_at_sequence"] == 8


def test_suffix_reorder_detected(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    _stamp(db_session, 3)
    a, b = _head(db_session, 6), _head(db_session, 7)
    a.previous_hash, b.previous_hash = b.previous_hash, a.previous_hash
    a.entry_hash, b.entry_hash = b.entry_hash, a.entry_hash
    db_session.commit()
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "TAMPERED"
    assert res["break_at_sequence"] in (6, 7)


def test_tail_truncation_detected(db_session):
    """Deleting entries below the anchored head is undetectable by a plain
    walk of the surviving prefix — the anchor must catch it."""
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)   # anchor at 5
    _stamp(db_session, 3)                          # top 8
    verify_audit_chain_incremental(db_session)    # anchor advances to 8
    # a plain full walk of what remains would still say OK:
    for r in (_head(db_session, 7), _head(db_session, 8)):
        db_session.delete(r)
    db_session.commit()
    assert verify_audit_chain(db_session)["status"] == "OK"  # the blind spot
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "TAMPERED"
    assert "truncated" in res["reason"]


def test_pre_anchor_tamper_bounded_by_full_walk_window(db_session):
    """An edit strictly before the anchor head is outside the incremental
    window; the full walk (forced, or due via the 7-day budget) locates it.
    The report states the mode + full_verified_at so consumers know the
    freshness of the guarantee."""
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    victim = _head(db_session, 2)
    victim.target_id = "forged"            # edit an OLD (pre-anchor) row
    db_session.commit()
    # incremental pass: honest about what it checked
    inc = verify_audit_chain_incremental(db_session)
    assert inc["mode"] == "incremental"
    # full walk (forced) finds the break
    full = verify_audit_chain_incremental(db_session, force_full=True)
    assert full["status"] == "TAMPERED"
    assert full["mode"] == "full"
    assert full["break_at_sequence"] == 2


def test_anchor_row_content_edit_stored_hash_intact_detected(db_session):
    """The lazy-attacker case: edit the ANCHOR row's content but leave its
    stored entry_hash column (and every later row's link) untouched. A
    stored-hash-only anchor check would trust it forever — the anchor row's
    content must be re-hashed on every incremental pass."""
    _stamp(db_session, 5)
    first = verify_audit_chain_incremental(db_session)   # anchor at 5
    _stamp(db_session, 2)                                 # rows 6, 7 chain from H5
    verify_audit_chain_incremental(db_session)            # anchor advances to 7
    victim = _head(db_session, 7)        # the ANCHOR row itself
    victim.action = "forged.action"      # content edit; entry_hash column stays
    db_session.commit()
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "TAMPERED"
    assert res["break_at_sequence"] == 7
    assert first["chain_head"]           # anchor head was valid before the edit


def test_anchor_row_deletion_forces_full_fallback(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    victim = _head(db_session, 5)
    db_session.delete(victim)
    db_session.commit()
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "TAMPERED"


# ------------------------------------------------------------------ controls
def test_force_full_bypasses_anchor(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    res = verify_audit_chain_incremental(db_session, force_full=True)
    assert res["status"] == "OK" and res["mode"] == "full" and res["checked"] == 5


def test_stale_anchor_triggers_full_walk(db_session):
    _stamp(db_session, 5)
    verify_audit_chain_incremental(db_session)
    # age the anchor past the 7-day full-walk budget
    stale = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=8)
    SettingsRepository(db_session).set("audit_chain_anchor", {
        "sequence": 5,
        "head": _head(db_session, 5).entry_hash,
        "full_verified_at": stale.isoformat(),
    })
    db_session.commit()
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "OK" and res["mode"] == "full"


def test_chain_with_no_rows(db_session):
    res = verify_audit_chain_incremental(db_session)
    assert res["status"] == "OK" and res["checked"] == 0 and res["chain_head"] is None
    res = verify_audit_chain_incremental(db_session)  # idempotent on empty
    assert res["status"] == "OK"


# -------------------------------------------- attestation w/ pre-computed res
def test_build_attestation_uses_supplied_verification(db_session):
    from governance.audit_attest import build_attestation, verify_attestation

    _stamp(db_session, 5)
    base = verify_audit_chain_incremental(db_session)
    verification = {
        "status": "VERIFIED" if base["status"] == "OK" else "TAMPERED",
        "entries_checked": base["checked"],
        "chain_head": base.get("chain_head"),
        "mismatches": [], "sequence_gaps": [],
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": base.get("mode"),
        "entry_count": base.get("entry_count"),
        "full_verified_at": base.get("full_verified_at"),
    }
    report = build_attestation([], org="Acme", signer="auditor",
                               secret="s3cret", verification=verification)
    assert report["attestation"]["status"] == "VERIFIED"
    assert report["attestation"]["mode"] == "full"
    assert report["attestation"]["entry_count"] == 5
    assert verify_attestation(report, secret="s3cret") is True
    # wrong secret must fail
    assert verify_attestation(report, secret="wrong") is False
