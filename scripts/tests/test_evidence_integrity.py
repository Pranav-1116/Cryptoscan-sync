"""Evidence integrity: the chain's detection surface, and the twin's enforcement.

The twin finding here is the important one. Verification existed at ingest,
export, audit and rescan — but the twin projected evidence rows into the estate
snapshot without checking them, so a stored payload that no longer matched its
committed hash read as fact. `_evidence_integrity` closes that, and these tests
keep it closed: a tampered scan must make the twin say FAIL and name the scan,
and a clean scan must not be flagged.
"""

from __future__ import annotations

import json

import pytest

from scripts import evidence_integrity_drill as drill


# ------------------------------------------------------------------ fixture --- #
def test_the_fixture_is_a_valid_chain_to_begin_with():
    """Every attack below is meaningless if the control store is already broken."""
    from evidence.verification.stored_scan import verify_stored_scan

    store = drill.build_store()
    try:
        rows = (store.session.query(type(store.rows[0]))
                .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
        verdict = verify_stored_scan(store.scan, rows)
        assert verdict["result"] == "PASS", verdict
        assert len(rows) == drill.RECORDS
    finally:
        store.close()


def test_a_completed_scan_without_a_manifest_is_unverifiable_not_passed():
    from evidence.verification.stored_scan import verify_stored_scan

    store = drill.build_store(manifest=False)
    try:
        rows = (store.session.query(type(store.rows[0]))
                .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
        assert verify_stored_scan(store.scan, rows)["result"] == "UNVERIFIABLE"
    finally:
        store.close()


# ------------------------------------------------------------------ attacks --- #
def test_payload_tamper_is_caught_by_the_content_hash():
    """The attack that matters: the body changes, the stored hashes do not."""
    from evidence.verification.stored_scan import verify_stored_scan

    store = drill.build_store()
    try:
        spec = drill.attack_payload_tamper(store)
        spec["mutate"]()
        rows = (store.session.query(type(store.rows[0]))
                .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
        verdict = verify_stored_scan(store.scan, rows)
        assert verdict["result"] == "FAIL"
        assert not verdict["content_intact"]
        assert any("content hash mismatch" in error for error in verdict["errors"])
    finally:
        store.close()


def test_deleting_the_tail_is_caught_by_the_manifest_not_the_chain():
    """The prefix still recomputes, so only the anchor can notice."""
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.verification.stored_scan import verify_stored_scan

    store = drill.build_store()
    try:
        drill.attack_delete_tail(store)["mutate"]()
        rows = (store.session.query(type(store.rows[0]))
                .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
        # The remaining chain is internally consistent …
        assert ChainHasher.verify_chain([row.content_hash for row in rows],
                                        [row.chain_hash for row in rows], store.scan.id)
        # … and the scan still refuses it, because the manifest no longer matches.
        verdict = verify_stored_scan(store.scan, rows)
        assert verdict["result"] == "FAIL"
        assert not verdict["manifest_intact"]
    finally:
        store.close()


def test_rewriting_the_manifest_is_the_documented_boundary():
    """Deleting a row and re-anchoring verifies PASS — this is why the row is
    graded UNDETECTABLE rather than counted as a detection."""
    from evidence.verification.stored_scan import verify_stored_scan

    store = drill.build_store()
    try:
        drill.attack_rebuild_manifest(store)["mutate"]()
        rows = (store.session.query(type(store.rows[0]))
                .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
        assert verify_stored_scan(store.scan, rows)["result"] == "PASS"
    finally:
        store.close()


# --------------------------------------------------------------- read paths --- #
def test_the_twin_refuses_tampered_evidence_and_names_the_scan():
    """The finding this drill was built for: twin corruption starts with evidence
    corruption, so the twin must check before projecting."""
    from api.routers.digital_twin import _evidence_integrity
    from db.models.evidence_record import EvidenceRecord

    store = drill.build_store()
    try:
        clean = _evidence_integrity(
            store.session,
            store.session.query(EvidenceRecord).filter_by(scan_id=store.scan.id).all(),
        )
        assert clean["result"] == "PASS" and clean["scans_passed"] == 1

        drill.attack_payload_tamper(store)["mutate"]()
        tampered = _evidence_integrity(
            store.session,
            store.session.query(EvidenceRecord).filter_by(scan_id=store.scan.id).all(),
        )
        assert tampered["result"] == "FAIL"
        assert tampered["scans_failed"] == 1
        assert tampered["failures"][0]["scan_id"] == store.scan.id
        assert tampered["failures"][0]["errors"]
    finally:
        store.close()


def test_the_twin_marks_evidence_it_could_not_verify_as_unverified():
    from api.routers.digital_twin import _evidence_integrity
    from db.models.evidence_record import EvidenceRecord

    store = drill.build_store(manifest=False)
    try:
        verdict = _evidence_integrity(
            store.session,
            store.session.query(EvidenceRecord).filter_by(scan_id=store.scan.id).all(),
        )
        assert verdict["result"] == "UNVERIFIED"
        assert verdict["scans_unverifiable"] == 1
        assert "absence of proof" in verdict["note"]
    finally:
        store.close()


def test_the_twin_verification_is_bounded_and_says_so(monkeypatch):
    from api.routers import digital_twin

    monkeypatch.setattr(digital_twin, "EVIDENCE_INTEGRITY_SCANS", 1)
    stores = [drill.build_store() for _ in range(2)]
    try:
        rows = []
        for store in stores:
            rows.extend(store.session.query(type(store.rows[0]))
                        .filter_by(scan_id=store.scan.id).all())
        # The verifier checks the first scan by id, so it has to be the one that
        # exists in the session it is queried from; the other one is deliberately
        # absent and must come back as unverifiable, not as a pass.
        primary = sorted(stores, key=lambda store: store.scan.id)[0]
        verdict = digital_twin._evidence_integrity(primary.session, rows)
        assert verdict["scans_total"] == 2
        assert verdict["scans_checked"] == 1
        assert verdict["truncated"] is True
        assert verdict["result"] == "PARTIAL"
    finally:
        for store in stores:
            store.close()


def test_the_scan_verify_route_rejects_a_tampered_scan():
    store = drill.build_store()
    try:
        drill.attack_payload_tamper(store)["mutate"]()
        verdict = drill.consume_scan_verify_route(store)
        assert verdict["result"] == "FAIL"
    finally:
        store.close()


# -------------------------------------------------------------------- report --- #
def test_the_committed_report_matches_the_tool():
    report = json.loads((drill.Path(__file__).resolve().parents[2] / "docs" /
                         "bank-environment" / "112-evidence-integrity.json").read_text())
    assert report["schema"] == drill.SCHEMA
    assert report["control_ok"] is True
    assert report["attacks_undetected"] == 0, "an attack went undetected — that is a finding"
    assert report["attacks_detected"] >= 8
    assert report["complete"] is True
    assert report["read_paths_enforcing"] == report["read_paths_total"] >= 3
    assert any("manifest" in limit and "unsigned" in limit for limit in report["limits"])


def test_the_report_names_the_boundary_rather_than_hiding_it():
    report = drill.measure()
    undetectable = [row for row in report["attacks"] if row["verdict"] == drill.UNDETECTABLE]
    assert undetectable, "the unsigned-anchor boundary must be reported, not omitted"
    assert "rebuild_manifest" in undetectable[0]["attack"]
    assert report["attacks_detected"] + report["attacks_undetectable_by_design"] == report["attacks_total"]


def test_render_md_marks_every_verdict():
    rendered = drill.render_md(drill.measure())
    assert "**DETECTED**" in rendered
    assert "**UNDETECTABLE**" in rendered
    assert "What this does not prove" in rendered


def test_cli_exit_code_reflects_detections(tmp_path):
    json_path = tmp_path / "integrity.json"
    md_path = tmp_path / "integrity.md"
    assert drill.main(["--json", str(json_path), "--md", str(md_path), "--min-detected", "8"]) == 0
    written = json.loads(json_path.read_text())
    assert written["attacks_detected"] >= 8
    assert "DETECTED" in md_path.read_text()


@pytest.mark.parametrize("attack", ["delete_middle", "reorder", "append_forged"])
def test_structural_attacks_are_detected(attack):
    store = drill.build_store()
    try:
        spec = dict(drill.ATTACKS_BY_NAME)[attack](store)
        spec["mutate"]()
        verdict = drill.consume_verifier(store)
        assert verdict["result"] == "FAIL", f"{attack} was accepted"
    finally:
        store.close()
