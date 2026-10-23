"""Authenticated trace/current-review contracts; synthetic SQLite, not site qualification."""
from copy import deepcopy
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from api.assurance import relationships
from db.models.assurance import AssuranceRevision
from db.models.evidence_record import EvidenceRecord
from test_assurance_workflows import (
    P, admin, approval, assured as assured, banks as banks, done, new_scan,
)
from test_package_identity_integrity import document, relationship, stored
from test_relationship_lifecycle_api import state
from test_software_supply_chain_api import attach, deploy, register

TRACE = P + "/applications/system-a/trace"
CANARY = "storage-corruption-canary"


def history(db):
    table = AssuranceRevision.__table__
    return deepcopy([dict(row) for row in db.execute(select(table).order_by(table.c.id)).mappings()])


def corrupt(db, identifier, selected_revision, **values):
    # Deliberately bypass the unchanged append-only ORM guard to model storage
    # corruption. This is NOT an authenticated API write or a demonstrated exploit.
    table = AssuranceRevision.__table__
    result = db.execute(update(table).where(
        table.c.subject_id == identifier, table.c.revision == selected_revision).values(**values))
    assert result.rowcount == 1
    db.commit()
    db.expire_all()


@pytest.fixture()
def trace_case(assured):
    clients, db, _ = assured
    client = clients["bank_a"]
    doc, purl = document("cyclonedx", "1.2.3")
    artifact = register(client)
    binding = attach(client, artifact, stored(client, doc))
    deployment = done(deploy(client, artifact, system_id="system-a"))
    scan = new_scan(db, algorithms=("MD5", "SHA1"))
    evidence, supporting = db.query(EvidenceRecord).filter_by(scan_id=scan.id).order_by(EvidenceRecord.chain_position).all()
    body = relationship(binding, purl, evidence)
    body["evidence_ids"].append(supporting.id)
    proposed = done(client.post(P + "/relationships", json=body))
    return {"clients": clients, "db": db, "client": client, "binding": binding,
            "deployment": deployment, "evidence": evidence, "supporting": supporting,
            "proposed": proposed, "body": body}


def review(case):
    identifier = case["proposed"]["subject_id"]
    return done(admin(case["clients"]).post(P + f"/relationships/{identifier}/approve", json=approval()), 200)


def assert_integrity_refusal(case):
    before = history(case["db"])
    response = case["client"].get(TRACE)
    assert response.status_code == 409, response.text
    assert "Assurance revision integrity mismatch" in response.text
    assert CANARY not in response.text
    assert history(case["db"]) == before  # Never silently repair or rewrite history.


@pytest.mark.parametrize("field", ["payload", "payload_sha256", "created_by", "previous_sha256", "revision", "subject_id"])
def test_trace_refuses_corrupt_reviewed_revision_envelope(trace_case, field):
    case = trace_case
    reviewed = review(case)
    values = {
        "payload": {**reviewed["payload"], "trust": CANARY, "evidence_ref": CANARY},
        "payload_sha256": "0" * 64, "created_by": CANARY,
        "previous_sha256": "0" * 64, "revision": 3, "subject_id": CANARY,
    }
    corrupt(case["db"], reviewed["subject_id"], 2, **{field: values[field]})
    assert_integrity_refusal(case)


@pytest.mark.parametrize("field", ["state", "evidence_ref"])
def test_trace_refuses_corruption_in_loaded_predecessor_not_only_latest(trace_case, field):
    case = trace_case
    reviewed = review(case)
    proposed = case["proposed"]
    corrupt(case["db"], proposed["subject_id"], 1,
            payload={**proposed["payload"], field: CANARY})
    # The latest envelope is still intact; the loaded predecessor is not.
    latest = case["db"].query(AssuranceRevision).filter_by(subject_id=reviewed["subject_id"], revision=2).one()
    from api.assurance import store
    store.verify(latest)
    assert_integrity_refusal(case)


def test_trace_does_not_treat_storage_forged_review_state_as_approval(trace_case):
    case = trace_case
    proposed = case["proposed"]
    corrupt(case["db"], proposed["subject_id"], 1,
            payload={**proposed["payload"], "state": "REVIEWED", "trust": CANARY})
    assert_integrity_refusal(case)


WINDOWS = [("observed_at", -1, False), ("observed_at", 0, True),
           ("expires_at", -1, True), ("expires_at", 0, False)]


@pytest.mark.parametrize("anchor,offset,current", WINDOWS)
def test_current_trace_rechecks_both_freshness_boundaries(trace_case, monkeypatch, anchor, offset, current):
    case = trace_case
    review(case)
    before = history(case["db"])
    clock = datetime.fromisoformat(case["body"][anchor]) + timedelta(seconds=offset)
    # Scope the synthetic clock to the relationship service, not auth/session time.
    monkeypatch.setattr(relationships, "utcnow", lambda: clock)
    result = done(case["client"].get(TRACE), 200)
    assert len(result["paths"]) == int(current)
    if not current:
        assert result["unresolved"][0]["reason"] == "NO_CURRENT_REVIEWED_CRYPTO_EDGE"
    assert result["complete"] is result["runtime_verified"] is False
    assert history(case["db"]) == before


@pytest.mark.parametrize("anchor,offset,current", WINDOWS)
def test_review_rechecks_both_freshness_boundaries(trace_case, monkeypatch, anchor, offset, current):
    case = trace_case
    before = history(case["db"])
    clock = datetime.fromisoformat(case["body"][anchor]) + timedelta(seconds=offset)
    monkeypatch.setattr(relationships, "utcnow", lambda: clock)
    identifier = case["proposed"]["subject_id"]
    result = admin(case["clients"]).post(P + f"/relationships/{identifier}/approve", json=approval())
    assert result.status_code == (200 if current else 409), result.text
    if not current:
        assert history(case["db"]) == before
    else:
        assert result.json()["revision"] == 2


@pytest.mark.parametrize("target", ["deployment", "sbom_binding", "evidence", "supporting"])
def test_current_trace_rechecks_upstream_lifecycle_without_rewriting_assertion(trace_case, target):
    case = trace_case
    review(case)
    before = history(case["db"])
    if target in {"deployment", "sbom_binding"}:
        row = case["deployment" if target == "deployment" else "binding"]
        done(state(case["client"], target, row, "STALE"), 200)
    else:
        # Normal evidence tombstone fixture; NOT corruption of assurance history.
        from db.models.base import utcnow
        case[target].deleted_at = utcnow()
        case["db"].commit()
    result = done(case["client"].get(TRACE), 200)
    assert result["paths"] == [] and result["unresolved"]
    assert history(case["db"]) == before


def test_intact_trace_preserves_assertion_limits_and_exact_estate_privacy(trace_case):
    case = trace_case
    reviewed = review(case)
    before = history(case["db"])
    result = done(case["client"].get(TRACE), 200)
    path, = result["paths"]
    assert path["relationship_id"] == reviewed["subject_id"]
    assert path["relationship_sha256"] == reviewed["payload_sha256"]
    assert path["trust"] == "CUSTOMER_REVIEWED_ASSERTION_NOT_INDEPENDENT_RUNTIME_PROOF"
    assert path["deployed_verified"] is path["invocation_verified"] is False
    assert result["complete"] is result["runtime_verified"] is False
    corrupt(case["db"], reviewed["subject_id"], 2, payload_sha256="0" * 64)
    for client in (case["clients"]["bank_b"], case["clients"]["platform_admin"]):
        response = client.get(TRACE)
        assert response.status_code == 404, response.text
        assert "integrity mismatch" not in response.text and CANARY not in response.text
    # An unrelated estate's own application does not consume A's corrupt history.
    other = done(case["clients"]["bank_b"].get(P + "/applications/system-b/trace"), 200)
    assert other["paths"] == []
    response = admin(case["clients"]).get(TRACE)
    assert response.status_code == 409, response.text
    after = history(case["db"])
    assert len(after) == len(before) == 2
    assert_integrity_refusal(case)
