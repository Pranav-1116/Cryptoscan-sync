"""Verify public synthetic witness commitments and model/schema equivalence offline."""

import json
from pathlib import Path
from jsonschema import Draft202012Validator
from shared_models.collection import CollectionResult
from shared_models.collection_views import (
    CollectionSnapshot,
    DriftRequest,
    SnapshotRequest,
    compare_snapshots,
    snapshot_views,
)
from shared_models.host_collection import digest
from api.assurance import store

ROOT = Path(__file__).resolve().parents[3]
WITNESS = Path(__file__).resolve().parent / "public-witness"


def read(name):
    return json.loads((WITNESS / (name + ".json")).read_text())


def verify_row(row):
    material = {
        "scope": store.scope_key(row["tenant_id"]),
        "kind": row["kind"],
        "subject_id": row["subject_id"],
        "revision": row["revision"],
        "payload": row["payload"],
        "created_by": row["created_by"],
        "previous_sha256": row["previous_sha256"],
    }
    assert store.digest(material) == row["payload_sha256"]
    assert row["revision"] == 1 and row["previous_sha256"] is None


def main():
    schema_root = ROOT / "shared/shared_models/shared_models/schemas"
    for name, model in (
        ("collection-snapshot-v1", CollectionSnapshot),
        ("collection-snapshot-request-v1", SnapshotRequest),
        ("collection-drift-request-v1", DriftRequest),
    ):
        actual = json.loads((schema_root / (name + ".schema.json")).read_text())
        expected = model.model_json_schema()
        expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        assert actual == expected
        Draft202012Validator.check_schema(actual)
    print("Three Draft 2020-12 schemas: valid and exactly equal to typed models")
    snapshots, rows = [], []
    for prefix in ("baseline", "candidate"):
        row, source = read(prefix + "-snapshot"), read(prefix + "-source")
        verify_row(row)
        source_sha = source.pop("envelope_sha256")
        parsed = CollectionResult.model_validate(source)
        assert digest(parsed) == source_sha
        snapshot = CollectionSnapshot.model_validate(row["payload"]["snapshot"])
        Draft202012Validator(json.loads((schema_root / "collection-snapshot-v1.schema.json").read_text())).validate(
            snapshot.model_dump(mode="json")
        )
        assert row["payload"] == {"snapshot": snapshot.model_dump(mode="json"), **snapshot_views(snapshot)}
        assert snapshot.source_sha256 == source_sha and snapshot.job_id == parsed.job_id
        originals = {o.observation_id: o for o in parsed.observations}
        assert len(originals) == len(snapshot.observations)
        for obs in snapshot.observations:
            original = originals[obs.observation_id]
            assert obs.evidence_id == original.evidence_id and obs.identity_slot == original.identity_slot
            assert obs.fact_sha256 == original.fact_sha256 == digest(original.fact)
            assert obs.local_basis == original.fact.local_basis and obs.domains == original.contributes_to
        snapshots.append(snapshot)
        rows.append(row)
    event = read("metadata-drift")
    verify_row(event)
    value = event["payload"]
    assert value["baseline_snapshot_id"] == rows[0]["subject_id"]
    assert value["candidate_snapshot_id"] == rows[1]["subject_id"]
    assert value["baseline_record_sha256"] == rows[0]["payload_sha256"]
    assert value["candidate_record_sha256"] == rows[1]["payload_sha256"]
    assert value["report"] == compare_snapshots(*snapshots)
    assert len(value["report"]["changes"]) == 1
    assert value["report"]["changes"][0]["state"] == "UNRESOLVED_COLLECTION_GAP"
    assert not value["report"]["changes"][0]["asset_absence_proven"]
    print(
        "Five public synthetic HTTP artifacts: original envelopes, snapshot/view/graph hashes and drift recomputation PASS"
    )
    print("This is unsigned engineering integrity, not independent customer/physical/bank acceptance")


if __name__ == "__main__":
    main()
