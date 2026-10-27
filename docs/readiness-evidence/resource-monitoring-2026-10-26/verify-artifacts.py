"""Offline schema/unsigned integrity verification of the actual sandbox resource witness."""

import json
from pathlib import Path
from jsonschema import Draft202012Validator
from shared_models.host_collection import digest
from shared_models.resource_monitoring import (
    ResourceAuthorization,
    ResourceCapture,
    ResourceScope,
    TrafficProposal,
    resource_report,
)
from api.assurance import store

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(__file__).resolve().parent


def row_hash(row):
    value = {
        "scope": store.scope_key(row["tenant_id"]),
        "kind": row["kind"],
        "subject_id": row["subject_id"],
        "revision": row["revision"],
        "payload": row["payload"],
        "created_by": row["created_by"],
        "previous_sha256": row["previous_sha256"],
    }
    assert store.digest(value) == row["payload_sha256"]


def main():
    for name, model in (
        ("scope", ResourceScope),
        ("authorization", ResourceAuthorization),
        ("capture", ResourceCapture),
        ("traffic-proposal", TrafficProposal),
    ):
        path = ROOT / f"shared/shared_models/shared_models/schemas/resource-{name}-v1.schema.json"
        actual = json.loads(path.read_text())
        expected = model.model_json_schema()
        expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        assert actual == expected
        Draft202012Validator.check_schema(actual)
    print("Four schemas: Draft 2020-12 validation and exact typed-model equality PASS")
    witness = OUTPUT / "public-witness"
    capture = ResourceCapture.model_validate_json((witness / "resource-capture.json").read_bytes())
    record = json.loads((witness / "resource-record.json").read_text())
    plans = json.loads((witness / "resource-plan.json").read_text())["history"]
    assert len(plans) == 2
    previous = None
    for index, row in enumerate(plans, 1):
        row_hash(row)
        assert row["revision"] == index and row["previous_sha256"] == previous
        previous = row["payload_sha256"]
    approval = plans[1]
    auth = ResourceAuthorization(
        plan_id=approval["subject_id"],
        plan_record_sha256=approval["payload_sha256"],
        scope_sha256=approval["payload"]["scope_sha256"],
        nonce=approval["payload"]["nonce"],
        scope=approval["payload"]["scope"],
    )
    assert auth == capture.authorization and approval["payload"]["state"] == "APPROVED"
    row_hash(record)
    assert record["revision"] == 1 and record["previous_sha256"] is None
    assert record["payload"]["capture"] == capture.model_dump(mode="json")
    assert record["payload"]["report"] == resource_report(capture)
    assert record["payload"]["report"]["capture_sha256"] == digest(capture)
    assert record["subject_id"] == store.subject(
        "resource-capture/v1", store.scope_key(record["tenant_id"]), auth.plan_id, capture.capture_id
    )
    assert all(n.status == "MEASURED" for n in capture.network) and all(s.status == "MEASURED" for s in capture.storage)
    assert not capture.configuration_changed and not capture.packet_payload_captured
    assert not record["payload"]["report"]["runtime_control_applied"]
    print(
        "Actual ordinary-user sandbox capture: original approval chain, typed source, stored row and full report recomputation PASS"
    )
    print(
        "Unsigned sandbox integrity only; not independent host/customer truth, traffic enforcement or production qualification"
    )


if __name__ == "__main__":
    main()
