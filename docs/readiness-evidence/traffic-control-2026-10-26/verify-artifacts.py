"""Offline engineering integrity check, not authenticated source/custody or host approval."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from jsonschema import Draft202012Validator
from shared_models.host_collection import digest
from shared_models.linux_traffic_control import (
    PreflightSpec,
    TrafficPreflight,
    ValidationChange,
    DrillAuthorization,
    DrillResult,
    preflight_report,
)

HERE = Path(__file__).resolve().parent
models = {
    "preflight-spec": PreflightSpec,
    "preflight": TrafficPreflight,
    "change": ValidationChange,
    "drill-authorization": DrillAuthorization,
    "drill-result": DrillResult,
}
for name, model in models.items():
    path = ROOT / f"shared/shared_models/shared_models/schemas/linux-traffic-{name}-v1.schema.json"
    schema = json.loads(path.read_text())
    Draft202012Validator.check_schema(schema)
    assert {k: v for k, v in schema.items() if k not in ("$schema", "$id")} == model.model_json_schema()


def load(name, model, schema_name):
    raw = (HERE / name).read_bytes()
    value = model.model_validate_json(raw)
    schema = json.loads(
        (ROOT / f"shared/shared_models/shared_models/schemas/linux-traffic-{schema_name}-v1.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(json.loads(raw))
    return value


spec = load("native-spec.json", PreflightSpec, "preflight-spec")
capture = load("native-preflight.json", TrafficPreflight, "preflight")
auth = load("synthetic-local-drill-packet.json", DrillAuthorization, "drill-authorization")
result = load("native-drill-result.json", DrillResult, "drill-result")
assert capture.spec == spec and auth.preflight_sha256 == digest(capture)
assert result.authorization_sha256 == digest(auth)
assert json.loads((HERE / "native-preflight-report.json").read_text()) == preflight_report(capture)
assert result.verdict == "REFUSED_OR_FAILED" and result.child_namespace_distinct
assert result.parent_namespace_unchanged and not result.qdisc_applied_in_child and not result.rollback_verified_in_child
assert (HERE / "parent-qdisc-before.json").read_bytes() == (HERE / "parent-qdisc-after.json").read_bytes()
assert "EXISTING_ROOT_POLICY_OR_UNKNOWN" in preflight_report(capture)["host_change_blockers"]
manifest = json.loads((HERE / "evidence-manifest.json").read_text())
for record in manifest["files"]:
    path = ROOT / record["path"]
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"], record["path"]
print(
    f"Verified five schemas, source/result/report commitments and {len(manifest['files'])} file hashes. Native TBF BLOCKED; production NOT qualified."
)
