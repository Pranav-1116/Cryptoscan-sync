from pathlib import Path
import json, subprocess
from jsonschema import Draft202012Validator
from shared_models.host_collection import HostManifest, HostSnapshot
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.qualification_acceptance import NativeEvidence
from shared_models.operation_evidence import OperationApproval, OperationEvidence
from shared_models.software_truth import SoftwareTruthPlan
from inventory.collector_release import build_lock

BASE = "7b06710118fa5efd14bad223e543176544df15bd"
NEW = {"TlsHybridFact"}
ADDED = {"NETWORK_TLS13_HYBRID", "TLS_REQUIRED_GROUP_NOT_SELECTED"}


def previous(v):
    if isinstance(v, list):
        return [
            previous(x)
            for x in v
            if not (
                isinstance(x, str)
                and x in ADDED
                or isinstance(x, dict)
                and x.get("$ref", "").removeprefix("#/$defs/") in NEW
            )
        ]
    if isinstance(v, dict):
        return {k: previous(x) for k, x in v.items() if k not in NEW}
    return v


for name, model in [
    ("host-manifest-v1", HostManifest),
    ("host-snapshot-v1", HostSnapshot),
    ("collection-target-v1", TargetSpec),
    ("collection-evidence-v1", CollectionResult),
    ("native-evidence-v1", NativeEvidence),
    ("operation-approval-v1", OperationApproval),
    ("operation-evidence-v1", OperationEvidence),
    ("software-truth-plan-v1", SoftwareTruthPlan),
]:
    p = Path("shared/shared_models/shared_models/schemas") / (name + ".schema.json")
    new = json.loads(p.read_text())
    assert new == model.model_json_schema()
    Draft202012Validator.check_schema(new)
    if name not in {"operation-approval-v1", "operation-evidence-v1", "software-truth-plan-v1"}:
        old = json.loads(subprocess.check_output(["git", "show", BASE + ":" + str(p)]))
        assert previous(new) == old, name
        for key, value in old.get("$defs", {}).items():
            if key.endswith("Fact"):
                assert new["$defs"][key] == value, (name, key)
        print(
            name
            + ": model/Draft PASS; exact hybrid kind/reason/fact reversal reproduces "
            + BASE
            + "; old facts unchanged"
        )
    else:
        print(name + ": new bounded public model/Draft PASS; no private keys/producer-supplied roots in evidence")
lock = build_lock(Path.cwd())
for p in [
    "services/inventory/inventory/tls_hybrid.py",
    "shared/shared_models/shared_models/tls_hybrid.py",
    "shared/shared_models/shared_models/operation_evidence.py",
    "shared/shared_models/shared_models/software_truth.py",
]:
    assert p in lock.files
print(
    "Source-lock inclusion PASS:",
    len(lock.files),
    "files. Hash/source inclusion is not authenticity or qualified execution.",
)
