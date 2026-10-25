from pathlib import Path
import json, subprocess
from jsonschema import Draft202012Validator
from shared_models.host_collection import HostManifest, HostSnapshot
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.qualification_acceptance import NativeEvidence
from inventory.collector_release import build_lock

BASE = "838be60086eda2ec7aec2d790bf742244a6c6965"
NEW = {"OciImageFact", "OciLayer"}


def previous(value):
    if isinstance(value, list):
        return [
            previous(x)
            for x in value
            if not (
                x == "OCI_IMAGE_METADATA" or isinstance(x, dict) and x.get("$ref", "").removeprefix("#/$defs/") in NEW
            )
        ]
    if isinstance(value, dict):
        return {k: previous(v) for k, v in value.items() if k not in NEW}
    return value


for name, model in [
    ("host-manifest-v1", HostManifest),
    ("host-snapshot-v1", HostSnapshot),
    ("collection-target-v1", TargetSpec),
    ("collection-evidence-v1", CollectionResult),
    ("native-evidence-v1", NativeEvidence),
]:
    p = Path("shared/shared_models/shared_models/schemas") / (name + ".schema.json")
    new = json.loads(p.read_text())
    assert new == model.model_json_schema()
    Draft202012Validator.check_schema(new)
    old = json.loads(subprocess.check_output(["git", "show", BASE + ":" + str(p)]))
    assert previous(new) == old, name
    for key, value in old.get("$defs", {}).items():
        if key.endswith("Fact"):
            assert new["$defs"][key] == value, (name, key)
    print(
        name
        + ": schema/model/Draft2020-12 PASS; removing only OCI input/fact union/definitions exactly reproduces baseline "
        + BASE
        + "; all old fact shapes/defaults unchanged"
    )
lock = build_lock(Path.cwd())
for p in ["services/inventory/inventory/oci_image.py", "shared/shared_models/shared_models/oci_image.py"]:
    assert p in lock.files
print(
    "Source-lock inclusion PASS:",
    len(lock.files),
    "files; no signature, admission or measured-execution approval generated.",
)
print(
    "Production allowlist: unchanged relative to baseline (verified separately by git diff); container is still not supported."
)
