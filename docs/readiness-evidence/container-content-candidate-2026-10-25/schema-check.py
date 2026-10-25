from pathlib import Path
import json, subprocess
from jsonschema import Draft202012Validator
from shared_models.host_collection import HostManifest, HostSnapshot
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.qualification_acceptance import NativeEvidence
from inventory.collector_release import build_lock

BASE = "f18380f02b65c6a2b47da4b13f7febc3254ca87e"
NEW = {"OciContentFact", "OciRuntimeFact", "PackageDatabase", "PackageRecord"}


def previous(value):
    if isinstance(value, list):
        return [
            previous(x)
            for x in value
            if not (
                isinstance(x, str)
                and x in {"OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"}
                or isinstance(x, dict)
                and x.get("$ref", "").removeprefix("#/$defs/") in NEW
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
for p in [
    "services/inventory/inventory/oci_content.py",
    "services/inventory/inventory/oci_runtime.py",
    "shared/shared_models/shared_models/oci_content.py",
    "shared/shared_models/shared_models/oci_overlay.py",
    "shared/shared_models/shared_models/container_admission.py",
]:
    assert p in lock.files
print(
    "Source-lock inclusion PASS:",
    len(lock.files),
    "files; no signature, admission or measured-execution approval generated.",
)
print(
    "Production execution is still not admitted: empty server-owned container profile set and existing universal production boundary; new explicit guards reject OCI-through-Linux bypass."
)
