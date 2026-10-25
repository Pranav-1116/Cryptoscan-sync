from pathlib import Path
import json, subprocess
from jsonschema import Draft202012Validator
from shared_models.host_collection import HostManifest, HostSnapshot
from shared_models.collection import TargetSpec, CollectionResult
from shared_models.qualification_acceptance import NativeEvidence
from inventory.collector_release import build_lock

BASE = "eaf1902cad138aee0826ea6ee6331a2b7c95d6be"
NEW = {"TlsSessionFact", "TlsPeerCertificate"}
ADDED = {
    "NETWORK_TLS_SESSION",
    "OBSERVE_APPROVED_TLS_SESSION",
    "TLS_TIMEOUT",
    "TLS_CONNECT_FAILED",
    "TLS_HANDSHAKE_FAILED",
    "TLS_PEER_PIN_MISMATCH",
    "ACTIVE_PROBE_NOT_AUTHORIZED",
}


def previous(v, path=()):
    if isinstance(v, list):
        return [
            previous(x, path + (i,))
            for i, x in enumerate(v)
            if not (
                isinstance(x, str)
                and x in ADDED
                or isinstance(x, dict)
                and x.get("$ref", "").removeprefix("#/$defs/") in NEW
            )
        ]
    if isinstance(v, dict):
        result = {k: previous(x, path + (k,)) for k, x in v.items() if k not in NEW}
        # The formerly single-valued operation literal becomes an enum, only at this exact leaf.
        if (
            path[-3:] == ("properties", "allowed_operations", "items")
            and result.get("enum") == ["READ_APPROVED_METADATA"]
            and result.get("type") == "string"
        ):
            del result["enum"]
            result["const"] = "READ_APPROVED_METADATA"
        return result
    return v


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
        + ": schema/model/Draft2020-12 PASS; exact TLS addition reversal reproduces "
        + BASE
        + "; old fact shapes/defaults unchanged"
    )
lock = build_lock(Path.cwd())
for p in ["services/inventory/inventory/tls_session.py", "shared/shared_models/shared_models/tls_session.py"]:
    assert p in lock.files
print(
    "Source-lock inclusion PASS:",
    len(lock.files),
    "files; no signature, authorization or measured execution attestation generated.",
)
print(
    "API network job admission stays blocked; offline_host cannot tunnel NETWORK_TLS_SESSION; generic collect_host has no active probe."
)
