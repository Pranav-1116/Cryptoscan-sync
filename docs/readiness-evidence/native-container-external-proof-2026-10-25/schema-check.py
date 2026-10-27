"""Six public schema/model checks plus unchanged historical schema bytes."""

from pathlib import Path
import json
import subprocess
from jsonschema import Draft202012Validator
from shared_models.operation_evidence_v2 import OperationApprovalV2, OperationEvidenceV2
from shared_models.hsm_operation_request import HsmOperationRequest
from shared_models.software_estate import SoftwareEstatePlan, SoftwareEstatePacket, EstateAssetRegister
from inventory.collector_release import build_lock

BASE = "a434e5eb3415c4506563a833d105b7b9f1c7e0b5"
folder = Path("shared/shared_models/shared_models/schemas")
for name, model in [
    ("operation-approval-v2", OperationApprovalV2),
    ("operation-evidence-v2", OperationEvidenceV2),
    ("hsm-operation-request-v1", HsmOperationRequest),
    ("software-estate-plan-v1", SoftwareEstatePlan),
    ("software-estate-packet-v1", SoftwareEstatePacket),
    ("estate-asset-register-v1", EstateAssetRegister),
]:
    schema = json.loads((folder / (name + ".schema.json")).read_bytes())
    assert schema == model.model_json_schema()
    Draft202012Validator.check_schema(schema)
    print(name, ": model / Draft2020-12 PASS")
old = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", BASE, str(folder)], text=True).splitlines()
for name in old:
    assert Path(name).read_bytes() == subprocess.check_output(["git", "show", BASE + ":" + name]), name
print("All", len(old), "existing schemas including operation-v1 and old facts are byte-for-byte unchanged.")
lock = build_lock(Path.cwd())
for name in ["operation_evidence_v2.py", "hsm_operation_request.py", "software_estate.py"]:
    assert "shared/shared_models/shared_models/" + name in lock.files
print(
    "Source lock:",
    len(lock.files),
    "files; hashes do not attest external producers, SDK dependencies, customer applications or physical HSMs.",
)
