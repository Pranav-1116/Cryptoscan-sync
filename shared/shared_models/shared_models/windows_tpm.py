"""Windows OS-reported TPM version metadata, not physical identity or attestation."""

import hashlib
import json
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

RESOURCE = "windows-tpm://local/device-info"


def device_resource(path):
    if path != RESOURCE:
        raise ValueError("Exact local OS-selected TPM device-info resource required")
    return path


def device_bytes(specification):
    return json.dumps(
        {"api_structure_version": 1, "tpm_specification": specification}, sort_keys=True, separators=(",", ":")
    ).encode()


class WindowsTpmFact(Strict):
    kind: Literal["WINDOWS_TPM_METADATA"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["OS_REPORTED_TPM_METADATA"] = "OS_REPORTED_TPM_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["WINDOWS_TBS_DEVICE_INFO"] = "WINDOWS_TBS_DEVICE_INFO"
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    identity_key: Literal["windows-tpm:local:device-info"] = "windows-tpm:local:device-info"
    hardware_type: Literal["TPM"] = "TPM"
    api_structure_version: Literal[1] = 1
    tpm_specification: Literal["1.2", "2.0"]
    capture_basis: Literal["OS_REPORTED_NOT_ATTESTED_OR_INVOKED"] = "OS_REPORTED_NOT_ATTESTED_OR_INVOKED"

    @model_validator(mode="after")
    def consistent(self):
        if self.interface_sha256 != hashlib.sha256(device_bytes(self.tpm_specification)).hexdigest():
            raise ValueError("TPM selected metadata commitment mismatch")
        return self


def validate_device(item, facts):
    device_resource(item.path)
    if facts and (len(facts) != 1 or facts[0].kind != "WINDOWS_TPM_METADATA"):
        raise ValueError("Exactly one OS-selected TPM metadata fact required")
