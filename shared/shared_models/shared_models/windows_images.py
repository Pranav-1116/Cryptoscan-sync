"""Windows candidate image metadata; separate union member preserves old defaults."""

import hashlib
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict


def process_resource(path):
    match = re.fullmatch(r"windows-process://([1-9][0-9]{0,9})/created/([1-9][0-9]{0,19})/modules", path)
    if not match or int(match[1]) > 0xFFFFFFFF or int(match[2]) > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Exact local PID/creation FILETIME resource required")
    return int(match[1]), match[2]


def image_path(path):
    if not re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f\x7f]+", path):
        raise ValueError("Only literal local drive image paths supported")
    parts = path[3:].split("\\")
    for part in parts:
        if (
            not part
            or part in {".", ".."}
            or part.endswith((" ", "."))
            or re.search(r'[?*"<>|]', part)
            or ":" in part
            or "/" in part
            or re.fullmatch(r"(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)
        ):
            raise ValueError("Ambiguous, remote or device image path")
    return path


class WindowsImageFact(Strict):
    kind: Literal["WINDOWS_PROCESS_IMAGE", "WINDOWS_MODULE"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["WINDOWS_IMAGE_METADATA"] = "WINDOWS_IMAGE_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["WINDOWS_PROCESS_TOOLHELP"] = "WINDOWS_PROCESS_TOOLHELP"
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pid: int = Field(ge=1, le=0xFFFFFFFF)
    creation_filetime: str = Field(pattern=r"^[1-9][0-9]{0,19}$")
    image_path: str = Field(min_length=4, max_length=1024)
    module_name: str | None = Field(default=None, min_length=1, max_length=255)
    identity_key: str = Field(min_length=1, max_length=160)
    capture_basis: Literal["REPEATED_MATCHING_METADATA_NOT_INVOCATION"] = "REPEATED_MATCHING_METADATA_NOT_INVOCATION"

    @model_validator(mode="after")
    def consistent(self):
        image_path(self.image_path)
        if int(self.creation_filetime) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("FILETIME outside unsigned 64-bit range")
        key = f"pid:{self.pid}:created:{self.creation_filetime}"
        if self.kind == "WINDOWS_MODULE":
            if (
                not self.module_name
                or self.module_name != self.image_path.rsplit("\\", 1)[-1]
                or len(self.image_path) >= 259
            ):
                raise ValueError("Module name/path mismatch or possible fixed-buffer truncation")
            key += ":path-sha256:" + hashlib.sha256(self.image_path.encode()).hexdigest()
        elif self.module_name is not None:
            raise ValueError("Process image is not a module-name assertion")
        if self.identity_key != key:
            raise ValueError("Process incarnation/image metadata identity mismatch")
        return self


def metadata_bytes(pid, creation, process_image, modules):
    """Deterministic selected metadata, not target image/file bytes."""
    return json.dumps(
        {"pid": pid, "creation_filetime": creation, "process_image": process_image, "modules": sorted(modules)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def validate_images(item, facts):
    pid, creation = process_resource(item.path)
    if not facts:
        return
    processes = [f for f in facts if f.kind == "WINDOWS_PROCESS_IMAGE"]
    modules = [f for f in facts if f.kind == "WINDOWS_MODULE"]
    if (
        len(processes) != 1
        or not 1 <= len(modules) <= 256
        or len(facts) != len(modules) + 1
        or len({f.image_path.casefold() for f in modules}) != len(modules)
        or any((f.pid, f.creation_filetime) != (pid, creation) for f in facts)
    ):
        raise ValueError("Exact process incarnation and bounded unique module evidence required")

    raw = metadata_bytes(pid, creation, processes[0].image_path, [(f.module_name, f.image_path) for f in modules])
    commitment = hashlib.sha256(raw).hexdigest()
    if any(f.interface_sha256 != commitment for f in facts):
        raise ValueError("Selected Windows metadata commitment mismatch")
