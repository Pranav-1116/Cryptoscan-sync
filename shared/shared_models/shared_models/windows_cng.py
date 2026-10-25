"""CNG registration metadata, never implementation capability or crypto use."""

import hashlib
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

PROVIDER = "Microsoft Primitive Provider"
INTERFACES = {
    "cipher": 1,
    "hash": 2,
    "asymmetric-encryption": 3,
    "secret-agreement": 4,
    "signature": 5,
    "rng": 6,
    "key-derivation": 7,
}


def registration_resource(path):
    match = re.fullmatch(
        r"windows-cng://local/microsoft-primitive/(cipher|hash|asymmetric-encryption|secret-agreement|signature|rng|key-derivation)-registration",
        path,
    )
    if not match:
        raise ValueError("Exact supported local CNG registration resource required")
    return match[1]


def registration_bytes(interface, flags, functions):
    return json.dumps(
        {
            "provider": PROVIDER,
            "mode": "USER",
            "registration_interface": interface,
            "registration_flags": flags,
            "registered_functions": sorted(functions),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class WindowsCngFact(Strict):
    kind: Literal["WINDOWS_CNG_REGISTRATION"] = "WINDOWS_CNG_REGISTRATION"
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["PROVIDER_REGISTRATION_METADATA"] = "PROVIDER_REGISTRATION_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["WINDOWS_CNG_REGISTRATION_QUERY"] = "WINDOWS_CNG_REGISTRATION_QUERY"
    provider_name: Literal["Microsoft Primitive Provider"] = PROVIDER
    registration_mode: Literal["USER"] = "USER"
    registration_interface: Literal[
        "cipher", "hash", "asymmetric-encryption", "secret-agreement", "signature", "rng", "key-derivation"
    ]
    registration_flags: int = Field(ge=0, le=0xFFFFFFFF)
    registered_functions: list[str] = Field(min_length=1, max_length=64)
    identity_key: str = Field(min_length=1, max_length=120)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_basis: Literal["REGISTERED_NOT_OPENED_OR_INVOKED"] = "REGISTERED_NOT_OPENED_OR_INVOKED"

    @model_validator(mode="after")
    def consistent(self):
        names = self.registered_functions
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}", name) for name in names):
            raise ValueError("Unsupported registration function label")
        if names != sorted(names) or len({n.casefold() for n in names}) != len(names):
            raise ValueError("Canonical unique registration function labels required")
        if self.identity_key != f"microsoft-primitive:user:{self.registration_interface}":
            raise ValueError("CNG registration identity mismatch")
        if (
            self.interface_sha256
            != hashlib.sha256(
                registration_bytes(self.registration_interface, self.registration_flags, names)
            ).hexdigest()
        ):
            raise ValueError("CNG selected metadata commitment mismatch")
        return self


def validate_registration(item, facts):
    selected = registration_resource(item.path)
    if facts and (len(facts) != 1 or facts[0].registration_interface != selected):
        raise ValueError("CNG registration outside exact approved interface")


def unsupported_expected_value(key, value):
    """Only bounded canonical registration labels / TCP metadata rows extend scalars."""
    if key == "listeners" and isinstance(value, list):
        from shared_models.windows_listeners import validate_expected_listeners

        return not validate_expected_listeners(value)
    if key == "registered_functions" and isinstance(value, list):
        return not (
            1 <= len(value) <= 64
            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}", v) for v in value)
            and value == sorted(value)
            and len({v.casefold() for v in value}) == len(value)
        )
    return isinstance(value, (dict, list))
