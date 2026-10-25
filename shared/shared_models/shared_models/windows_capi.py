"""Legacy default-provider selection metadata, not provider/key use or capability."""

import hashlib
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

PROVIDER_TYPES = {"rsa-full": 1, "rsa-signature": 2, "dss": 3, "dss-dh": 13, "rsa-aes": 24}


def provider_resource(path):
    match = re.fullmatch(
        r"windows-capi://local/current-user/(rsa-full|rsa-signature|dss|dss-dh|rsa-aes)/default-provider", path
    )
    if not match:
        raise ValueError("Exact supported current-user default-provider resource required")
    return match[1]


def provider_bytes(provider_type, provider_name):
    return json.dumps(
        {"provider_type": provider_type, "provider_name": provider_name, "context": "CURRENT_USER"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class WindowsCapiFact(Strict):
    kind: Literal["WINDOWS_CAPI_DEFAULT_PROVIDER"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["DEFAULT_PROVIDER_SELECTION_METADATA"] = "DEFAULT_PROVIDER_SELECTION_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["WINDOWS_CAPI_DEFAULT_PROVIDER_QUERY"] = "WINDOWS_CAPI_DEFAULT_PROVIDER_QUERY"
    provider_context: Literal["CURRENT_USER"] = "CURRENT_USER"
    provider_type: Literal[1, 2, 3, 13, 24]
    provider_name: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,254}$")
    identity_key: str = Field(max_length=100)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_basis: Literal["DEFAULT_SELECTION_NOT_OPENED_OR_INVOKED"] = "DEFAULT_SELECTION_NOT_OPENED_OR_INVOKED"

    @model_validator(mode="after")
    def consistent(self):
        if self.provider_name != self.provider_name.strip():
            raise ValueError("Unsupported provider label")
        if self.identity_key != f"windows-capi:current-user:{self.provider_type}:default-provider":
            raise ValueError("CAPI selection identity mismatch")
        if self.interface_sha256 != hashlib.sha256(provider_bytes(self.provider_type, self.provider_name)).hexdigest():
            raise ValueError("CAPI selection commitment mismatch")
        return self


def validate_provider(item, facts):
    selected = PROVIDER_TYPES[provider_resource(item.path)]
    if facts and (len(facts) != 1 or facts[0].provider_type != selected):
        raise ValueError("CAPI provider type outside approved scope")
