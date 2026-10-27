"""Bounded OS TCP table metadata. PIDs are not process incarnations or TLS proof."""

import hashlib
import ipaddress
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

MAX_LISTENERS = 256


def listener_resource(path):
    match = re.fullmatch(r"windows-sockets://local/(ipv4|ipv6)/tcp-listeners", path)
    if not match:
        raise ValueError("Exact local TCP-listener address-family resource required")
    return match[1]


class WindowsListener(Strict):
    address: str = Field(min_length=2, max_length=45)
    port: int = Field(ge=1, le=65535)
    owning_pid: int = Field(ge=0, le=0xFFFFFFFF)
    scope_id: int = Field(ge=0, le=0xFFFFFFFF)


def listener_bytes(family, listeners):
    return json.dumps(
        {"address_family": family, "listeners": [r.model_dump(mode="json") for r in listeners]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def row_key(row):
    return row.address, row.scope_id, row.port, row.owning_pid


class WindowsListenerFact(Strict):
    kind: Literal["WINDOWS_TCP_LISTENER_TABLE"]
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["OS_TCP_LISTENER_TABLE_METADATA"] = "OS_TCP_LISTENER_TABLE_METADATA"
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    interface: Literal["WINDOWS_IP_HELPER_TCP_TABLE"] = "WINDOWS_IP_HELPER_TCP_TABLE"
    address_family: Literal["ipv4", "ipv6"]
    listener_count: int = Field(ge=0, le=MAX_LISTENERS)
    listeners: list[WindowsListener] = Field(max_length=MAX_LISTENERS)
    identity_key: str = Field(max_length=100)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_basis: Literal["REPEATED_TABLE_NOT_PROCESS_IDENTITY_OR_TLS"] = "REPEATED_TABLE_NOT_PROCESS_IDENTITY_OR_TLS"
    process_identity_verified: Literal[False] = False
    tls_observed: Literal[False] = False
    asset_absence_proven: Literal[False] = False

    @model_validator(mode="after")
    def consistent(self):
        keys = [row_key(r) for r in self.listeners]
        if self.listener_count != len(keys) or keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("Canonical unique TCP rows/count required")
        for row in self.listeners:
            address = ipaddress.ip_address(row.address)
            if (
                "%" in row.address
                or str(address) != row.address
                or address.version != (4 if self.address_family == "ipv4" else 6)
                or self.address_family == "ipv4"
                and row.scope_id
            ):
                raise ValueError("Listener address/family/scope mismatch")
        if self.identity_key != f"windows-tcp-table:{self.address_family}:owner-pid-listener":
            raise ValueError("TCP table metadata identity mismatch")
        if self.interface_sha256 != hashlib.sha256(listener_bytes(self.address_family, self.listeners)).hexdigest():
            raise ValueError("TCP selected metadata commitment mismatch")
        return self


def validate_listeners(item, facts):
    family = listener_resource(item.path)
    if facts and (len(facts) != 1 or facts[0].address_family != family):
        raise ValueError("TCP table outside approved address family")


def validate_expected_listeners(value):
    """Validate independent flat TCP row assertions; no executable/nested assertions."""
    if len(value) > MAX_LISTENERS:
        return False
    try:
        rows = []
        for record in value:
            if not isinstance(record, dict) or set(record) != {"address", "port", "owning_pid", "scope_id"}:
                return False
            if type(record["address"]) is not str or any(
                type(record[k]) is not int for k in ("port", "owning_pid", "scope_id")
            ):
                return False
            row = WindowsListener.model_validate(record)
            address = ipaddress.ip_address(row.address)
            if "%" in row.address or str(address) != row.address or address.version == 4 and row.scope_id:
                return False
            rows.append(row)
        keys = [row_key(row) for row in rows]
        return keys == sorted(keys) and len(keys) == len(set(keys))
    except (TypeError, ValueError):
        return False
