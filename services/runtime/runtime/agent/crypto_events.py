"""Map agent observations onto the runtime crypto engine's event contract.

The platform engine (`spec 92`) accepts events, not raw agent output. This
module is the bridge for the two collectors this repository actually ships:

* the **LD_PRELOAD tracer** (`preload_trace.py`) — real `EVP_*` call counts,
  which is a Level 1 crypto-API observation;
* the **process scan** (`process_discovery.py`) — which libraries a process has
  mapped. That is *not* an operation, so it never becomes a crypto event; it is
  offered separately for scope selection.

Function names map to the engine's operation taxonomy. A function we do not
recognise becomes ``UNKNOWN`` rather than being guessed into ENCRYPT, and a
missing algorithm stays ``UNKNOWN``.
"""

from __future__ import annotations

import os
from typing import Any, Iterable

#: OpenSSL call → operation taxonomy (spec 92 §8)
FUNCTION_OPERATIONS: dict[str, str] = {
    "EVP_EncryptInit": "ENCRYPT",
    "EVP_EncryptInit_ex": "ENCRYPT",
    "EVP_EncryptInit_ex2": "ENCRYPT",
    "EVP_EncryptUpdate": "ENCRYPT",
    "EVP_EncryptFinal_ex": "ENCRYPT",
    "EVP_DecryptInit": "DECRYPT",
    "EVP_DecryptInit_ex": "DECRYPT",
    "EVP_DecryptInit_ex2": "DECRYPT",
    "EVP_DecryptUpdate": "DECRYPT",
    "EVP_DecryptFinal_ex": "DECRYPT",
    "EVP_DigestInit": "HASH",
    "EVP_DigestInit_ex": "HASH",
    "EVP_DigestInit_ex2": "HASH",
    "EVP_DigestSign": "SIGN",
    "EVP_DigestVerify": "VERIFY",
    "EVP_PKEY_sign": "SIGN",
    "EVP_PKEY_verify": "VERIFY",
    "EVP_PKEY_encrypt": "ENCRYPT",
    "EVP_PKEY_decrypt": "DECRYPT",
    "EVP_PKEY_derive": "KEY_AGREEMENT",
    "EVP_PKEY_keygen": "KEY_GENERATION",
    "HMAC_Init": "MAC",
    "HMAC_Init_ex": "MAC",
    "EVP_MAC_init": "MAC",
    "EVP_KDF_derive": "KEY_DERIVATION",
}


def operation_for_function(function: str | None) -> str:
    """Fold a traced function name onto the engine's operation taxonomy."""
    name = str(function or "").strip()
    if not name:
        return "UNKNOWN"
    direct = FUNCTION_OPERATIONS.get(name)
    if direct:
        return direct
    # EVP_EncryptUpdate-style names are covered above, but shims vary: match on
    # the verb, never on "it probably encrypts"
    lowered = name.lower()
    for verb, operation in (
        ("encryptinit", "ENCRYPT"),
        ("decryptinit", "DECRYPT"),
        ("digestinit", "HASH"),
        ("pkey_sign", "SIGN"),
        ("pkey_verify", "VERIFY"),
        ("pkey_derive", "KEY_AGREEMENT"),
        ("keygen", "KEY_GENERATION"),
    ):
        if verb in lowered:
            return operation
    return "UNKNOWN"


def observations_from_trace(
    trace_rows: Iterable[dict[str, Any]],
    *,
    host: str | None = None,
    application: str | None = None,
    source: str = "OPENSSL_TRACE",
    runtime_method: str = "CRYPTO_API_TRACE",
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Trace rows → engine observations (never inventing a parameter)."""
    hostname = host or os.uname().nodename if hasattr(os, "uname") else host
    observations: list[dict[str, Any]] = []
    for row in trace_rows:
        process = str(row.get("process_name") or row.get("process") or "unknown")
        function = str(row.get("function") or "") or None
        algorithm = row.get("algorithm")
        if algorithm in ("", "UNKNOWN"):
            algorithm = None
        observation: dict[str, Any] = {
            "source": source,
            "runtime_method": runtime_method,
            "host": hostname,
            "application": application or process,
            "process": process,
            "pid": row.get("pid"),
            "function": function,
            "operation": operation_for_function(function),
            "algorithm": algorithm,
            "observation_count": max(1, int(row.get("observation_count") or 1)),
            # metadata only: the tracer never records key bytes, IVs or plaintext
            "attributes": {"collector": "ld-preload-shim"},
        }
        if row.get("key_size") is not None:
            observation["key_size"] = row["key_size"]
        if row.get("mode"):
            observation["mode"] = row["mode"]
        extra = row.get("extra") or {}
        for field in ("hash", "padding", "curve", "crypto_provider"):
            if extra.get(field):
                observation[field] = extra[field]
        for field in ("tls_min_version", "tls_max_version"):
            if extra.get(field):
                observation.setdefault("attributes", {})[field] = extra[field]
        if observed_at:
            observation["timestamp"] = observed_at
        observations.append(observation)
    return observations


def scope_candidates(process_scan: dict[str, Any]) -> dict[str, Any]:
    """Suggest runtime scope hosts/processes from a process scan.

    A suggestion only: nothing is observed until an operator saves a scope.
    """
    processes: list[dict[str, Any]] = []
    for process in (process_scan or {}).get("processes") or []:
        libraries = [lib.get("library") for lib in process.get("libraries") or [] if lib.get("library")]
        processes.append(
            {
                "process": process.get("name") or process.get("comm"),
                "pid": process.get("pid"),
                "user": process.get("user"),
                "tls_libraries": libraries,
                "listening_ports": process.get("listening_ports") or [],
                "container": bool(process.get("container")),
                "suggested": True,
            }
        )
    return {
        "model": "cryptoscan.runtime-scope-candidates/1",
        "processes": processes,
        "note": (
            "candidates for an approved runtime scope — saving the scope is the operator's decision, "
            "and a candidate is never instrumented automatically"
        ),
    }
