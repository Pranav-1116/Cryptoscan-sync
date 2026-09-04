"""Import crypto facts ops teams already have on disk.

- ``openssl s_client`` transcripts (protocol + cipher + verification)
- tap session JSONL written by runtime.agent.tls_tap
- ``openssl cipher`` style names (ECDHE-RSA-AES256-GCM-SHA384) decomposed
  into key-exchange / cipher / MAC components with registry verdicts
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:  # platform registry provides rich verdicts; the agent also runs
    # standalone on a laptop without shared_models on PYTHONPATH — fall back
    # to a minimal stdlib-only stand-in that exposes the attributes we read.
    from shared_models.algorithm_registry import parse_algorithm
except ImportError:  # pragma: no cover - exercised only outside the platform
    from types import SimpleNamespace

    def parse_algorithm(name: str) -> Any:
        return SimpleNamespace(
            canonical=name or "TLS",
            components=[],
            key_size=None,
            status=None,
            quantum_impact=None,
            to_dict=lambda: {"algorithm": name, "key_size": None, "status": None},
        )


def parse_sclient_output(text: str) -> dict[str, Any]:
    """Parse `openssl s_client -connect host:port` output."""
    out: dict[str, Any] = {"cert_verified": None, "tls_version": None, "cipher_suite": None}
    for line in text.splitlines():
        stripped = line.strip()
        # modern: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
        m = re.match(r"^New,\s*(TLSv[\d.]+|SSLv[\d.]+),\s*Cipher is (\S+)", stripped)
        if m:
            out["tls_version"], out["cipher_suite"] = m.group(1), m.group(2)
            continue
        m = re.match(r"^New,\s+\((?P<ver>[^)]+)\),\s+Cipher is (?P<cipher>\S+)", stripped)
        if m:
            out["tls_version"], out["cipher_suite"] = m.group("ver"), m.group("cipher")
            continue
        # "Protocol  : TLSv1.2"
        m = re.match(r"^Protocol\s*:\s*(\S+)", stripped)
        if m:
            out["tls_version"] = m.group(1)
            continue
        # "Cipher    : ECDHE-RSA-AES256-GCM-SHA384"
        m = re.match(r"^Cipher\s*:\s*(\S+)", stripped)
        if m and not out["cipher_suite"]:
            out["cipher_suite"] = m.group(1)
            continue
        if stripped.startswith("Verify return code:"):
            out["cert_verified"] = "ok" in stripped.lower()
    return out


# --------------------------------------------------------------------------- #
# OpenSSL cipher-name decomposition: ECDHE-RSA-AES256-GCM-SHA384
# --------------------------------------------------------------------------- #

_KX_TOKENS = ("ECDHE-RSA", "ECDHE-ECDSA", "DHE-RSA", "DHE-DSS", "ECDH-RSA", "ECDH-ECDSA", "RSA", "PSK", "SRP", "GOST01")
_PQC_KX = frozenset({"XYBER", "MLKEM", "HYBRID"})


def parse_openssl_cipher(name: str) -> dict[str, Any]:
    """Decompose an OpenSSL cipher name into components + verdict."""
    raw = (name or "").strip()
    parts = [p for p in raw.split("-") if p]
    kx: str | None = None
    for token in _KX_TOKENS + tuple(sorted(_PQC_KX)):
        if raw.upper().replace("_", "-").startswith(token.upper().replace("_", "-")):
            kx = token
            break
    if kx:
        remainder = raw[len(kx):].lstrip("-")
    else:
        remainder = raw

    # bulk cipher + optional mode + optional MAC
    cipher = remainder
    mac = None
    m = re.match(r"^(AES(?:128|256)?|CAMELLIA128|CAMELLIA256|ARIA128|ARIA256|CHACHA20|3DES|DES|RC4|SEED|NULL)(?:-(GCM|CCM|CBC|CTR|CFB))?(?:-(SHA256|SHA384|SHA1|SHA|MD5))?$", remainder, re.IGNORECASE)
    if m:
        cipher = m.group(1).upper()
        mode = (m.group(2) or "").upper() or None
        mac = m.group(3).upper() if m.group(3) else None
        mac = {"SHA": "SHA-1"}.get(mac, mac)
    else:
        mode = m.group(2) if m else None
        tail = re.search(r"-(SHA256|SHA384|SHA1|SHA|MD5)$", remainder, re.IGNORECASE)
        if tail:
            mac = tail.group(1).upper()
            mac = {"SHA": "SHA-1"}.get(mac, mac)
            cipher = remainder[: tail.start()]
    cipher = {"DES-CBC3": "3DES", "DES-EDE3": "3DES", "DES-EDE": "3DES", "DES": "DES"}.get(cipher.upper(), cipher)
    if mode is None and mac and cipher.upper() not in {"CHACHA20", "RC4", "NULL"}:
        # OpenSSL shorthand "AES128-SHA" is the CBC form
        mode = "CBC"

    # canonical algorithm string for the registry
    registry_name = cipher
    if cipher.upper().startswith("AES") and mode in {"GCM", "CCM"}:
        size = re.search(r"(\d{3})", cipher)
        registry_name = f"AES-{size.group(1)}" if size else "AES"
    elif cipher.upper() == "CHACHA20":
        registry_name = "ChaCha20-Poly1305" if mac in {None, "SHA256"} else "ChaCha20"

    info = parse_algorithm(registry_name)
    components = []
    if kx:
        kx_info = parse_algorithm({"ECDHE-RSA": "ECDH", "ECDHE-ECDSA": "ECDH", "DHE-RSA": "DH", "DHE-DSS": "DH", "ECDH-RSA": "ECDH", "ECDH-ECDSA": "ECDH"}.get(kx, kx))
        entry = kx_info.to_dict()
        entry["role"] = "key_exchange"
        entry["name"] = kx
        components.append(entry)
    if mac:
        mac_info = parse_algorithm(mac.replace("SHA256", "SHA-256").replace("SHA384", "SHA-384"))
        entry = mac_info.to_dict()
        entry["role"] = "mac"
        components.append(entry)

    return {
        "raw": raw,
        "key_exchange": kx,
        "bulk_cipher": cipher.upper(),
        "mode": mode,
        "mac": mac,
        "algorithm": info.canonical,
        "key_size": info.key_size,
        "status": info.status,
        "quantum_impact": info.quantum_impact,
        "components": components,
    }


# --------------------------------------------------------------------------- #
# JSONL session import (tap output, possibly from another host)
# --------------------------------------------------------------------------- #


def parse_tap_jsonl(path: str | Path) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                sessions.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return sessions
