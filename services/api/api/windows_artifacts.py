"""Windows cryptographic artefacts — parsers for what an operator exports from a host.

The Windows candidate itself runs on the Windows host. What the control plane can do
without one is read the exports a host already produced, in the formats Windows
actually writes them:

* ``reg export "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"``
  — the Schannel protocol policy (which TLS versions a server enables, which are
  disabled by default);
* ``Get-TlsCipherSuite | ConvertTo-Json`` (or ``Export-Csv``) — the cipher suites the
  host offers, from which the algorithms are derived out of the IANA suite name;
* ``Get-ChildItem Cert:\\LocalMachine\\My | ConvertTo-Json`` — the machine certificate
  store: subject, issuer, thumbprint, validity, key algorithm.

What that establishes, stated once: **configuration**. The policy says TLS 1.2 is
enabled; it does not say a single connection used it. An exported certificate is a
certificate that exists in a store, not one that was presented in a handshake. The
collector labels every fact ``CONFIGURED`` and the console shows it that way.

Nothing here executes anything, opens a socket, or reads a binary format: an export
that cannot be parsed is reported as refused with its reason, never skipped silently.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "cryptoscan.windows-artifacts/1"

#: registry value names the Schannel policy cares about
_POLICY_VALUES = ("enabled", "disabledbydefault")
_PROTOCOLS_KEY = re.compile(r"\\SCHANNEL\\Protocols\\([^\\\]]+)", re.IGNORECASE)

#: IANA suite name token → the algorithm name a CBOM reader expects
_TOKEN_ALGORITHMS: tuple[tuple[str, str], ...] = (
    ("CHACHA20_POLY1305", "CHACHA20-POLY1305"),
    ("AES_256_GCM", "AES-256-GCM"),
    ("AES_128_GCM", "AES-128-GCM"),
    ("AES_256_CBC", "AES-256-CBC"),
    ("AES_128_CBC", "AES-128-CBC"),
    ("AES_256_CCM", "AES-256-CCM"),
    ("AES_128_CCM", "AES-128-CCM"),
    ("3DES_EDE_CBC", "3DES-EDE-CBC"),
    ("SHA384", "SHA-384"),
    ("SHA256", "SHA-256"),
    ("SHA512", "SHA-512"),
    ("ECDHE", "ECDHE"),
    ("DHE", "DHE"),
    ("ECDSA", "ECDSA"),
    ("RSA", "RSA"),
)


@dataclass
class ArtifactResult:
    """One parsed file and what it turned out to be."""

    path: str
    format: str | None
    parsed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "error": self.error,
            "records": len(self.parsed.get("records") or []),
        }


def iana_suite_algorithms(suite: str) -> list[dict[str, str]]:
    """Derive the algorithms a TLS suite name states, with their role.

    A suite name is authoritative for the suite — ``TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384``
    really does mean ECDHE key agreement, AES-256-GCM record protection and SHA-384
    for the handshake MAC. It says nothing about which of them a connection used.

    Tokens are consumed longest-first so ``ECDHE`` is not also read as ``DHE``.
    """
    name = str(suite or "").strip().upper()
    if not name:
        return []
    if "_WITH_" in name:
        key_exchange, body = name.split("_WITH_", 1)
    else:
        key_exchange, body = "", name
    tokens = sorted(_TOKEN_ALGORITHMS, key=lambda item: len(item[0]), reverse=True)
    out: list[dict[str, str]] = []
    taken: set[str] = set()
    for part, side in ((key_exchange, "key_exchange"), (body, "record")):
        working = part
        for token, algorithm in tokens:
            if token not in working or algorithm in taken:
                continue
            is_kex = algorithm in {"ECDHE", "DHE", "ECDSA", "RSA"}
            if (side == "key_exchange") != is_kex:
                continue
            role = (
                "key_exchange"
                if is_kex
                else ("handshake" if algorithm.startswith("SHA") else "record_protection")
            )
            out.append({"algorithm": algorithm, "role": role})
            taken.add(algorithm)
            working = working.replace(token, "_")
    return out


def _dword(raw: str) -> int | None:
    text = str(raw or "").strip().strip('"')
    if text.lower().startswith("dword:"):
        try:
            return int(text.split(":", 1)[1], 16)
        except ValueError:
            return None
    return None


def parse_schannel_registry(text: str) -> dict[str, Any]:
    """Protocol policy from a ``reg export`` of the SCHANNEL tree.

    Windows exports a key as ``[HKEY...]`` followed by its values. A protocol block
    inherits its own ``Enabled``/``DisabledByDefault`` values; the per-role
    sub-keys (``Client``/``Server``) repeat them. Those are kept separately because
    a server enabling TLS 1.0 and a client enabling it are different facts.
    """
    records: list[dict[str, Any]] = []
    current: str | None = None
    scope: str | None = None
    values: dict[str, int] = {}

    def flush() -> None:
        if current is None or not values:
            return
        records.append({
            "protocol": current,
            "scope": scope or "global",
            "enabled": bool(values.get("enabled")) if "enabled" in values else None,
            "disabled_by_default": (
                bool(values.get("disabledbydefault")) if "disabledbydefault" in values else None
            ),
        })

    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            flush()
            values = {}
            key = stripped.strip("[]")
            match = _PROTOCOLS_KEY.search(key)
            if match:
                current = match.group(1).strip()
                scope = "global"
                if re.search(r"\\Client$", key, re.IGNORECASE):
                    scope = "client"
                elif re.search(r"\\Server$", key, re.IGNORECASE):
                    scope = "server"
            else:
                current, scope = None, None
            continue
        if current is None or "=" not in stripped:
            continue
        raw_name, _, raw_value = stripped.partition("=")
        name = raw_name.strip().strip('"').lower()
        if name in _POLICY_VALUES:
            parsed = _dword(raw_value)
            if parsed is not None:
                values[name] = parsed
    flush()
    records.sort(key=lambda row: (row["protocol"].lower(), row["scope"]))
    return {"format": "schannel-registry", "records": records}


def parse_cipher_suites(text: str) -> dict[str, Any]:
    """Cipher suites from ``Get-TlsCipherSuite`` as JSON or CSV.

    JSON is tried first (``ConvertTo-Json``); CSV is read when the text has a
    ``Name`` header. Every suite is expanded into the algorithms its name states, so
    the CBOM gets a capability inventory rather than a list of opaque strings.
    """
    body = str(text or "").strip()
    if not body:
        return {"format": "cipher-suites", "records": []}
    rows: list[dict[str, Any]] = []
    if body[:1] in "[{":
        try:
            loaded = json.loads(body)
        except json.JSONDecodeError:
            loaded = None
        if loaded is not None:
            items = loaded if isinstance(loaded, list) else [loaded]
            for item in items:
                if isinstance(item, dict):
                    rows.append(item)
            return {"format": "cipher-suites-json", "records": _suite_records(rows)}
    reader = csv.DictReader(io.StringIO(body))
    if reader.fieldnames and any(name.strip().lower() == "name" for name in reader.fieldnames):
        rows = [dict(row) for row in reader]
        return {"format": "cipher-suites-csv", "records": _suite_records(rows)}
    return {"format": "cipher-suites", "records": [], "error": "unrecognised cipher-suite export"}


def _suite_records(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        name = str(row.get("Name") or row.get("name") or "").strip()
        if not name:
            continue
        out.append({
            "suite": name,
            "protocol": row.get("Protocol") or row.get("protocol"),
            "algorithms": iana_suite_algorithms(name),
        })
    out.sort(key=lambda item: item["suite"])
    return out


def parse_certificate_store(text: str) -> dict[str, Any]:
    """Machine certificate store from ``Get-ChildItem Cert:\\ | ConvertTo-Json``."""
    body = str(text or "").strip()
    if not body:
        return {"format": "certificate-store", "records": []}
    try:
        loaded = json.loads(body)
    except json.JSONDecodeError as exc:
        return {"format": "certificate-store", "records": [], "error": f"invalid JSON: {exc}"}
    items = loaded if isinstance(loaded, list) else [loaded]
    records: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        thumbprint = str(item.get("Thumbprint") or item.get("thumbprint") or "").strip()
        if not thumbprint:
            continue
        records.append({
            "subject": item.get("Subject"),
            "issuer": item.get("Issuer"),
            "thumbprint": thumbprint.upper(),
            "not_before": item.get("NotBefore"),
            "not_after": item.get("NotAfter"),
            "has_private_key": item.get("HasPrivateKey"),
            "public_key_algorithm": item.get("PublicKeyAlgorithm") or item.get("SignatureAlgorithm"),
            "dns_names": item.get("DnsNameList") or [],
        })
    records.sort(key=lambda row: row["thumbprint"])
    return {"format": "certificate-store", "records": records}


def parse_artifact(path: str | Path) -> ArtifactResult:
    """Parse one exported artefact, choosing the format from what is inside it."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ArtifactResult(path=str(file_path), format=None, error=f"unreadable: {exc}")
    lowered = text.lower()
    if "windows registry editor" in lowered or "_schannel\\" in lowered or "\\\\schannel" in lowered:
        return ArtifactResult(path=str(file_path), format="schannel-registry",
                              parsed=parse_schannel_registry(text))
    if "tls_" in lowered or "cipher" in lowered:
        parsed = parse_cipher_suites(text)
        if not parsed.get("error"):
            return ArtifactResult(path=str(file_path), format=parsed["format"], parsed=parsed)
    if "thumbprint" in lowered:
        parsed = parse_certificate_store(text)
        if not parsed.get("error"):
            return ArtifactResult(path=str(file_path), format=parsed["format"], parsed=parsed)
    return ArtifactResult(path=str(file_path), format=None,
                          error="unrecognised artefact: expected a SCHANNEL registry export, "
                                "Get-TlsCipherSuite JSON/CSV, or a certificate-store JSON export")


def parse_artifacts(paths: Iterable[str | Path]) -> dict[str, Any]:
    """Every requested artefact, with the ones that could not be read listed."""
    results = [parse_artifact(path) for path in paths]
    return {
        "schema": SCHEMA,
        "files": [result.as_dict() for result in results],
        "protocols": [row for result in results for row in result.parsed.get("records") or []
                      if result.format == "schannel-registry"],
        "suites": [row for result in results for row in result.parsed.get("records") or []
                   if str(result.format or "").startswith("cipher-suites")],
        "certificates": [row for result in results for row in result.parsed.get("records") or []
                         if result.format == "certificate-store"],
        "refused": [result.as_dict() for result in results if result.error],
        "note": (
            "these are configuration facts read from a host's own exports: an enabled protocol "
            "and an offered suite are not a handshake, and a certificate in a store is not one "
            "that was presented"
        ),
    }


__all__ = [
    "ArtifactResult",
    "SCHEMA",
    "iana_suite_algorithms",
    "parse_artifact",
    "parse_artifacts",
    "parse_certificate_store",
    "parse_cipher_suites",
    "parse_schannel_registry",
]
