"""Hardcoded cryptographic material detection in container filesystems.

The finding schema has carried ``metadata.is_hardcoded_key`` since the
beginning — always ``False``, because nothing ever looked.  This module
looks: PEM/OpenSSH/PUTTY private keys, JWTs, and AWS-style access keys in
configuration-shaped files.

Precision beats recall here — a secret scanner that cries wolf is ignored:

* only text-ish files under 2 MB are read, and only files whose *names* look
  like config/source/env/keys (``.env``, ``.pem``, ``.key``, ``.json``,
  ``.yaml``, ``.toml``, ``.ini``, ``.conf``, ``.txt``, ``.js``, ``.py`` ...)
* every hit records file path + line number + a redacted preview (first 12
  chars of the secret, then ``…``) — never the full secret in a report that
  gets stored and shipped around
* JWTs must have three dot-separated base64url segments, the first of which
  decodes to JSON with an ``alg`` field; AWS keys must match the strict
  ``AKIA[0-9A-Z]{16}`` access-key-id shape (secret keys are unreadable noise
  without the id shape, and guessing breeds false positives)
* findings carry ``is_hardcoded_key: True`` and honest confidence: HIGH for
  key material, MEDIUM for tokens
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Iterable

MAX_SECRET_FILE_BYTES = 2 * 1024 * 1024
_TEXT_SUFFIXES = {
    ".env", ".pem", ".key", ".pub", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".config", ".txt", ".js", ".ts", ".py", ".rb", ".go",
    ".php", ".sh", ".xml", ".properties", ".cs", ".java", "",
}
# files whose bare names scream configuration
_NAME_HINTS = {
    "credentials", "secret", "secrets", "token", "tokens", "id_rsa",
    "id_ed25519", "identity", "private", ".env", ".htpasswd", ".netrc",
    "dpkg-status", "installed",
}

_PEM_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_PUTTY_PPK = re.compile(r"PuTTY-User-KeyFile-\d")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
_AWS_ACCESS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "__pycache__", ".mypy_cache",
    "proc", "sys", "dev", "run",
}


def _looks_like_config(path: Path) -> bool:
    name = path.name.lower()
    if name in _NAME_HINTS or any(hint in name for hint in _NAME_HINTS):
        return True
    return path.suffix.lower() in _TEXT_SUFFIXES


def _redact(secret: str) -> str:
    return f"{secret[:12]}…({len(secret)} chars)" if len(secret) > 12 else f"{secret[:3]}…"


def _jwt_has_alg_header(token: str) -> bool:
    try:
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==="))
    except Exception:  # noqa: BLE001 — malformed token is not a finding
        return False
    return isinstance(header, dict) and "alg" in header


def scan_text_for_secrets(text: str, *, rel_path: str = "") -> list[dict[str, Any]]:
    """Pure scanner over one file's text content (unit-testable)."""
    findings: list[dict[str, Any]] = []

    def add(kind: str, confidence: str, line_no: int, preview: str, detail: str) -> None:
        findings.append(
            {
                "type": "HARDCODED_SECRET",
                "kind": kind,
                "path": rel_path,
                "line_number": line_no,
                "preview": preview,
                "detail": detail,
                "confidence": confidence,
            }
        )

    for line_no, line in enumerate(text.splitlines(), start=1):
        if _PEM_KEY.search(line):
            add("pem-private-key", "HIGH", line_no, line.strip()[:40], "PEM private key header in plaintext file")
        if _PUTTY_PPK.search(line):
            add("putty-private-key", "HIGH", line_no, line.strip()[:40], "PuTTY PPK key header in plaintext file")
        for match in _JWT.finditer(line):
            token = match.group(0)
            if _jwt_has_alg_header(token):
                add("jwt", "MEDIUM", line_no, _redact(token), "hardcoded JWT (verified alg header)")
        for match in _AWS_ACCESS_KEY.finditer(line):
            add("aws-access-key-id", "MEDIUM", line_no, _redact(match.group(1)), "AWS access key id pattern")
    return findings


def scan_filesystem_for_secrets(root: Path) -> list[dict[str, Any]]:
    """Walk a rootfs and return hardcoded-secret findings (redacted)."""
    secrets: list[dict[str, Any]] = []
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_SECRET_FILE_BYTES:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in blob[:4096]:
            continue  # binary content — secrets scanners read text
        text = blob.decode("utf-8", "replace")
        rel = str(path.relative_to(root))
        secrets.extend(scan_text_for_secrets(text, rel_path=rel))
    return secrets


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not _looks_like_config(path):
            continue
        yield path


def secret_findings(secrets: list[dict[str, Any]], *, scanner_id: str = "container-scanner-v1.0") -> list[dict[str, Any]]:
    """Convert raw secret hits into the canonical container finding shape."""
    import uuid

    out: list[dict[str, Any]] = []
    for secret in secrets:
        out.append(
            {
                "finding_id": str(uuid.uuid4()),
                "scanner_id": scanner_id,
                "scanner_version": "1.0.0",
                "source": {
                    "type": "CONTAINER_SECRET",
                    "language": "UNKNOWN",
                    "file_path": secret["path"],
                    "line_number": secret["line_number"],
                    "class_name": secret["kind"],
                },
                "crypto": {
                    "api_type": "HARDCODED_KEY",
                    "algorithm": "UNKNOWN",
                    "purpose": "KEY_MATERIAL",
                },
                "metadata": {
                    "confidence": secret["confidence"],
                    "confidence_reason": secret["detail"],
                    "library": secret["kind"],
                    "is_hardcoded_key": True,
                    "preview": secret["preview"],
                },
            }
        )
    return out
