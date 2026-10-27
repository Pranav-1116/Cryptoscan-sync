"""Scan a JAR/ZIP for cryptographic API strings without full decompilation."""

from __future__ import annotations

import zipfile
from pathlib import Path

from scanner.models.raw_finding import CryptoInfo, FindingMetadata, RawFinding, SourceLocation

STRINGS = (
    b"Cipher.getInstance",
    b"MessageDigest.getInstance",
    b"KeyGenerator.getInstance",
    b"Mac.getInstance",
    b"Signature.getInstance",
    b"SecretKeySpec",
    b"AES/ECB",
    b"AES/CBC",
    b"DES/",
    b"DESede",
    b"MD5",
    b"SHA-1",
    b"SHA1",
    b"RSA/ECB",
)


def scan_jar(jar_path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    path = Path(jar_path)
    findings: list[RawFinding] = []
    if not path.is_file():
        return findings
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return findings
    root = Path(repo_root) if repo_root else path.parent
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    with archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            try:
                blob = archive.read(name)
            except Exception:
                continue
            hits = [token.decode("ascii") for token in STRINGS if token in blob]
            if not hits:
                continue
            findings.append(
                RawFinding(
                    scanner_id="static-jar-string-scanner-v0.1",
                    source=SourceLocation(
                        type="BINARY",
                        language="JAVA",
                        file_path=f"{rel}!{name}",
                        line_number=0,
                        code_snippet=", ".join(hits[:6]),
                    ),
                    crypto=CryptoInfo(
                        api_type="UNKNOWN",
                        algorithm=_guess_algorithm(hits),
                        raw_transformation=hits[0],
                    ),
                    metadata=FindingMetadata(
                        confidence="LOW",
                        confidence_reason="string-match-in-jar",
                        library="unknown-jar",
                    ),
                )
            )
    return findings


def _guess_algorithm(hits: list[str]) -> str | None:
    joined = " ".join(hits).upper()
    for name in ("AES", "DESEDE", "3DES", "DES", "RSA", "MD5", "SHA-256", "SHA-1", "SHA1"):
        if name in joined:
            return "3DES" if name in {"DESEDE", "3DES"} else ("SHA-1" if name == "SHA1" else name)
    return None
