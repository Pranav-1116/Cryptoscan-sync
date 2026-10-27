"""
Inventory PEM / certificate / PKCS#12 material next to source.

Does not require cryptography. Banner + optional stdlib/cryptography
parse for notAfter / key size. Findings join to source later via
file-stem matching (foo.pem ↔ foo.java / foo.py).
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-material-scanner"

MATERIAL_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".key"}

PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]+)-----END \1-----",
    re.MULTILINE,
)

BANNER_ALGO = {
    "RSA PRIVATE KEY": ("RSA", "KEY_STORAGE"),
    "RSA PUBLIC KEY": ("RSA", "KEY_STORAGE"),
    "EC PRIVATE KEY": ("ECDSA", "KEY_STORAGE"),
    "DSA PRIVATE KEY": ("DSA", "KEY_STORAGE"),
    "PRIVATE KEY": ("UNKNOWN", "KEY_STORAGE"),
    "ENCRYPTED PRIVATE KEY": ("UNKNOWN", "KEY_STORAGE"),
    "PUBLIC KEY": ("UNKNOWN", "KEY_STORAGE"),
    "CERTIFICATE": ("UNKNOWN", "CERTIFICATE"),
    "X509 CERTIFICATE": ("UNKNOWN", "CERTIFICATE"),
    "TRUSTED CERTIFICATE": ("UNKNOWN", "CERTIFICATE"),
}


def iter_material_files(root: Path) -> Iterator[Path]:
    excluded = DEFAULT_EXCLUDED_DIRS
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded or part.startswith(".") for part in path.parts):
            continue
        if path.suffix.lower() in MATERIAL_SUFFIXES:
            yield path


def _classify_banner(label: str) -> tuple[str, str]:
    return BANNER_ALGO.get(label.upper().strip(), ("UNKNOWN", "CERTIFICATE"))


def _try_parse_certificate(pem_text: str) -> dict:
    info: dict = {}
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

        cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"), default_backend())
        public = cert.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            info["algorithm"] = "RSA"
            info["key_size"] = public.key_size
        elif isinstance(public, ec.EllipticCurvePublicKey):
            info["algorithm"] = "ECDSA"
            info["key_size"] = public.curve.key_size
        elif isinstance(public, dsa.DSAPublicKey):
            info["algorithm"] = "DSA"
            info["key_size"] = public.key_size
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
            tzinfo=timezone.utc
        )
        info["not_after"] = not_after.isoformat()
        info["expired"] = not_after < datetime.now(timezone.utc)
        try:
            info["subject"] = cert.subject.rfc4514_string()
        except Exception:
            info["subject"] = str(cert.subject)
    except Exception:
        # Fallback: look for RSA OID 1.2.840.113549.1.1.1 in DER
        try:
            body = PEM_BLOCK.search(pem_text)
            if body:
                der = base64.b64decode(re.sub(r"\s+", "", body.group(2)))
                if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in der:
                    info["algorithm"] = "RSA"
                elif b"\x2a\x86\x48\xce\x3d\x02\x01" in der:
                    info["algorithm"] = "ECDSA"
        except Exception:
            pass
    return info


def scan_materials(root_path: Path, repo_root: Optional[Path] = None) -> list[RawFinding]:
    root = Path(root_path)
    repo = Path(repo_root) if repo_root else root
    findings: list[RawFinding] = []
    if not root.exists():
        return findings

    for path in iter_material_files(root):
        suffix = path.suffix.lower()
        if suffix in {".p12", ".pfx"}:
            findings.append(
                make_finding(
                    file_path=path,
                    repo_root=repo,
                    line_number=1,
                    language="pkcs12",
                    api_type="PKCS12",
                    algorithm="UNKNOWN",
                    purpose="KEY_STORAGE",
                    library="pkcs12",
                    scanner_id=SCANNER_ID,
                    confidence="MEDIUM",
                    confidence_reason="pkcs12-container",
                    raw_transformation="PKCS12",
                )
            )
            continue
        if suffix == ".der":
            findings.append(
                make_finding(
                    file_path=path,
                    repo_root=repo,
                    line_number=1,
                    language="der",
                    api_type="CERTIFICATE",
                    algorithm="UNKNOWN",
                    purpose="CERTIFICATE",
                    library="x509",
                    scanner_id=SCANNER_ID,
                    confidence="MEDIUM",
                    confidence_reason="der-blob",
                    raw_transformation="DER",
                )
            )
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matches = list(PEM_BLOCK.finditer(text))
        if not matches:
            if suffix in {".pem", ".crt", ".cer", ".key"}:
                findings.append(
                    make_finding(
                        file_path=path,
                        repo_root=repo,
                        line_number=1,
                        language="pem",
                        api_type="CERTIFICATE",
                        algorithm="UNKNOWN",
                        purpose="CERTIFICATE",
                        library="x509",
                        scanner_id=SCANNER_ID,
                        confidence="LOW",
                        confidence_reason="empty-or-binary-pem",
                    )
                )
            continue
        for match in matches:
            label = match.group(1)
            algorithm, purpose = _classify_banner(label)
            line_number = text[: match.start()].count("\n") + 1
            extra = {}
            if "CERTIFICATE" in label.upper():
                extra = _try_parse_certificate(match.group(0))
                algorithm = extra.get("algorithm") or algorithm
            findings.append(
                make_finding(
                    file_path=path,
                    repo_root=repo,
                    line_number=line_number,
                    language="pem",
                    api_type="CERTIFICATE" if purpose == "CERTIFICATE" else "KEY_MATERIAL",
                    algorithm=algorithm,
                    purpose=purpose,
                    library="x509",
                    scanner_id=SCANNER_ID,
                    key_size=extra.get("key_size"),
                    confidence="HIGH",
                    confidence_reason="pem-banner",
                    raw_transformation=label,
                )
            )
    return findings


def join_materials_to_source(
    material_findings: list[dict],
    source_findings: list[dict],
) -> list[dict]:
    """Attach nearby source findings that share a file stem or directory."""
    by_stem: dict[str, list[dict]] = {}
    for finding in source_findings:
        path = str(finding.get("file_path") or "")
        stem = Path(path).stem.lower()
        parent = str(Path(path).parent)
        by_stem.setdefault(stem, []).append(finding)
        by_stem.setdefault(parent, []).append(finding)

    joined = []
    for material in material_findings:
        path = str(material.get("file_path") or "")
        stem = Path(path).stem.lower()
        parent = str(Path(path).parent)
        neighbors = []
        seen = set()
        for key in (stem, parent):
            for neighbor in by_stem.get(key, []):
                nid = neighbor.get("evidence_id") or neighbor.get("id") or neighbor.get("file_path")
                if nid in seen:
                    continue
                seen.add(nid)
                neighbors.append(
                    {
                        "evidence_id": neighbor.get("evidence_id") or neighbor.get("id"),
                        "file_path": neighbor.get("file_path"),
                        "line_number": neighbor.get("line_number"),
                        "algorithm": neighbor.get("algorithm"),
                        "purpose": neighbor.get("purpose"),
                    }
                )
        payload = dict(material)
        payload["linked_source"] = neighbors
        joined.append(payload)
    return joined
