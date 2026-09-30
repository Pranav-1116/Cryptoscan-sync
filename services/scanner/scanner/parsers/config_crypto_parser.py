"""Detect cryptographic settings in deploy/config files (nginx, TLS, JWT, Terraform)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import re
from pathlib import Path

from scanner.core.file_discovery import DEFAULT_EXCLUDED_DIRS
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-config-scanner-v1.0"

CONFIG_SUFFIXES = {
    ".conf",
    ".cnf",
    ".yml",
    ".yaml",
    ".properties",
    ".env",
    ".ini",
    ".tf",
    ".tfvars",
    ".cfg",
}

NAMED_FILES = {
    "dockerfile",
    ".env",
    ".env.local",
    ".env.production",
    "nginx.conf",
    "openssl.cnf",
}

SSL_PROTOCOLS = re.compile(r"(?im)^\s*(?:proxy_|grpc_|uwsgi_)?ssl_protocols\s+([^;#]+)")
SSL_ECDH_CURVE = re.compile(r"(?im)^\s*ssl_ecdh_curve\s+([^;#]+)")
_TEMPLATED = re.compile(r"\{\{|\$\{|%\{|<%|\{%")
APACHE_PROTO = re.compile(r"(?im)^\s*SSLProtocol\s+(.+)$")
OPENSSL_MIN = re.compile(r"(?im)^\s*MinProtocol\s*=\s*(\S+)")
SPRING_PROTO = re.compile(
    r"(?im)^\s*(?:server\.ssl\.enabled-protocols|ssl-protocol|min[_-]?tls[_-]?version|minimum_protocol_version)\s*[:=]\s*['\"]?([A-Za-z0-9._-]+)"
)
JWT_SECRET = re.compile(
    r"(?im)^\s*(?:jwt[_./-]?secret|secret[_-]?key|encryption[_-]?key)\s*[:=]\s*['\"]?(\S+)"
)
ENV_SECRET = re.compile(
    r"(?im)^(JWT_SECRET|SECRET_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|ENCRYPTION_KEY|NEXTAUTH_SECRET|TOKEN_SECRET)=(\S+)"
)
TF_PRIVATE_KEY = re.compile(
    r'(?is)resource\s+"tls_private_key"\s+"[^"]+"\s*\{.*?algorithm\s*=\s*"(\w+)".*?\}'
)
TF_RSA_BITS = re.compile(r"(?im)^\s*rsa_bits\s*=\s*(\d+)")
TF_KMS = re.compile(r'(?im)^\s*customer_master_key_spec\s*=\s*"([^"]+)"')
TF_SSL_POLICY = re.compile(r'(?im)^\s*(?:ssl_policy|min_tls_version)\s*=\s*"([^"]+)"')
HAPROXY = re.compile(r"(?im)^\s*ssl-min-ver\s+(\S+)")
CIPHERS = re.compile(r"(?im)^\s*(?:ssl_ciphers|SSLCipherSuite)\s+(.+)$")

_TLS_TOKEN = {
    "sslv3": "SSLv3",
    "sslv2": "SSLv2",
    "tlsv1": "TLS1.0",
    "tlsv1.0": "TLS1.0",
    "tls1": "TLS1.0",
    "tls1.0": "TLS1.0",
    "tlsv1.1": "TLS1.1",
    "tls1.1": "TLS1.1",
    "tlsv1.2": "TLS1.2",
    "tls1.2": "TLS1.2",
    "tlsv1.3": "TLS1.3",
    "tls1.3": "TLS1.3",
}


def iter_config_files(root: Path):
    excluded = DEFAULT_EXCLUDED_DIRS
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded or part.startswith(".") and part not in {".env", ".env.local", ".env.production"} for part in path.parts[:-1]):
            continue
        name = path.name.lower()
        if path.suffix.lower() in CONFIG_SUFFIXES or name in NAMED_FILES:
            yield path


def scan_config_tree(root_path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    root = Path(root_path)
    repo = Path(repo_root) if repo_root else root
    if not root.exists():
        return []
    findings: list[RawFinding] = []
    for path in iter_config_files(root):
        findings.extend(parse_config_file(path, repo))
    return findings


def _content_start(match: "re.Match[str]") -> int:
    """``(?m)^\\s*directive`` may begin on the *previous* blank line because ``\\s*``
    swallows the newline; report the line where the directive text actually starts."""
    whole = match.group(0)
    return match.start() + (len(whole) - len(whole.lstrip()))


def parse_config_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if len(text) > 2_000_000:
        return []
    findings: list[RawFinding] = []

    def add(match: re.Match, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=text[: _content_start(match)].count("\n") + 1,
                language="CONFIG",
                scanner_id=SCANNER_ID,
                **kwargs,
            )
        )

    for match in SSL_ECDH_CURVE.finditer(text):
        add(match, api_type="KEY_AGREEMENT", algorithm="ECDH", purpose="KEY_EXCHANGE", library="nginx",
            raw_transformation=match.group(1).strip()[:60], confidence="MEDIUM")
        for tok in re.split(r"[\s:,]+", match.group(1).strip()):
            low = tok.lower()
            if low in {"x25519", "curve25519"}:
                add(match, api_type="KEY_AGREEMENT", algorithm="X25519", purpose="KEY_EXCHANGE", library="nginx", raw_transformation=tok, confidence="HIGH")
            elif low in {"x448"}:
                add(match, api_type="KEY_AGREEMENT", algorithm="X448", purpose="KEY_EXCHANGE", library="nginx", raw_transformation=tok, confidence="HIGH")
            elif low.startswith(("x25519kyber", "x25519mlkem", "secp256r1mlkem")):
                add(match, api_type="KEY_AGREEMENT", algorithm="ML-KEM", purpose="KEY_EXCHANGE", library="nginx", raw_transformation=tok, confidence="HIGH")
    for match in SSL_PROTOCOLS.finditer(text):
        value = match.group(1).strip()
        if _TEMPLATED.search(value):
            # ssl_protocols {{ $cfg.SSLProtocols }} — the version set is decided at
            # deploy time; record the TLS endpoint without a version.
            add(match, api_type="KEY_AGREEMENT", algorithm="TLS", purpose="NETWORK_ENCRYPTION",
                library="nginx", raw_transformation=value[:60], confidence="LOW",
                confidence_reason="protocol list is a template variable")
            continue
        for token in re.split(r"[\s,]+", value):
            algo = _normalize_tls(token)
            if not algo:
                continue
            add(
                match,
                api_type="KEY_AGREEMENT",
                algorithm=algo,
                purpose="NETWORK_ENCRYPTION",
                library="nginx",
                raw_transformation=token,
            )
    for match in APACHE_PROTO.finditer(text):
        for token in re.split(r"[\s,]+", match.group(1).strip()):
            token = token.lstrip("+-")
            algo = _normalize_tls(token)
            if not algo:
                continue
            add(
                match,
                api_type="KEY_AGREEMENT",
                algorithm=algo,
                purpose="NETWORK_ENCRYPTION",
                library="apache",
                raw_transformation=token,
            )
    for match in OPENSSL_MIN.finditer(text):
        algo = _normalize_tls(match.group(1)) or match.group(1).upper()
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="NETWORK_ENCRYPTION",
            library="openssl.cnf",
            raw_transformation=match.group(1),
        )
    for match in SPRING_PROTO.finditer(text):
        algo = _normalize_tls(match.group(1)) or match.group(1).upper()
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="NETWORK_ENCRYPTION",
            library="application-config",
            raw_transformation=match.group(1),
        )
    for match in JWT_SECRET.finditer(text):
        secret = match.group(1).strip().strip("'\"")
        if len(secret) < 6 or secret.lower() in {"changeme", "null", "none", "xxx"}:
            continue
        add(
            match,
            api_type="HARDCODED_KEY",
            algorithm="JWT",
            purpose="KEY_GENERATION",
            library="config-secret",
            is_hardcoded_key=True,
            hardcoded_key_length=len(secret),
            confidence="HIGH",
            confidence_reason="jwt-or-app-secret-in-config",
            raw_transformation="secret",
        )
    for match in ENV_SECRET.finditer(text):
        value = match.group(2).strip().strip("'\"")
        if not value or value.startswith("${") or value.startswith("$("):
            continue
        add(
            match,
            api_type="HARDCODED_KEY",
            algorithm="UNKNOWN",
            purpose="KEY_GENERATION",
            library=match.group(1),
            is_hardcoded_key=True,
            hardcoded_key_length=len(value),
            confidence="HIGH",
            confidence_reason="secret-env-assignment",
        )
    for match in TF_PRIVATE_KEY.finditer(text):
        algo = match.group(1).upper()
        bits = None
        nested = match.group(0)
        bit_match = TF_RSA_BITS.search(nested)
        if bit_match:
            bits = int(bit_match.group(1))
        add(
            match,
            api_type="KEY_PAIR_GENERATOR",
            algorithm=algo,
            purpose="KEY_GENERATION",
            library="terraform-tls",
            key_size=bits,
            raw_transformation=match.group(1),
        )
    for match in TF_KMS.finditer(text):
        spec = match.group(1).upper()
        algo = "RSA" if "RSA" in spec else ("AES" if "SYMMETRIC" in spec else spec)
        bits = None
        digits = re.search(r"(\d{3,4})", spec)
        if digits:
            bits = int(digits.group(1))
        add(
            match,
            api_type="KEY_GENERATOR",
            algorithm=algo,
            purpose="KEY_MANAGEMENT",
            library="aws-kms",
            key_size=bits,
            raw_transformation=match.group(1),
        )
    for match in TF_SSL_POLICY.finditer(text):
        raw = match.group(1)
        algo = "TLS1.0" if "TLS-1-0" in raw.upper() or raw in {"1.0", "TLSv1"} else (
            "TLS1.1" if "TLS-1-1" in raw.upper() or raw in {"1.1", "TLSv1.1"} else raw
        )
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="LOAD_BALANCER_TLS",
            library="terraform",
            raw_transformation=raw,
        )
    for match in HAPROXY.finditer(text):
        algo = _normalize_tls(match.group(1)) or match.group(1).upper()
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="NETWORK_ENCRYPTION",
            library="haproxy",
            raw_transformation=match.group(1),
        )
    for match in CIPHERS.finditer(text):
        suite = match.group(1).strip().strip(";'\"")
        if not suite:
            continue
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm="TLS-CIPHERS",
            purpose="NETWORK_ENCRYPTION",
            library="tls-config",
            confidence="MEDIUM",
            confidence_reason="cipher-suite-list",
            raw_transformation=suite[:80],
        )
    try:
        from scanner.parsers.config_rules import run_config_rules

        seen = {
            (f.source.line_number, f.crypto.algorithm or "", f.crypto.api_type or "")
            for f in findings
        }
        findings.extend(run_config_rules(file_path, repo_root, text, SCANNER_ID, seen))
    except Exception as _handler_exc:  # rule pack must never break the base parser
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    return findings


def _normalize_tls(token: str) -> str | None:
    cleaned = token.strip().strip("'\" ").lower().replace("_", ".")
    cleaned = cleaned.replace("tlsv", "tls").replace("sslv", "ssl")
    if cleaned in _TLS_TOKEN:
        return _TLS_TOKEN[cleaned]
    if cleaned.startswith("tlsv"):
        return _TLS_TOKEN.get(cleaned.replace("tlsv", "tls"))
    return _TLS_TOKEN.get(cleaned)
