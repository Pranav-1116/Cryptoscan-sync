"""PKI signing for compliance reports (RS256) — bring your own key.

The signature is a real RSASSA-PKCS1-v1_5 SHA-256 signature (RFC 8017) over
the canonical JSON of the report body (every key except ``signature``), so any
independent party can verify it with plain OpenSSL, no CryptoScan code needed:

    # exporter (or the API response) writes the canonical body and the signature
    python -m reporting.signing canonicalize report.json > body.json
    openssl base64 -d -A -in sig.b64 -out report.sig
    openssl dgst -sha256 -verify pub.pem -signature report.sig body.json

Backends, tried in order (no new hard dependencies — air-gap installs stay
stdlib-only):
1. the ``cryptography`` package, when installed (in-process, fastest);
2. the ``openssl`` CLI (present on every deployment this product documents).

When neither is available, signing fails loudly — we never downgrade to an
HMAC and call it a signature.
"""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Mapping


class SigningError(RuntimeError):
    """Key unusable or backend missing — reported, never swallowed into an HMAC."""


def canonical_body(report: Mapping[str, Any]) -> bytes:
    """Canonical JSON of the report without the signature member."""
    payload = {key: value for key, value in report.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _backend() -> str:
    try:
        import cryptography  # noqa: F401

        return "cryptography"
    except ImportError:
        pass
    from shutil import which

    if which("openssl"):
        return "openssl-cli"
    raise SigningError(
        "no signing backend: install the 'cryptography' package or ensure the openssl CLI is on PATH"
    )


def _read_key(key_pem: str | Path) -> bytes:
    """Accept a PEM file path or inline PEM text.

    Inline PEM is recognized *before* path probing: a PEM string can be
    hundreds of characters, and if its base64 happens to contain no ``/`` it
    forms one over-long path component that raises ``ENAMETOOLONG`` on
    ``stat()`` (a nondeterministic failure depending on the random key).
    """
    data = str(key_pem).encode("utf-8")
    if b"PRIVATE KEY" in data or b"PUBLIC KEY" in data:
        return data
    path = Path(key_pem)
    if path.exists():
        return path.read_bytes()
    raise SigningError(f"key not found: {key_pem}")


def _sign_cryptography(data: bytes, private_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        key = serialization.load_pem_private_key(private_pem, password=None)
    except (ValueError, TypeError) as exc:  # garbage / truncated / wrong format
        raise SigningError(f"could not load private key: {exc}") from exc
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _verify_cryptography(data: bytes, signature: bytes, public_pem: bytes) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:  # garbage / truncated / wrong format
        raise SigningError(f"could not load public key: {exc}") from exc
    key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())  # raises on mismatch


def _run_openssl(args: list[str], *, input_: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["openssl", *args], input=input_, capture_output=True, check=False, timeout=30
    )
    if proc.returncode != 0:
        raise SigningError(
            f"openssl {' '.join(args[:2])} failed: {proc.stderr.decode('utf-8', 'replace')[:300]}"
        )
    return proc.stdout


def _sign_openssl(data: bytes, private_pem: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pem") as key_file, tempfile.NamedTemporaryFile(
        suffix=".bin"
    ) as sig_file:
        key_file.write(private_pem)
        key_file.flush()
        _run_openssl(["dgst", "-sha256", "-sign", key_file.name, "-out", sig_file.name], input_=data)
        return sig_file.read()


def _verify_openssl(data: bytes, signature: bytes, public_pem: bytes) -> None:
    with tempfile.NamedTemporaryFile(suffix=".pem") as key_file, tempfile.NamedTemporaryFile(
        suffix=".sig"
    ) as sig_file:
        key_file.write(public_pem)
        key_file.flush()
        sig_file.write(signature)
        sig_file.flush()
        _run_openssl(
            ["dgst", "-sha256", "-verify", key_file.name, "-signature", sig_file.name],
            input_=data,
        )  # non-zero exit -> SigningError -> verification failure


def sign_bytes(data: bytes, private_key_pem: str | Path) -> dict[str, Any]:
    """RSASSA-PKCS1v15-SHA256 over ``data`` with an RSA private key."""
    backend = _backend()
    private_pem = _read_key(private_key_pem)
    if backend == "cryptography":
        signature = _sign_cryptography(data, private_pem)
    else:
        signature = _sign_openssl(data, private_pem)
    return {"alg": "RS256", "value": _b64url(signature), "backend": backend}


def verify_bytes(data: bytes, signature_b64: str, public_key_pem: str | Path) -> dict[str, Any]:
    """Verify a signature produced by :func:`sign_bytes` (or by openssl directly)."""
    backend = _backend()
    public_pem = _read_key(public_key_pem)
    signature = _b64url_decode(str(signature_b64))
    try:
        if backend == "cryptography":
            _verify_cryptography(data, signature, public_pem)
        else:
            _verify_openssl(data, signature, public_pem)
    except SigningError as exc:
        return {"ok": False, "backend": backend, "error": str(exc)}
    except Exception as exc:  # cryptography raises several exception types on mismatch
        return {"ok": False, "backend": backend, "error": f"signature invalid: {exc}"}
    return {"ok": True, "backend": backend, "error": None}


def sign_report(
    report: dict[str, Any], private_key_pem: str | Path, *, key_id: str | None = None
) -> dict[str, Any]:
    """Attach a detached PKI signature covering the canonical report body."""
    signature = sign_bytes(canonical_body(report), private_key_pem)
    signature["key_id"] = key_id
    signature["covers"] = "canonical JSON of the report without the signature member"
    signature["verify"] = (
        "openssl dgst -sha256 -verify pub.pem -signature report.sig body.json "
        "(body = canonical JSON, signature = base64url-decoded value)"
    )
    report["signature"] = signature
    return report


def verify_report(report: Mapping[str, Any], public_key_pem: str | Path) -> dict[str, Any]:
    """Verify a signed report. A report without a signature is an honest failure."""
    signature = report.get("signature")
    if not isinstance(signature, Mapping) or not signature.get("value"):
        return {"ok": False, "error": "report carries no signature", "backend": None}
    result = verify_bytes(canonical_body(report), str(signature["value"]), public_key_pem)
    result["alg"] = signature.get("alg")
    result["key_id"] = signature.get("key_id")
    return result


def _main(argv: list[str]) -> int:
    """``python -m reporting.signing canonicalize report.json`` — export the signed body.

    Auditors verify without us: canonicalize the report they received, then
    check the signature with OpenSSL against the issuer's public key.
    """
    if len(argv) == 2 and argv[0] == "canonicalize":
        report = json.loads(Path(argv[1]).read_text())
        print(canonical_body(report).decode("utf-8"))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":  # pragma: no cover - manual ops path
    import sys

    raise SystemExit(_main(sys.argv[1:]))
