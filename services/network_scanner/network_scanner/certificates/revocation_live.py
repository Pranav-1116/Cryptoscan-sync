"""Real live revocation checking: OCSP queries + CRL fetch/parse via openssl.

The pre-existing live paths were shallow (OCSP = HEAD reachability, CRL =
``cryptography``-only parsing, which silently yields nothing when the package
is absent).  This module does the real work using the ``openssl`` CLI, which
is the same dependency the rest of the deep probes rely on, and stays honest:

* OCSP: ``openssl ocsp -issuer .. -cert .. -url .. -nonce`` — the stdout
  status line (``good`` / ``revoked`` / ``unknown``) is the verdict.  When the
  response signer fails verification (e.g. a self-signed responder) the status
  is kept but ``response_verified`` is ``False`` — a fact, not a failure.
* CRL: fetched over HTTP(S) through the bounded disk cache, PEM *or* DER,
  parsed with ``openssl crl -text``; a past ``Next Update`` means the CRL is
  stale, so the verdict stays UNKNOWN (fail-closed) with ``reason`` naming it.
* Serials are normalized (colon-hex, ``0x``, leading zeros, case) before they
  are compared.
* No openssl binary, no issuer for OCSP, unreachable endpoints — every gap is
  reported as a reason string, never guessed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from network_scanner.certificates.cert_parser import normalize_dn
from network_scanner.certificates.crl_checker import extract_crl_urls
from network_scanner.certificates.ocsp_checker import extract_ocsp_urls
from network_scanner.certificates.revocation_cache import cache_get, cache_put

_OCSP_STATUS = re.compile(r"^\s*\S+:\s+(good|revoked|unknown)", re.IGNORECASE | re.MULTILINE)
_OCSP_REVOKED_AT = re.compile(r"Revocation Time:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_CRL_SERIAL = re.compile(r"Serial Number:\s*([0-9A-Fa-f:]+)")
_CRL_NEXT_UPDATE = re.compile(r"Next Update:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_PEM_CRL = b"-----BEGIN X509 CRL-----"


def normalize_serial(value: Any) -> str:
    """``'0x1A:2B'``/``'1a:2b'``/``'001a2b'`` -> ``'1a2b'`` (lowercase, no zeros)."""
    if value is None:
        return ""
    text = str(value).strip().lower().removeprefix("0x").replace(":", "").replace(" ", "")
    try:
        return format(int(text or "0", 16), "x")
    except ValueError:
        return text.lstrip("0")


def parse_ocsp_output(stdout: str, stderr: str) -> dict[str, Any]:
    """Pure classifier over an ``openssl ocsp`` transcript."""
    result: dict[str, Any] = {
        "status": "UNKNOWN",
        "reason": None,
        "response_verified": None,
        "revocation_time": None,
    }
    if stderr:
        lowered = stderr.lower()
        result["response_verified"] = not (
            "verify error" in lowered or "response verify failure" in lowered
        )
        if "error querying" in lowered or "connect timeout" in lowered or "connection refused" in lowered:
            result["reason"] = "responder_unreachable"
        elif "http" in lowered and "error" in lowered:
            result["reason"] = "responder_http_error"
    match = _OCSP_STATUS.search(stdout or "")
    if match:
        status = match.group(1).lower()
        result["status"] = {"good": "GOOD", "revoked": "REVOKED", "unknown": "UNKNOWN"}[status]
        result["reason"] = "responder_answered"
        if status == "revoked":
            when = _OCSP_REVOKED_AT.search(stdout or "")
            result["revocation_time"] = when.group(1).strip() if when else None
    elif not result["reason"]:
        result["reason"] = "no_status_line"
    return result


def parse_crl_text(text: str) -> dict[str, Any]:
    """Pure extraction of revoked serials + next-update from ``openssl crl -text``."""
    serials = {normalize_serial(match.group(1)) for match in _CRL_SERIAL.finditer(text or "")}
    serials.discard("")
    match = _CRL_NEXT_UPDATE.search(text or "")
    return {"revoked_serials": sorted(serials), "next_update_raw": match.group(1).strip() if match else None}


def crl_is_stale(next_update_raw: str | None, *, now: datetime | None = None) -> bool | None:
    """True/False on parsable next-update, None when the CRL omits it."""
    if not next_update_raw:
        return None
    try:
        stamp = datetime.strptime(next_update_raw, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp <= (now or datetime.now(timezone.utc))


def _openssl_binary() -> str | None:
    return shutil.which("openssl")


def _run(argv: list[str], *, data: bytes | None = None, timeout: float) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, local diagnostic tool
            argv, input=data, capture_output=True, timeout=max(2.0, timeout) + 2.0
        )
    except (subprocess.TimeoutExpired, OSError):
        return "", "", -1
    return (
        (proc.stdout or b"").decode("utf-8", "replace"),
        (proc.stderr or b"").decode("utf-8", "replace"),
        proc.returncode,
    )


def _find_issuer_pem(leaf: dict[str, Any], chain: list[dict[str, Any]]) -> str | None:
    issuer_dn = normalize_dn(str(leaf.get("issuer") or ""))
    if not issuer_dn:
        return None
    for cert in chain[1:]:
        if normalize_dn(str(cert.get("subject") or "")) == issuer_dn and cert.get("pem"):
            return str(cert["pem"])
    return None


def check_ocsp_live(
    leaf: dict[str, Any],
    chain: list[dict[str, Any]],
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Query the leaf's OCSP responder for real; never guess GOOD."""
    urls = extract_ocsp_urls(leaf)
    result: dict[str, Any] = {
        "method": "OCSP",
        "status": "UNKNOWN",
        "urls": urls,
        "reason": "no_ocsp_url" if not urls else None,
        "response_verified": None,
        "revocation_time": None,
        "cache": None,
    }
    if not urls:
        return result
    binary = _openssl_binary()
    if not binary:
        result["reason"] = "local_unsupported_openssl_missing"
        return result
    leaf_pem = leaf.get("pem")
    issuer_pem = _find_issuer_pem(leaf, chain)
    if not leaf_pem or not issuer_pem:
        result["reason"] = "issuer_unavailable"
        return result
    with tempfile.TemporaryDirectory(prefix="cryptoscan-ocsp-") as tmp:
        cert_path = Path(tmp) / "leaf.pem"
        issuer_path = Path(tmp) / "issuer.pem"
        cert_path.write_text(str(leaf_pem))
        issuer_path.write_text(issuer_pem)
        stdout, stderr, _rc = _run(
            [
                binary, "ocsp",
                "-issuer", str(issuer_path),
                "-cert", str(cert_path),
                "-url", urls[0],
                "-nonce",
                "-timeout", str(int(max(2, timeout))),
            ],
            timeout=timeout,
        )
    result.update(parse_ocsp_output(stdout, stderr))
    return result


def check_crl_live(
    leaf: dict[str, Any],
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Fetch (cache-first) the leaf's CRL and look its serial up."""
    urls = extract_crl_urls(leaf)
    serial = normalize_serial(leaf.get("serial_number"))
    result: dict[str, Any] = {
        "method": "CRL",
        "status": "UNKNOWN",
        "urls": urls,
        "reason": "no_crl_url" if not urls else None,
        "serial_number": serial or None,
        "next_update_raw": None,
        "cache": None,
        "revoked_serials": None,
    }
    if not urls:
        return result
    binary = _openssl_binary()
    if not binary:
        result["reason"] = "local_unsupported_openssl_missing"
        return result

    url = urls[0]
    payload: bytes | None = None
    cached = cache_get(url)
    if cached is not None:
        payload = cached["data"]
        result["cache"] = "hit"
    else:
        result["cache"] = "miss"
        try:
            req = Request(url, method="GET")  # noqa: S310 — operator-opt-in live probe
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                payload = resp.read()
        except (URLError, OSError, ValueError) as exc:
            result["reason"] = f"crl_unreachable:{exc.__class__.__name__}"
            return result
        if payload:
            cache_put(url, payload)

    if not payload:
        result["reason"] = "crl_empty_response"
        return result
    inform = "PEM" if _PEM_CRL in payload else "DER"
    stdout, _stderr, rc = _run(
        [binary, "crl", "-inform", inform, "-noout", "-text"],
        data=payload,
        timeout=timeout,
    )
    carries_revocations = "Serial Number" in stdout or "No Revoked Certificates" in stdout
    if rc != 0 or not carries_revocations:
        result["reason"] = "crl_unparsed"
        return result
    parsed = parse_crl_text(stdout)
    result["next_update_raw"] = parsed["next_update_raw"]
    result["revoked_serials"] = parsed["revoked_serials"] or []
    stale = crl_is_stale(parsed["next_update_raw"])
    if stale is True:
        # fail-closed: an expired CRL proves nothing about right now
        result["reason"] = "crl_stale"
        return result
    if not serial:
        result["reason"] = "leaf_serial_unknown"
        return result
    if serial in parsed["revoked_serials"]:
        result["status"] = "REVOKED"
        result["reason"] = "serial_on_crl"
    else:
        result["status"] = "GOOD"
        result["reason"] = "serial_not_on_crl"
    return result


def check_revocation_live(
    leaf: dict[str, Any],
    chain: list[dict[str, Any]] | None = None,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """OCSP first (specific + fresh), CRL as fallback; honest either way."""
    chain = chain or [leaf]
    ocsp = check_ocsp_live(leaf, chain, timeout=timeout)
    if ocsp.get("status") in {"GOOD", "REVOKED"}:
        ocsp["checked_at"] = datetime.now(timezone.utc).isoformat()
        return ocsp
    crl = check_crl_live(leaf, timeout=timeout)
    if crl.get("status") in {"GOOD", "REVOKED"}:
        crl["checked_at"] = datetime.now(timezone.utc).isoformat()
        crl["ocsp"] = {key: ocsp.get(key) for key in ("status", "reason")}
        return crl
    crl["checked_at"] = datetime.now(timezone.utc).isoformat()
    crl["ocsp"] = {key: ocsp.get(key) for key in ("status", "reason")}
    return crl
