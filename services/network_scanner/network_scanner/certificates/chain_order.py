"""Analyze the certificate chain exactly as the server SENT it.

Python 3.11's stdlib only hands us the leaf (``get_unverified_chain`` arrives
in 3.13), so the sent chain is fetched with ``openssl s_client -showcerts``
and parsed with the shared ``parse_der``.  The analysis itself is a pure
function over parsed certs so it stays unit-testable without openssl:

* issuer/subject links must chain (``CHAIN_LINK_BROKEN``),
* out-of-order sends are named as such (``CHAIN_ORDER_BROKEN``),
* a lone non-self-signed leaf means clients without the intermediates will
  fail validation (``CHAIN_INCOMPLETE``),
* shipping the root wastes bytes and discloses topology (``ROOT_CERT_SENT``),
* duplicated certs are flagged (``DUPLICATE_CERT_IN_CHAIN``),
* weak intermediate keys / signatures are surfaced via the registry verdicts.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any

from network_scanner.certificates.cert_parser import normalize_dn, parse_der, pem_to_der

_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def _openssl_binary() -> str | None:
    return shutil.which("openssl")


def fetch_sent_chain(
    host: str,
    port: int,
    *,
    ip: str | None = None,
    sni: str | None = None,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Return the parsed certs the server sent, leaf first (s_client order)."""
    binary = _openssl_binary()
    if not binary:
        return []
    argv = [
        binary,
        "s_client",
        "-connect",
        f"{ip or host}:{port}",
        "-servername",
        sni or host,
        "-showcerts",
    ]
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, local diagnostic tool
            argv,
            input=b"",
            capture_output=True,
            timeout=max(3.0, timeout) + 2.0,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    text = (proc.stdout or b"").decode("utf-8", "replace")
    certs: list[dict[str, Any]] = []
    for block in _PEM_BLOCK.findall(text):
        der = pem_to_der(block)
        if not der:
            continue
        parsed = parse_der(der)
        if parsed:
            certs.append(parsed)
    return certs


def _is_self_signed(cert: dict[str, Any]) -> bool:
    return bool(cert.get("is_self_signed")) or normalize_dn(str(cert.get("subject") or "")) == normalize_dn(
        str(cert.get("issuer") or "")
    )


def analyze_chain_sent(certs: list[dict[str, Any]]) -> dict[str, Any]:
    """Pure verdicts over the chain as sent (leaf first)."""
    chain = [cert for cert in certs if cert]
    issues: list[str] = []
    length = len(chain)
    if length == 0:
        return {"sent_length": 0, "issues": ["CHAIN_UNAVAILABLE"], "order_ok": None, "leaf_self_signed": None}

    fingerprints = [str(cert.get("fingerprint_sha256") or "") for cert in chain]
    if len(set(fingerprints)) != length:
        issues.append("DUPLICATE_CERT_IN_CHAIN")

    subjects = [normalize_dn(str(cert.get("subject") or "")) for cert in chain]
    issuers = [normalize_dn(str(cert.get("issuer") or "")) for cert in chain]
    order_ok = True
    for index in range(length - 1):
        expected = issuers[index]
        if not expected:
            continue
        if subjects[index + 1] == expected:
            continue
        order_ok = False
        if expected in subjects[index + 2 :]:
            issues.append("CHAIN_ORDER_BROKEN")
        else:
            issues.append("CHAIN_LINK_BROKEN")

    leaf_self_signed = _is_self_signed(chain[0])
    if length == 1 and not leaf_self_signed:
        issues.append("CHAIN_INCOMPLETE")
    if length > 1 and _is_self_signed(chain[-1]):
        issues.append("ROOT_CERT_SENT")

    for cert in chain[1:]:
        weak = _weak_intermediate_issues(cert)
        if weak and weak not in issues:
            issues.append(weak)

    return {
        "sent_length": length,
        "issues": issues,
        "order_ok": order_ok,
        "leaf_self_signed": leaf_self_signed,
        "subjects": subjects,
    }


def _weak_intermediate_issues(cert: dict[str, Any]) -> str | None:
    """Registry-based weak key / signature check for non-leaf certs."""
    try:
        from shared_models.algorithm_registry import parse_algorithm

        algo = str(cert.get("public_key_algorithm") or "")
        size = cert.get("public_key_size")
        key_info = parse_algorithm(f"{algo}-{size}".rstrip("-")) if (algo and size) else None
        if key_info is not None and key_info.status == "DISALLOWED":
            return "CHAIN_WEAK_INTERMEDIATE"
        sig = str(cert.get("signature_algorithm") or "").lower()
        if sig.startswith(("sha1", "md5")):
            return "CHAIN_WEAK_INTERMEDIATE"
    except Exception:  # noqa: BLE001 — registry unavailable: degrade, don't crash
        return None
    return None


def probe_chain_sent(
    host: str,
    port: int,
    *,
    ip: str | None = None,
    sni: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Fetch + analyze the sent chain; honest when openssl is unavailable."""
    if not _openssl_binary():
        return {
            "method": "openssl-sclient-unavailable",
            "sent_length": 0,
            "issues": [],
            "order_ok": None,
            "leaf_self_signed": None,
            "detail": "openssl binary not found on this host; sent-chain not observable",
        }
    certs = fetch_sent_chain(host, port, ip=ip, sni=sni, timeout=timeout)
    if not certs:
        return {
            "method": "openssl-sclient",
            "sent_length": 0,
            "issues": ["CHAIN_UNAVAILABLE"],
            "order_ok": None,
            "leaf_self_signed": None,
            "detail": "handshake transcript carried no certificates",
        }
    analysis = analyze_chain_sent(certs)
    analysis["method"] = "openssl-sclient"
    analysis["certificates"] = certs
    return analysis
