"""Extract CRL distribution points. Live fetch is opt-in and fail-open."""

from __future__ import annotations

import re
from typing import Any
from urllib.request import urlopen

from network_scanner.certificates.ocsp_checker import live_revocation_enabled

CRL_URL = re.compile(r"http[s]?://[^\s\"']+crl[^\s\"']*", re.IGNORECASE)


def extract_crl_urls(cert: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    if cert.get("crl_url"):
        urls.append(str(cert["crl_url"]))
    extra = cert.get("extra") or {}
    for item in extra.get("crl_urls") or []:
        urls.append(str(item))
    pem = cert.get("pem") or ""
    urls.extend(CRL_URL.findall(pem))
    urls.extend(_crypto_crl(cert.get("pem")))
    seen = []
    for url in urls:
        if url and url not in seen:
            seen.append(url)
    return seen


def _crypto_crl(pem: str | None) -> list[str]:
    if not pem:
        return []
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID

        parsed = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        ext = parsed.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        out = []
        for point in ext.value:
            if not point.full_name:
                continue
            for name in point.full_name:
                value = getattr(name, "value", None)
                if value:
                    out.append(str(value))
        return out
    except Exception:
        return []


def serials_from_crl_pem(text: str) -> set[str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        crl = x509.load_pem_x509_crl(text.encode("utf-8"), default_backend())
        return {format(item.serial_number, "x") for item in crl}
    except Exception:
        return set()


def check_crl(
    cert: dict[str, Any],
    *,
    live: bool | None = None,
    crl_pem: str | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    urls = extract_crl_urls(cert)
    serial = str(cert.get("serial_number") or "").lower().lstrip("0x")
    result: dict[str, Any] = {"method": "CRL", "status": "UNKNOWN", "urls": urls, "reason": "unchecked"}
    pem = crl_pem
    if pem is None and live_revocation_enabled(live) and urls:
        try:
            with urlopen(urls[0], timeout=timeout) as resp:  # noqa: S310
                pem = resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            result["reason"] = f"unreachable:{exc.__class__.__name__}"
            return result
    if pem:
        revoked = serials_from_crl_pem(pem)
        if serial and serial in revoked:
            result["status"] = "REVOKED"
            result["reason"] = "serial_on_crl"
        elif revoked:
            result["status"] = "GOOD"
            result["reason"] = "serial_not_on_crl"
        else:
            result["reason"] = "crl_unparsed"
        return result
    result["reason"] = "live_disabled" if not live_revocation_enabled(live) else "no_crl"
    return result
