"""Extract OCSP URLs. Live checks are opt-in and fail-open (never claim GOOD blindly)."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.request import Request, urlopen

AIA_OCSP = re.compile(r"http[s]?://[^\s\"']+ocsp[^\s\"']*", re.IGNORECASE)


def live_revocation_enabled(flag: bool | None = None) -> bool:
    if flag is not None:
        return bool(flag)
    env = os.environ.get("CRYPTOSCAN_TLS_LIVE", "").strip().lower()
    return env in {"1", "true", "yes", "on"}


def extract_ocsp_urls(cert: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    if cert.get("ocsp_url"):
        urls.append(str(cert["ocsp_url"]))
    extra = cert.get("extra") or {}
    for item in extra.get("ocsp_urls") or []:
        urls.append(str(item))
    pem = cert.get("pem") or ""
    urls.extend(AIA_OCSP.findall(pem))
    urls.extend(_crypto_aia(cert.get("pem")))
    seen = []
    for url in urls:
        if url and url not in seen:
            seen.append(url)
    return seen


def _crypto_aia(pem: str | None) -> list[str]:
    if not pem:
        return []
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

        parsed = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        ext = parsed.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        out = []
        for access in ext.value:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                out.append(access.access_location.value)
        return out
    except Exception:
        return []


def check_ocsp(cert: dict[str, Any], *, live: bool | None = None, timeout: float = 3.0) -> dict[str, Any]:
    urls = extract_ocsp_urls(cert)
    enabled = live_revocation_enabled(live)
    result = {
        "method": "OCSP",
        "status": "UNKNOWN",
        "urls": urls,
        "reason": "live_disabled" if not enabled else ("no_ocsp_url" if not urls else "no_signed_response"),
    }
    if not enabled or not urls:
        return result
    # Reachability only — a GET is not a valid OCSP request, so we never return GOOD.
    try:
        req = Request(urls[0], method="HEAD")
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-opt-in live probe
            result["http_status"] = getattr(resp, "status", None)
            result["reason"] = "responder_reachable_unsigned"
    except Exception as exc:
        result["reason"] = f"unreachable:{exc.__class__.__name__}"
    return result
