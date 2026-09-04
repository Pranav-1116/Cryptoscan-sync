"""TLS library version risk table.

Verdicts for the crypto libraries found loaded in running processes —
EOL OpenSSL builds are the classic production liability: they keep
serving TLS 1.0/1.1 and dead ciphers long after policy banned them.
"""

from __future__ import annotations

from typing import Any

ALLOWED = "ALLOWED"
RESTRICTED = "RESTRICTED"
DEPRECATED = "DEPRECATED"
DISALLOWED = "DISALLOWED"
UNKNOWN = "UNKNOWN"

#: OpenSSL release dates/EOL — https://www.openssl.org/source/ (EOL column)
_OPENSSL_EOL: dict[tuple[int, int, int], str] = {
    (0, 9, 8): "2015-12-03",
    (1, 0, 0): "2010-03-29",
    (1, 0, 1): "2016-12-31",
    (1, 0, 2): "2019-12-31",
    (1, 1, 0): "2019-09-11",
    (1, 1, 1): "2023-09-11",
    (3, 0, 0): "2026-09-07",
}


def _parse_version(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts: list[int] = []
    for token in version.split("."):
        if token.isdigit():
            parts.append(int(token))
        else:
            break
    return tuple(parts) if parts else None


def assess_library(library: str, version: str | None) -> dict[str, Any]:
    """Risk verdict for a loaded TLS library version.

    A soname-only match (e.g. OpenSSL ``"3"``, GnuTLS ``"30.x"``) is treated as
    an unversioned ABI tag and never yields a false EOL verdict — callers must
    resolve the real upstream version (version_resolve) before assessing.
    """
    lib = (library or "").lower()
    ver = _parse_version(version)

    if lib == "openssl":
        return _assess_openssl(ver, version=version)
    if lib == "libressl":
        return _verdict(ALLOWED if ver and ver >= (3, 4) else RESTRICTED,
                        "LibreSSL" + (f" {version}" if version else ""),
                        "verify TLS 1.3 support on this build")
    if lib == "boringssl":
        return _verdict(ALLOWED, "BoringSSL", "Chromium lineage; no static EOL — track container base image")
    if lib == "gnutls":
        if ver is None:
            return _verdict(UNKNOWN, "GnuTLS", "version not exposed in filename")
        # A soname-only match (libgnutls.so.30.40.3) parses to (30, 40, 3).
        # The GnuTLS soname major stays 30 across *all* 3.3–3.8 releases, so it
        # is an ABI tag, not the upstream version — never call it deprecated
        # from the soname alone. The real version is resolved via the package
        # manager before we get here (version_resolve), and then parses as a
        # 3.x tuple below.
        if ver[0] >= 10:
            return _verdict(
                UNKNOWN,
                f"GnuTLS (ABI soname {version})",
                "soname is an ABI tag shared by GnuTLS 3.3–3.8 — not the release version; resolved via package manager",
            )
        if ver < (3, 6):
            return _verdict(DISALLOWED, f"GnuTLS {version}", "pre-3.6: no modern TLS 1.3, weak defaults")
        if ver < (3, 7):
            return _verdict(DEPRECATED, f"GnuTLS {version}", "3.6.x aging; upgrade to 3.7/3.8")
        return _verdict(ALLOWED, f"GnuTLS {version}", "")
    if lib == "nss":
        if ver is None:
            return _verdict(UNKNOWN, "NSS", "libnss3.so has no version in its name; resolved via package manager or vendor-managed")
        return _verdict(ALLOWED if ver >= (3, 44) else DEPRECATED, f"NSS {version}", "current supported NSS" if ver >= (3, 44) else "aging NSS")
    if lib == "wolfssl":
        if ver and ver < (4, 6):
            return _verdict(DEPRECATED, f"wolfSSL {version}", "older releases lack TLS 1.3 defaults")
        return _verdict(ALLOWED if version else UNKNOWN, "wolfSSL" + (f" {version}" if version else ""), "")
    if lib == "mbedtls":
        if ver and ver < (2, 25):
            return _verdict(DISALLOWED, f"mbedTLS {version}", "multiple CVEs; pre-2.25")
        if ver and ver < (3, 0):
            return _verdict(DEPRECATED, f"mbedTLS {version}", "2.x maintenance only")
        return _verdict(ALLOWED if version else UNKNOWN, "mbedTLS" + (f" {version}" if version else ""), "")
    if lib in {"java", "nspr", "go-crypto"}:
        return _verdict(ALLOWED, lib, "runtime-managed crypto — verify runtime patch level separately")
    return _verdict(UNKNOWN, library or "unknown", "no risk data — review manually")


def _assess_openssl(ver: tuple[int, ...] | None, *, version: str | None = None) -> dict[str, Any]:
    if ver is None:
        return _verdict(UNKNOWN, "OpenSSL", "version not exposed in filename — check `openssl version`")
    # A major-only soname ("3" -> libssl.so.3, "1" -> libcrypto.so.1) is an ABI
    # tag spanning many release lines (3.0 through 3.5 all ship libssl.so.3).
    # It cannot establish EOL, so do not verdictionary from it alone — the real
    # version must be resolved via the package manager first.
    if len(ver) == 1:
        return _verdict(
            UNKNOWN,
            f"OpenSSL (ABI soname {version})",
            f"soname libssl.so.{version} is shared by OpenSSL {version}.x release lines — resolved via package manager",
        )
    key = tuple(list(ver[:3]) + [0] * (3 - len(ver[:3])))
    # EOL applies per release line (3.0.x, 1.1.1x...): exact hit, else minor line
    eol = _OPENSSL_EOL.get(key) or _OPENSSL_EOL.get((key[0], key[1], 0))
    name = f"OpenSSL {ver[0]}.{ver[1]}.{ver[2]}" if len(ver) >= 3 else f"OpenSSL {ver[0]}.{ver[1]}"
    if eol is None:
        return _verdict(ALLOWED, name, "supported OpenSSL release")
    if key < (3, 0):
        return _verdict(
            DISALLOWED,
            name,
            f"EOL {eol} — past end of life; still negotiates TLS 1.0/1.1 and dead ciphers",
        )
    return _verdict(
        DEPRECATED,
        name,
        f"EOL {eol} — plan upgrade to a supported OpenSSL 3.x release",
    )


def _verdict(status: str, name: str, notes: str) -> dict[str, Any]:
    return {"status": status, "library_name": name, "notes": notes}
