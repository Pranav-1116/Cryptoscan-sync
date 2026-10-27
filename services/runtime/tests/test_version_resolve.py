"""Version resolution: soname ABI tags must never be read as release versions."""

from __future__ import annotations

from runtime.agent.version_resolve import resolve_path, _upstream
from runtime.agent.library_risk import assess_library


def test_upstream_strips_epoch_and_distro_suffix():
    assert _upstream("3.7.9-2+deb12u7") == "3.7.9"
    assert _upstream("2:1.3.0-4") == "1.3.0"
    assert _upstream("3.0.20-1~deb12u2") == "3.0.20"
    assert _upstream("not-a-version") is None


def test_unmanaged_or_unparseable_path_yields_no_version():
    # a browser's bundled lib under /opt (no package owner) -> unmanaged, no verdict basis
    info = resolve_path("/opt/chrome/libnss3.so")
    assert info["version"] is None
    assert info["source"] in {"unmanaged", "dpkg", "rpm"}
    assert resolve_path(None)["version"] is None
    assert resolve_path("")["version"] is None
    assert resolve_path("relative/path.so")["version"] is None


def test_soname_only_matches_are_unknown_not_deprecated():
    """The whole point: soname numbers are ABI tags shared across many
    releases, so they must never produce a DEPRECATED/DISALLOWED verdict."""
    # libgnutls.so.30 ships with modern GnuTLS 3.7/3.8 — soname "30.x"
    assert assess_library("gnutls", "30.40.3")["status"] == "UNKNOWN"
    assert assess_library("gnutls", "30.14")["status"] == "UNKNOWN"
    # libssl.so.3 covers OpenSSL 3.0 (EOL) AND 3.1–3.5 (current) — major only
    assert assess_library("openssl", "3")["status"] == "UNKNOWN"
    # NSS has no version in its soname
    assert assess_library("nss", None)["status"] == "UNKNOWN"


def test_resolved_real_versions_are_assessed_accurately():
    # genuinely old GnuTLS (real upstream version) stays flagged
    assert assess_library("gnutls", "3.5.18")["status"] == "DISALLOWED"
    # current GnuTLS / NSS / OpenSSL are allowed
    assert assess_library("gnutls", "3.7.9")["status"] == "ALLOWED"
    assert assess_library("nss", "3.87.1")["status"] == "ALLOWED"
    assert assess_library("openssl", "3.5.0")["status"] == "ALLOWED"
    # OpenSSL 3.0 line is nearing EOL (2026-09-07) — still flagged
    assert assess_library("openssl", "3.0.20")["status"] == "DEPRECATED"
