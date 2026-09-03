"""Deterministic plugin marketplace tests: pinning, signing, quarantine."""

from __future__ import annotations

import base64

import pytest
from marketplace.manifest import ManifestError, PluginManifest
from marketplace.registry import (
    InstalledPlugin,
    PluginState,
    decide_state,
    is_newer,
    select_enable_target,
)
from marketplace.verify import (
    content_digest,
    platform_supports,
    sign_plugin,
    verify_plugin,
)

pytest.importorskip("cryptography", reason="Ed25519 requires the cryptography backend")
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,  # noqa: E402
)


def _key_pair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv, base64.b64encode(pub).decode()


def _manifest(**overrides):
    base = {
        "plugin_id": "zelnx.pqc-rules",
        "version": "1.2.0",
        "plugin_type": "ruleset",
        "name": "PQC ruleset",
        "content_sha256": "",
        "min_platform": "1.0.0",
    }
    base.update(overrides)
    return base


def _signed_bundle(plugin_type="scanner"):
    priv, pub_b64 = _key_pair()
    content = b"def scan(): return []"
    m = PluginManifest.from_dict(
        _manifest(plugin_type=plugin_type, content_sha256=content_digest(content))
    )
    sig = sign_plugin(priv, m)
    return m, content, sig, "authority-1", f"authority-1:{pub_b64}"


# ------------------------------------------------------------ manifest
def test_manifest_requires_fields_and_semver():
    with pytest.raises(ManifestError):
        PluginManifest.from_dict(_manifest(version="latest"))
    with pytest.raises(ManifestError):
        PluginManifest.from_dict(_manifest(plugin_id="BAD ID"))
    with pytest.raises(ManifestError):
        PluginManifest.from_dict(_manifest(plugin_type="neural-net"))
    with pytest.raises(ManifestError):
        PluginManifest.from_dict(_manifest(content_sha256="notahex"))


def test_manifest_accepts_valid():
    m = PluginManifest.from_dict(_manifest(content_sha256="a" * 64))
    assert m.plugin_id == "zelnx.pqc-rules"
    assert m.is_executable is False


# ------------------------------------------------------------ pinning
def test_content_pin_tamper_detected():
    m, content, sig, kid, trust = _signed_bundle("scanner")
    tampered = content + b" "
    res = verify_plugin(m, tampered, trusted_keys=[trust], signature=sig, signer_key_id=kid)
    assert res.ok is False
    assert "content_sha256 mismatch" in res.reason


def test_data_plugin_unsigned_is_ok():
    content = b"rules: [DES->AES]"
    m = PluginManifest.from_dict(_manifest(plugin_type="ruleset", content_sha256=content_digest(content)))
    res = verify_plugin(m, content)
    assert res.ok is True
    assert res.trusted is False


# ------------------------------------------------------------ signing
def test_executable_plugin_must_be_signed():
    content = b"code"
    m = PluginManifest.from_dict(
        _manifest(plugin_type="scanner", content_sha256=content_digest(content))
    )
    res = verify_plugin(m, content)  # no signature
    assert res.ok is False
    assert "not signed" in res.reason


def test_executable_plugin_signed_by_trusted_authority_passes():
    m, content, sig, kid, trust = _signed_bundle("scanner")
    res = verify_plugin(m, content, trusted_keys=[trust], signature=sig, signer_key_id=kid)
    assert res.ok is True
    assert res.trusted is True
    assert res.signer_key_id == kid


def test_executable_plugin_signed_by_untrusted_key_quarantined():
    m, content, sig, kid, _trust = _signed_bundle("scanner")
    # a *different* key pair is the only trusted authority
    _priv2, pub2 = _key_pair()
    res = verify_plugin(
        m, content, trusted_keys=[f"authority-other:{pub2}"], signature=sig, signer_key_id=kid
    )
    assert res.ok is False
    assert "not in the pinned trust set" in res.reason


def test_corrupted_signature_fails():
    m, content, _sig, kid, trust = _signed_bundle("scanner")
    res = verify_plugin(m, content, trusted_keys=[trust], signature="AAAA", signer_key_id=kid)
    assert res.ok is False
    assert "signature verification failed" in res.reason


def test_platform_version_gate():
    content = b"x"
    m = PluginManifest.from_dict(
        _manifest(plugin_type="ruleset", min_platform="5.0.0", content_sha256=content_digest(content))
    )
    assert platform_supports(m, "5.0.0") is True
    assert platform_supports(m, "4.9.9") is False
    res = verify_plugin(m, content, platform_version="4.0.0")
    assert res.ok is False
    assert "platform" in res.reason


# ------------------------------------------------------------ registry state
def test_decide_state_fail_closed():
    m = PluginManifest.from_dict(_manifest(plugin_type="scanner", content_sha256="a" * 64))
    # failed verification always quarantines, even if operator wanted to enable
    assert decide_state(m, verified_ok=False, trusted=False, operator_enable=True) is PluginState.QUARANTINED
    # executable but not trusted -> quarantine
    assert decide_state(m, verified_ok=True, trusted=False, operator_enable=True) is PluginState.QUARANTINED
    # verified + trusted + enable -> ENABLED
    assert decide_state(m, verified_ok=True, trusted=True, operator_enable=True) is PluginState.ENABLED
    # verified but not enabled -> VERIFIED
    assert decide_state(m, verified_ok=True, trusted=True, operator_enable=False) is PluginState.VERIFIED


def test_is_newer_and_select_target():
    assert is_newer("1.3.0", "1.2.9") is True
    assert is_newer("1.2.0", "1.2.0") is False
    assert is_newer("2.0.0", None) is True

    def plug(ver, state):
        m = PluginManifest.from_dict(_manifest(version=ver, content_sha256="a" * 64))
        return InstalledPlugin(manifest=m, state=state, trusted=True, signer_key_id="k")

    cands = [plug("1.0.0", PluginState.ENABLED), plug("1.5.0", PluginState.VERIFIED),
             plug("2.0.0", PluginState.QUARANTINED)]
    target = select_enable_target(cands, "zelnx.pqc-rules")
    assert target.manifest.version == "1.5.0"  # quarantined 2.0.0 is never selected
