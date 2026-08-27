"""Enterprise CBOM behaviour: key rotation, fail-closed signing, verify
reports, and deep structural validation."""

from __future__ import annotations

import pytest

from cbom.config.settings import Settings, load_settings, parse_retired_secrets
from cbom.generator import CbomGenerator
from cbom.signing.key_manager import KeyManager
from cbom.validator import deep_validate, validate_cbom

SECRET_OLD = "old-signing-secret-" + "a" * 16
SECRET_NEW = "new-signing-secret-" + "b" * 16


def _bom() -> dict:
    return CbomGenerator().from_records(
        [{"algorithm": "AES", "file_path": "x/a.java", "line_number": 1, "finding_id": "f1"}],
        name="svc",
    )


# --------------------------------------------------------------------------- #
# Key rotation (kid-aware signing + verification)
# --------------------------------------------------------------------------- #

def test_sign_embeds_kid_header():
    signed = CbomGenerator().sign(_bom(), SECRET_NEW, key_id="k2026")
    jws = _jws_of(signed)
    header = _header_of(jws)
    assert header["kid"] == "k2026"
    assert header["alg"] == "HS256"


def test_rotation_old_cbom_still_verifies_via_keyring():
    generator = CbomGenerator()
    old_bom = generator.sign(_bom(), SECRET_OLD, key_id="k2025")
    new_bom = generator.sign(_bom(), SECRET_NEW, key_id="k2026")
    keyring = {"k2025": SECRET_OLD, "k2026": SECRET_NEW}
    assert generator.verify(old_bom, keyring)
    assert generator.verify(new_bom, keyring)
    # Single-secret verification of the OLD bom with the NEW key must fail.
    assert not generator.verify(old_bom, SECRET_NEW)


def test_unknown_kid_is_reported_not_swallowed():
    signed = CbomGenerator().sign(_bom(), SECRET_NEW, key_id="ghost")
    report = CbomGenerator().verify_report(signed, {"k2026": SECRET_NEW})
    assert report["ok"] is False
    assert "unknown key id" in (report["error"] or "")
    assert report["key_id"] == "ghost"


def test_key_manager_rotation_flow(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", SECRET_NEW)
    monkeypatch.setenv("CRYPTOSCAN_CBOM_KEY_ID", "k2026")
    monkeypatch.setenv("ENVIRONMENT", "development")
    manager = KeyManager(retired={"k2025": SECRET_OLD})
    signed_now = manager.sign(_bom())
    assert _header_of(_jws_of(signed_now))["kid"] == "k2026"
    assert manager.verify(signed_now)

    signed_before = CbomGenerator().sign(_bom(), SECRET_OLD, key_id="k2025")
    assert manager.verify(signed_before), "retired key must keep verifying old CBOMs"


def test_verify_report_structure_and_tamper_detection():
    generator = CbomGenerator()
    signed = generator.sign(_bom(), SECRET_NEW)
    report = generator.verify_report(signed, SECRET_NEW)
    assert report["ok"] is True
    assert report["algorithm"] == "JWS-HS256"
    assert [c["name"] for c in report["checks"]] == [
        "jws_format",
        "algorithm",
        "key_resolution",
        "signature",
        "payload_matches_bom",
    ]

    tampered = generator.sign(_bom(), SECRET_NEW)
    tampered["components"].append(dict(tampered["components"][0], name="Injected-3DES"))
    tamper_report = generator.verify_report(tampered, SECRET_NEW)
    assert tamper_report["ok"] is False
    assert tamper_report["error"]
    assert any(c["name"] == "payload_matches_bom" and not c["ok"] for c in tamper_report["checks"])


def test_malformed_jws_reported():
    bom = _bom()
    bom.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "cryptoscan:jws", "value": "not-a-jws"}
    )
    report = CbomGenerator().verify_report(bom, SECRET_NEW)
    assert report["ok"] is False
    assert "malformed JWS" in (report["error"] or "")


# --------------------------------------------------------------------------- #
# Fail-closed key management
# --------------------------------------------------------------------------- #

def test_production_without_secret_fails_closed(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_CBOM_SECRET", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(Exception, match="ephemeral"):
        KeyManager()


def test_development_allows_ephemeral_with_warning():

    manager = KeyManager(environment="development", secret=None)  # type: ignore[arg-type]
    assert manager.ephemeral is True
    # Ephemeral key signs and verifies within the process.
    signed = manager.sign(_bom())
    assert manager.verify(signed)


def test_settings_production_gate():
    with pytest.raises(Exception, match="CRYPTOSCAN_CBOM_SECRET"):
        Settings(sign=True, secret="", environment="production").validate_for_production()
    with pytest.raises(Exception, match="KEY_ID"):
        Settings(sign=True, secret="x" * 40, key_id="", environment="production").validate_for_production()
    Settings(sign=True, secret="x" * 40, key_id="k1", environment="production").validate_for_production()
    # Non-signing production needs no key.
    Settings(sign=False, secret="", environment="production").validate_for_production()


def test_parse_retired_secrets():
    assert parse_retired_secrets("k1: s1 , k2:s2 ;") == {"k1": "s1", "k2": "s2"}
    assert parse_retired_secrets("") == {}
    assert parse_retired_secrets("garbage,no-colon") == {}


def test_load_settings_reads_environment(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SIGN", "true")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", "s")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_KEY_ID", "k1")
    monkeypatch.setenv("CRYPTOSCAN_CBOM_RETIRED_SECRETS", "old:sec1")
    settings = load_settings()
    assert settings.sign and settings.secret == "s"
    assert settings.key_id == "k1"
    assert settings.retired_secrets == {"old": "sec1"}


# --------------------------------------------------------------------------- #
# Deep structural validation
# --------------------------------------------------------------------------- #

def _valid_bom() -> dict:
    bom = CbomGenerator().from_records(
        [{"algorithm": "AES", "file_path": "x/a.java", "line_number": 1, "finding_id": "f1"}],
        name="svc",
    )
    return bom


def test_deep_validate_accepts_generator_output():
    result = deep_validate(_valid_bom())
    assert result["ok"], result["errors"]


def test_deep_validate_catches_bad_serial_and_version():
    bom = _valid_bom()
    bom["serialNumber"] = "not-a-urn"
    bom["version"] = 0
    result = deep_validate(bom)
    assert any("serialNumber" in e for e in result["errors"])
    assert any("version" in e for e in result["errors"])


def test_deep_validate_catches_duplicate_bom_refs():
    bom = _valid_bom()
    if bom["components"]:
        clone = dict(bom["components"][0])
        bom["components"].append(clone)  # same bom-ref twice
    result = deep_validate(bom)
    assert any("duplicate bom-ref" in e for e in result["errors"])


def test_deep_validate_catches_dangling_dependency_refs():
    bom = _valid_bom()
    bom["dependencies"] = [{"ref": "urn:does-not-exist", "dependsOn": ["also-missing"]}]
    result = deep_validate(bom)
    dangling = [e for e in result["errors"] if "unknown bom-ref" in e]
    assert len(dangling) == 2


def test_deep_validate_catches_malformed_jws_property():
    bom = _valid_bom()
    bom.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "cryptoscan:jws", "value": "two.segments"}
    )
    result = deep_validate(bom)
    assert any("cryptoscan:jws is malformed" in e for e in result["errors"])


def test_deep_validate_flags_sparse_crypto_properties_as_warning():
    bom = _valid_bom()
    for component in bom["components"]:
        component["cryptoProperties"] = {"assetType": "algorithm"}
        break
    bom["components"].append(
        {"name": "sparse", "type": "library", "bom-ref": "ref-sparse", "cryptoProperties": {"assetType": "algorithm"}}
    )
    result = deep_validate(bom)
    assert result["ok"], result["errors"]  # warnings, not errors
    assert any("lacks oid" in w for w in result["warnings"])


def test_validate_cbom_merges_layers():
    bom = _valid_bom()
    bom["bomFormat"] = "Wrong"
    bom["serialNumber"] = "bad"
    result = validate_cbom(bom)
    assert result["ok"] is False
    assert any("bomFormat" in e for e in result["errors"])  # schema layer
    assert any("serialNumber" in e for e in result["errors"])  # deep layer
    assert "warnings" in result


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _jws_of(bom: dict) -> str:
    props = (bom.get("metadata") or {}).get("properties") or []
    for item in props:
        if item.get("name") == "cryptoscan:jws":
            return str(item.get("value"))
    raise AssertionError("no jws property")


def _header_of(jws: str) -> dict:
    import base64
    import json

    header_b64 = jws.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
