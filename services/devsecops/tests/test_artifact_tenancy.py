"""A binary artifact belongs to a tenant: its own prefix, its own key.

The interesting claims here are negative ones — another tenant cannot read it, a
disk copy is not plaintext, a missing key is recorded rather than assumed — so the
tests state those directly instead of only checking the happy round-trip.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from devsecops import artifact_crypto as ac
from devsecops import artifact_store as store_mod


MASTER = "tenancy-test-master"


@pytest.fixture()
def storage(tmp_path, monkeypatch):
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.delenv("CRYPTOSCAN_ARTIFACT_KEY", raising=False)
    monkeypatch.setenv("SECRET_KEY", MASTER)
    return store_mod.artifact_storage()


def _scan():
    return {"target": "/srv/images/fleet", "files_walked": 2,
            "binaries": [{"path": "/srv/images/libcrypto.so.3", "format": "ELF",
                          "embedded_keys": {"private_keys": 1,
                                            "unencrypted_private_keys": 1}}],
            "libraries": [{"name": "OpenSSL", "version": "3.0.20"}],
            "findings": [], "packages": [], "limits": {}}


def _store(artifact_id: str, *, tenant_id: str | None, encryption_secret: str | None = MASTER):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [], "metadata": {}}
    cbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    return store_mod.store_binary_artifact(
        scan=_scan(), result=_scan(), bom=bom, cbom=cbom, created_by="operator",
        artifact_id=artifact_id, tenant_id=tenant_id, encryption_secret=encryption_secret)


def test_an_artifact_is_written_under_its_tenants_prefix_and_sealed(storage):
    stored = _store("11111111-1111-1111-1111-111111111111", tenant_id="acme")
    manifest = stored["manifest"]
    assert manifest["tenant_id"] == "acme"
    assert manifest["tenant_bucket"] == "acme"
    assert manifest["storage_key"].startswith("tenants/acme/")
    assert manifest["cbom_storage_key"].startswith("tenants/acme/")
    assert manifest["at_rest"]["algorithm"] == "AES-256-GCM"
    assert manifest["at_rest"]["key_id"] == ac.key_id("acme", MASTER)

    on_disk = storage.get(manifest["storage_key"])
    assert ac.is_envelope(on_disk)
    assert b"CycloneDX" not in on_disk  # the document is not sitting there in the clear

    plaintext, at_rest = store_mod.read_artifact_blob(storage, manifest, tenant_id="acme",
                                                      encryption_secret=MASTER)
    assert json.loads(plaintext)["bomFormat"] == "CycloneDX"
    assert at_rest["key_id"] == manifest["at_rest"]["key_id"]
    # the digest and the signature are over the plaintext, so verification did not change
    assert hashlib.sha256(plaintext).hexdigest() == manifest["sha256"]
    assert stored["payload_sha256"] == manifest["sha256"]


def test_the_cbom_is_sealed_with_the_same_tenant_key(storage):
    stored = _store("22222222-2222-2222-2222-222222222222", tenant_id="acme")
    manifest = stored["manifest"]
    assert b"CycloneDX" not in storage.get(manifest["cbom_storage_key"])
    cbom, at_rest = store_mod.read_artifact_cbom(storage, manifest, tenant_id="acme",
                                                 encryption_secret=MASTER)
    assert json.loads(cbom)["bomFormat"] == "CycloneDX"
    assert at_rest["algorithm"] == "AES-256-GCM"


def test_another_tenant_cannot_see_or_open_it(storage):
    stored = _store("33333333-3333-3333-3333-333333333333", tenant_id="acme")
    manifest = stored["manifest"]
    artifact_id = manifest["artifact_id"]

    assert store_mod.find_manifest(storage, artifact_id, tenant_id="globex") is None
    assert store_mod.find_manifest(storage, artifact_id, tenant_id="acme") is not None
    assert [m["artifact_id"] for m in store_mod.visible_manifests(storage, tenant_id="globex")] == []

    with pytest.raises(ac.ArtifactCryptoError) as caught:
        store_mod.read_artifact_blob(storage, manifest, tenant_id="globex", encryption_secret=MASTER)
    assert caught.value.reason == "wrong_tenant"
    assert "tenants read their own artifacts" in str(caught.value)


def test_a_tenant_only_lists_its_own_artifacts(storage):
    _store("44444444-4444-4444-4444-444444444444", tenant_id="acme")
    _store("55555555-5555-5555-5555-555555555555", tenant_id="globex")
    _store("66666666-6666-6666-6666-666666666666", tenant_id=None)  # the platform estate

    assert [m["tenant_bucket"] for m in store_mod.visible_manifests(storage, tenant_id="acme")] == ["acme"]
    assert [m["tenant_bucket"] for m in store_mod.visible_manifests(storage, tenant_id="globex")] == ["globex"]
    assert [m["tenant_bucket"] for m in store_mod.visible_manifests(storage)] == ["platform"]


def test_the_two_tenants_have_different_ciphertext_for_the_same_document(storage):
    """Same bytes, two tenants: two keys, so one leaked key does not read both."""
    first = _store("77777777-7777-7777-7777-777777777777", tenant_id="acme")
    second = _store("88888888-8888-8888-8888-888888888888", tenant_id="globex")
    acme_blob = storage.get(first["manifest"]["storage_key"])
    globex_blob = storage.get(second["manifest"]["storage_key"])
    assert ac.envelope_key_id(acme_blob) != ac.envelope_key_id(globex_blob)
    assert acme_blob != globex_blob
    # and a key rotation is visible: the same tenant, a new master, a new key id
    rotated = _store("99999999-9999-9999-9999-999999999999", tenant_id="acme",
                     encryption_secret="rotated-master")
    assert ac.envelope_key_id(storage.get(rotated["manifest"]["storage_key"])) != ac.envelope_key_id(acme_blob)


def test_without_a_key_the_artifact_is_plain_and_says_so(storage, monkeypatch):
    """No key configured is recorded, not glossed over."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_ARTIFACT_KEY", raising=False)
    stored = _store("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", tenant_id="acme",
                    encryption_secret="")
    manifest = stored["manifest"]
    assert manifest["at_rest"]["algorithm"] == "none"
    assert manifest["at_rest"]["encrypted"] is False
    assert "no CRYPTOSCAN_ARTIFACT_KEY" in manifest["at_rest"]["note"] or \
        "unencrypted" in manifest["at_rest"]["note"]
    assert b"CycloneDX" in storage.get(manifest["storage_key"])  # honestly plaintext
    plaintext, at_rest = store_mod.read_artifact_blob(storage, manifest, tenant_id="acme",
                                                      encryption_secret="")
    assert b"CycloneDX" in plaintext
    assert at_rest["algorithm"] == "none"


def test_an_artifact_written_before_tenancy_still_reads_as_the_platform_estate(storage):
    """Nothing on disk became unreadable when tenancy arrived."""
    legacy = {"artifact_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "kind": "binary",
              "target": "/srv/images/old", "created_at": "2026-01-01T00:00:00+00:00",
              "storage_key": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.cdx.json"}
    storage.put(legacy["storage_key"], b'{"bomFormat": "CycloneDX", "legacy": true}')
    storage.put_manifest(legacy["storage_key"], legacy)

    assert store_mod.manifest_tenant(legacy) == ac.PLATFORM_TENANT
    assert store_mod.find_manifest(storage, legacy["artifact_id"]) is not None
    plaintext, at_rest = store_mod.read_artifact_blob(storage, legacy, tenant_id=None,
                                                      encryption_secret=MASTER)
    assert json.loads(plaintext)["legacy"] is True
    assert at_rest["algorithm"] == "none"
    assert "plaintext on disk" in at_rest["note"]
    # but not to a tenant that never owned it
    with pytest.raises(ac.ArtifactCryptoError):
        store_mod.read_artifact_blob(storage, legacy, tenant_id="acme", encryption_secret=MASTER)


def test_at_rest_status_answers_what_a_store_would_do(storage, monkeypatch):
    status = store_mod.at_rest_status("acme")
    assert status["encrypted"] is True
    assert status["key_id"] == ac.key_id("acme", MASTER)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    unkeyed = store_mod.at_rest_status("acme")
    assert unkeyed["encrypted"] is False
    assert unkeyed["algorithm"] == "none"
    assert "CRYPTOSCAN_ARTIFACT_KEY" in unkeyed["note"]


def test_a_tenant_id_that_could_escape_its_prefix_is_refused(storage):
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        _store("cccccccc-cccc-cccc-cccc-cccccccccccc", tenant_id="../../etc")
    assert caught.value.reason == "invalid_tenant"
    # nothing was written for the refused scope, and nothing escaped the root
    assert not [p for p in storage.root.rglob("*") if "etc" in p.name]


def test_the_stored_manifest_separates_the_index_from_the_document(storage):
    """The manifest stays the readable index — that is why it is not sealed yet."""
    stored = _store("dddddddd-dddd-dddd-dddd-dddddddddddd", tenant_id="acme")
    manifest = stored["manifest"]
    assert manifest["binary_count"] == 1
    assert manifest["binary_summary"]["key_material"]["private_keys"] == 1
    written_manifest = json.loads(
        Path(storage._manifest_path(manifest["storage_key"])).read_text())
    assert written_manifest["at_rest"]["key_id"] == manifest["at_rest"]["key_id"]
    assert "components" not in written_manifest  # the document lives in the sealed blob
