"""Encryption at rest for stored scan artifacts, keyed per tenant."""

from __future__ import annotations

import os

import pytest

from devsecops import artifact_crypto as ac


MASTER = "unit-test-master-secret"


def test_encryption_round_trips_and_never_writes_the_plaintext():
    payload = b'{"components": ["libcrypto.so.3"], "keys": 1}'
    blob, report = ac.encrypt_blob(payload, tenant_id="acme", secret=MASTER)
    assert report["algorithm"] == "AES-256-GCM"
    assert report["encrypted"] is True
    assert report["key_source"] == "explicit"
    assert payload not in blob  # the point of the exercise
    assert blob.startswith(ac.ENVELOPE_MAGIC)
    assert ac.envelope_key_id(blob) == report["key_id"]

    plaintext, back = ac.decrypt_blob(blob, tenant_id="acme", secret=MASTER)
    assert plaintext == payload
    assert back["key_id"] == report["key_id"]
    assert back["encrypted"] is True


def test_identical_payloads_produce_different_bytes():
    """A random nonce per object: a dump of one tenant's artifacts is not a dictionary."""
    first, _ = ac.encrypt_blob(b"same bytes", tenant_id="acme", secret=MASTER)
    second, _ = ac.encrypt_blob(b"same bytes", tenant_id="acme", secret=MASTER)
    assert first != second
    assert ac.decrypt_blob(first, tenant_id="acme", secret=MASTER)[0] == b"same bytes"
    assert ac.decrypt_blob(second, tenant_id="acme", secret=MASTER)[0] == b"same bytes"


def test_a_tenant_key_is_stable_and_distinct_per_tenant():
    acme = ac.key_id("acme", MASTER)
    assert acme == ac.key_id("acme", MASTER)  # restart-stable: derived, not random
    assert acme != ac.key_id("globex", MASTER)
    assert acme.startswith(ac.KEY_ID_PREFIX)
    assert len(acme) == len(ac.KEY_ID_PREFIX) + 16
    # an empty tenant is the platform estate, not a wildcard
    assert ac.key_id(None, MASTER) == ac.key_id("", MASTER) == ac.key_id("platform", MASTER)


def test_another_tenant_cannot_read_the_object_and_is_told_why():
    blob, _ = ac.encrypt_blob(b"acme's inventory", tenant_id="acme", secret=MASTER)
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(blob, tenant_id="globex", secret=MASTER)
    assert caught.value.reason == "wrong_key"
    assert ac.key_id("acme", MASTER) in str(caught.value)
    assert "tenant reads its own artifacts only" in str(caught.value)


def test_tampering_is_detected_not_decrypted():
    blob, _ = ac.encrypt_blob(b"unsigned plaintext inventory", tenant_id="acme", secret=MASTER)
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(tampered, tenant_id="acme", secret=MASTER)
    assert caught.value.reason == "tampered"
    # the header is authenticated too: relabelling the object as another tenant's
    # key does not make it readable under that key
    rest = blob[len(ac.ENVELOPE_MAGIC):]
    nonce_and_ct = rest.split(b"\n", 1)[1]
    swapped = b"".join([ac.ENVELOPE_MAGIC, ac.key_id("globex", MASTER).encode(), b"\n", nonce_and_ct])
    assert ac.envelope_key_id(swapped) == ac.key_id("globex", MASTER)
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(swapped, tenant_id="globex", secret=MASTER)
    assert caught.value.reason == "tampered"


def test_a_rotated_master_secret_is_reported_as_such():
    blob, _ = ac.encrypt_blob(b"before the rotation", tenant_id="acme", secret=MASTER)
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(blob, tenant_id="acme", secret="rotated-master")
    # a different master derives a different key id, so this is caught before decryption
    assert caught.value.reason == "wrong_key"


def test_encrypted_objects_need_key_material_to_be_opened():
    blob, _ = ac.encrypt_blob(b"secret", tenant_id="acme", secret=MASTER)
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(blob, tenant_id="acme", secret="")
    assert caught.value.reason == "no_key"
    assert "CRYPTOSCAN_ARTIFACT_KEY" in str(caught.value)


def test_without_key_material_objects_are_stored_plain_and_say_so():
    """No key configured is a stated fact, not a silent downgrade."""
    blob, report = ac.encrypt_blob(b"plain", tenant_id="acme", secret="")
    assert blob == b"plain"
    assert report["algorithm"] == "none"
    assert report["encrypted"] is False
    assert "no CRYPTOSCAN_ARTIFACT_KEY" in report["note"]


def test_legacy_plaintext_objects_stay_readable():
    """Artifacts written before at-rest encryption existed are not lost."""
    plaintext, report = ac.decrypt_blob(b'{"old": true}', tenant_id="acme", secret=MASTER)
    assert plaintext == b'{"old": true}'
    assert report["algorithm"] == "none"
    assert report["encrypted"] is False
    assert "plaintext on disk" in report["note"]


def test_a_truncated_envelope_is_malformed_not_empty():
    blob, _ = ac.encrypt_blob(b"data", tenant_id="acme", secret=MASTER)
    with pytest.raises(ac.ArtifactCryptoError) as caught:
        ac.decrypt_blob(blob[: len(ac.ENVELOPE_MAGIC) + 4], tenant_id="acme", secret=MASTER)
    assert caught.value.reason == "malformed"


def test_the_master_secret_order_is_explicit_then_dedicated_then_platform(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_ARTIFACT_KEY", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert ac.resolve_master_secret() == (None, "none")
    monkeypatch.setenv("SECRET_KEY", "platform-master")
    assert ac.resolve_master_secret() == ("platform-master", "env:SECRET_KEY")
    monkeypatch.setenv("CRYPTOSCAN_ARTIFACT_KEY", "dedicated-at-rest")
    assert ac.resolve_master_secret() == ("dedicated-at-rest", "env:CRYPTOSCAN_ARTIFACT_KEY")
    assert ac.resolve_master_secret("passed-in") == ("passed-in", "explicit")


def test_the_environment_secret_is_what_an_unconfigured_call_uses(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_ARTIFACT_KEY", "env-secret")
    blob, report = ac.encrypt_blob(b"from the environment", tenant_id="acme")
    assert report["key_source"] == "env:CRYPTOSCAN_ARTIFACT_KEY"
    assert ac.decrypt_blob(blob, tenant_id="acme")[0] == b"from the environment"
    assert "env-secret" not in blob.decode("utf-8", "replace")
    monkeypatch.delenv("CRYPTOSCAN_ARTIFACT_KEY")
    assert os.environ.get("CRYPTOSCAN_ARTIFACT_KEY") is None


def test_a_tenant_id_that_could_escape_its_scope_is_refused():
    for bad in ("../other", "acme/../globex", "acme/globex", "-leading-dash", "a" * 65):
        with pytest.raises(ac.ArtifactCryptoError) as caught:
            ac.normalize_tenant(bad)
        assert caught.value.reason == "invalid_tenant"
    assert ac.normalize_tenant("acme-bank.eu_1") == "acme-bank.eu_1"
    # blank is not an escape attempt: it is the platform estate
    assert ac.normalize_tenant("   ") == ac.PLATFORM_TENANT


def test_the_at_rest_report_names_the_key_without_revealing_it():
    report = ac.at_rest_report("acme", MASTER)
    assert report == {"tenant": "acme", "algorithm": "AES-256-GCM", "key_source": "explicit",
                      "encrypted": True, "key_id": ac.key_id("acme", MASTER)}
    unkeyed = ac.at_rest_report("acme", "")
    assert unkeyed["algorithm"] == "none"
    assert "key_id" not in unkeyed
    assert MASTER not in str(report)
