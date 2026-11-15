"""S3ObjectStore — bank-controlled S3-compatible bodies, same store contract.

The spec's object-storage row names the technology: "bank-controlled
S3-compatible storage or an equivalent". This pins the S3-compatible form
of the ObjectStore protocol: content-addressed keys, faithful byte
round-trips, honest absence (ContentGoneError, never a silent empty), and
total non-ownership of the connection — the injected client is the bank's.
"""
from __future__ import annotations

import hashlib
import io

import pytest

from db.storage.cas import ContentGoneError, S3ObjectStore


class NoSuchKey(Exception):
    pass


class FakeS3:
    """boto3-shaped client over a dict."""

    def __init__(self):
        self.objects: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def put_object(self, *, Bucket, Key, Body):
        self.calls.append(("put", Key))
        self.objects[(Bucket, Key)] = bytes(Body)

    def get_object(self, *, Bucket, Key):
        self.calls.append(("get", Key))
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey(f"{Key} missing")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def delete_object(self, *, Bucket, Key):
        self.calls.append(("delete", Key))
        self.objects.pop((Bucket, Key), None)


def _store():
    return S3ObjectStore(FakeS3(), "bank-evidence", prefix="cryptoscan")


class TestTheStoreContract:
    def test_bodies_round_trip_and_keys_are_content_addressed(self):
        store = _store()
        sha = hashlib.sha256(b"evidence").hexdigest()
        store.put("tenant_a", sha, b"cipher")
        assert store.get("tenant_a", sha) == b"cipher"
        keys = [k for (_op, k) in store.client.calls if _op == "put"]
        assert keys == [f"cryptoscan/tenant_a/{sha[:2]}/{sha}.bin"]

    def test_absence_raises_gone_never_empty_bytes(self):
        store = _store()
        with pytest.raises(ContentGoneError):
            store.get("tenant_a", "0" * 64)

    def test_delete_is_idempotent(self):
        store = _store()
        sha = hashlib.sha256(b"x").hexdigest()
        store.put("t", sha, b"c")
        store.delete("t", sha)
        store.delete("t", sha)  # S3 answers 204 either way
        with pytest.raises(ContentGoneError):
            store.get("t", sha)

    def test_tenants_never_share_a_key_and_tenant_ids_are_sanitized(self):
        store = _store()
        sha = hashlib.sha256(b"same-bytes").hexdigest()
        store.put("tenant_a", sha, b"cipher-a")
        store.put("tenant_b", sha, b"cipher-b")
        assert store.get("tenant_a", sha) == b"cipher-a"
        assert store.get("tenant_b", sha) == b"cipher-b"
        # a hostile tenant id cannot climb out of its prefix
        store.put("../escape", sha, b"e")
        keys = [k for (_op, k) in store.client.calls if _op == "put"]
        assert not any(".." in k for k in keys), keys

    def test_the_store_never_opens_its_own_connection(self):
        # the client is the bank's — no module-level endpoint, no embedded
        # credential, no lazy global. Ownership is visible in the constructor.
        store = S3ObjectStore(FakeS3(), "bucket")
        assert store.client is not None and store.bucket == "bucket"
        assert "endpoint" not in S3ObjectStore.__init__.__code__.co_varnames

    def test_bytes_reach_the_caller_unaltered(self):
        # the CAS layer is what hash-verifies: a corrupted body is caught
        # where the address is checked (ContentCorruptionError), not here —
        # the store's job is faithful transport.
        sha = hashlib.sha256(b"payload").hexdigest()
        store = _store()
        store.put("t", sha, b"body")
        assert store.get("t", sha) == b"body"
