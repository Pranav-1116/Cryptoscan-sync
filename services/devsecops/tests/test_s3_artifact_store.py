"""Bank-owned S3 bytes are versioned, tenant-keyed and checked by readback."""
from __future__ import annotations

import io
import json

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from devsecops.artifact_store import (
    StorageRefused, artifact_storage, find_manifest, read_artifact_blob,
    storage_status, store_binary_artifact,
)
from devsecops.s3_artifact_store import S3ArtifactStorage


class BankS3:
    def __init__(self):
        self.objects: dict[str, tuple[bytes, dict[str, str]]] = {}
        self.broken = False
        self.offline = False
        self.versioning = "Enabled"

    def head_bucket(self, **_kw):
        return {}

    def get_bucket_versioning(self, **_kw):
        return {"Status": self.versioning}

    def head_object(self, *, Key, **_kw):
        if self.offline:
            raise EndpointConnectionError(endpoint_url="https://s3.bank.internal")
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key][0])}

    def put_object(self, *, Key, Body, Metadata, IfNoneMatch, **_kw):
        if self.offline:
            raise EndpointConnectionError(endpoint_url="https://s3.bank.internal")
        if IfNoneMatch != "*" or Key in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[Key] = (bytes(Body), dict(Metadata))
        return {"VersionId": "v1"}

    def get_object(self, *, Key, **_kw):
        if self.offline:
            raise EndpointConnectionError(endpoint_url="https://s3.bank.internal")
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        data, metadata = self.objects[Key]
        if self.broken:
            data = b"X" + data[1:]
        return {"ContentLength": len(data), "Body": io.BytesIO(data), "Metadata": metadata}

    def list_objects_v2(self, **_kw):
        return {"Contents": [{"Key": key} for key in sorted(self.objects) if key.startswith("tenants/")],
                "IsTruncated": False}


@pytest.fixture()
def configured(tmp_path, monkeypatch):
    bank = BankS3()
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: bank)
    access = tmp_path / "access"
    secret = tmp_path / "secret"
    ca = tmp_path / "ca.pem"
    access.write_text("bank-local-access")
    secret.write_text("test-only-not-a-real-password")
    ca.write_text("test bank CA placeholder — no TLS socket is opened")
    monkeypatch.setenv("SBOM_S3_ENDPOINT", "https://s3.bank.internal")
    monkeypatch.setenv("SBOM_S3_BUCKET", "cryptoscan-artifacts")
    monkeypatch.setenv("SBOM_S3_ACCESS_KEY_FILE", str(access))
    monkeypatch.setenv("SBOM_S3_SECRET_KEY_FILE", str(secret))
    monkeypatch.setenv("SBOM_S3_CA_BUNDLE", str(ca))
    monkeypatch.setenv("SBOM_STORAGE_BACKUP_DIR", str(tmp_path / "bank-backup"))
    monkeypatch.setenv("SBOM_RETENTION_DAYS", "365")
    yield bank


def test_production_store_checks_versioned_bank_bucket_and_exact_bytes(configured):
    store = artifact_storage("production")
    assert isinstance(store, S3ArtifactStorage)
    key = "tenants/bank-a/artifact-1.cdx.json"
    blob = b'{"bomFormat":"CycloneDX"}'
    store.put(key, blob)
    store.put(key, blob)  # retry converges without overwriting the version
    assert store.get(key) == blob
    manifest = {"storage_key": key, "sha256": "a" * 64,
                "tenant_id": "bank-a", "tenant_bucket": "bank-a"}
    store.put_manifest(key, manifest)
    assert store.list_manifests() == [dict(manifest, storage_key=key)]
    assert storage_status("production")["root"] == "s3://cryptoscan-artifacts"
    assert storage_status("production")["verdict"] == "ALLOW"
    assert storage_status("production")["backup_verified"] is False
    assert storage_status("production")["site_qualified"] is False
    assert len(configured.objects) == 3  # probe, BOM, manifest — no duplicate retry version
    legacy_key = "tenants/bank-a/legacy.cdx.json"
    store.put_manifest(legacy_key, {"storage_key": legacy_key, "tenant_id": "bank-a"})
    assert any(row["storage_key"] == legacy_key for row in store.list_manifests())

    with pytest.raises(StorageRefused, match="different bytes"):
        store.put(key, b"changed")
    assert store.get(key) == blob
    with pytest.raises(StorageRefused, match="deletion requires"):
        store.delete(key)


def test_binary_artifact_pipeline_reads_sealed_bytes_from_bank_s3(configured):
    artifact_id = "11111111-1111-1111-1111-111111111111"
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [], "metadata": {}}
    cbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    scan = {"target": "test-only:binary", "result_state": "COMPLETE"}
    result = {"packages": [], "binaries": [], "findings": []}
    saved = store_binary_artifact(
        scan=scan, result=result, bom=bom, cbom=cbom, created_by="test-operator",
        tenant_id="bank-a", artifact_id=artifact_id, secret=(None, "unsigned"),
        encryption_secret="test-only-encryption-secret",
    )
    store = artifact_storage("production")
    manifest = find_manifest(store, artifact_id, tenant_id="bank-a")
    assert manifest is not None
    assert manifest["storage_key"] == saved["artifact_key"]
    assert find_manifest(store, artifact_id, tenant_id="bank-b") is None
    blob, _ = read_artifact_blob(store, manifest, tenant_id="bank-a",
                                 encryption_secret="test-only-encryption-secret")
    assert json.loads(blob) == bom
    assert b"CycloneDX" not in store.get(manifest["storage_key"])
    with pytest.raises(StorageRefused, match="different bytes"):
        store_binary_artifact(
            scan=scan, result=result, bom=bom, cbom=cbom, created_by="test-operator",
            tenant_id="bank-a", artifact_id=artifact_id, secret=(None, "unsigned"),
            encryption_secret="test-only-encryption-secret",
        )
    assert find_manifest(store, artifact_id, tenant_id="bank-a") == manifest


def test_tenant_keys_and_manifest_identity_are_not_inferred(configured):
    store = artifact_storage("production")
    for key in ("../escape", "tenants/bank-a/../bank-b/x", "tenants//x", "evidence/x"):
        with pytest.raises(StorageRefused, match="tenant-prefixed"):
            store.put(key, b"x")
    with pytest.raises(StorageRefused, match="identity does not match"):
        store.put_manifest("tenants/bank-a/x", {"storage_key": "tenants/bank-b/x",
                                                 "tenant_id": "bank-a", "tenant_bucket": "bank-a"})
    with pytest.raises(StorageRefused, match="identity does not match"):
        store.put_manifest("tenants/bank-a/x", {"storage_key": "tenants/bank-a/x",
                                                 "tenant_id": "bank-b", "tenant_bucket": "bank-b"})
    configured.broken = True
    with pytest.raises(StorageRefused, match="SHA-256"):
        store.probe()


def test_unversioned_or_unbacked_bucket_is_never_production_evidence(configured, monkeypatch):
    configured.versioning = "Suspended"
    assert storage_status("production")["verdict"] == "REFUSE"
    with pytest.raises(StorageRefused, match="versioning"):
        artifact_storage("production")
    configured.versioning = "Enabled"
    monkeypatch.delenv("SBOM_STORAGE_BACKUP_DIR")
    assert storage_status("production")["verdict"] == "REFUSE"
    with pytest.raises(StorageRefused, match="backup"):
        artifact_storage("production")


def test_external_plain_http_and_secret_symlink_fail_before_s3_connection(tmp_path, configured, monkeypatch):
    monkeypatch.setenv("SBOM_S3_ENDPOINT", "http://s3.bank.internal")
    with pytest.raises(StorageRefused, match="HTTPS"):
        artifact_storage("production")
    monkeypatch.setenv("SBOM_S3_ENDPOINT", "https://s3.bank.internal")
    link = tmp_path / "linked-secret"
    link.symlink_to(tmp_path / "secret")
    monkeypatch.setenv("SBOM_S3_SECRET_KEY_FILE", str(link))
    with pytest.raises(StorageRefused, match="linked"):
        artifact_storage("production")
    monkeypatch.setenv("SBOM_S3_SECRET_KEY_FILE", str(tmp_path / "secret"))
    monkeypatch.setenv("SBOM_S3_ENDPOINT", "https://[broken")
    assert storage_status("production")["verdict"] == "REFUSE"


def test_transport_failure_is_a_storage_refusal_not_a_false_status(configured):
    store = artifact_storage("production")
    key = "tenants/bank-a/artifact-1.cdx.json"
    store.put(key, b"first")
    configured.offline = True
    with pytest.raises(StorageRefused, match="identity could not be checked"):
        store.put(key, b"second")
    with pytest.raises(StorageRefused, match="read failed"):
        store.get(key)
    status = storage_status("production")
    assert status["verdict"] == "REFUSE"
    assert status["integrity_verified"] is False
    with pytest.raises(StorageRefused):
        artifact_storage("production")


def test_corrupt_manifest_refuses_listing_instead_of_hiding_it(configured):
    store = artifact_storage("production")
    key = "tenants/bank-a/artifact-1.cdx.json"
    store.put_manifest(key, {"storage_key": key, "tenant_id": "bank-a", "tenant_bucket": "bank-a"})
    raw, metadata = configured.objects[key + ".manifest.json"]
    configured.objects[key + ".manifest.json"] = (json.dumps({"storage_key": "tenants/bank-b/other"}).encode(), metadata)
    with pytest.raises(StorageRefused):
        store.list_manifests()
