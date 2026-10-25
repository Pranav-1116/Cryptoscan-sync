"""Synthetic local OCI metadata fixtures, no image pull/layer/runtime witness."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import pytest
from pydantic import ValidationError
from inventory.host import collect
from inventory.collection import OfflineOciMetadataCollector, OfflineLinuxCollector
from shared_models.host_collection import HostManifest, HostInput, HostSnapshot, digest
from shared_models.collection import TargetSpec
from shared_models.oci_image import MANIFEST_TYPE, CONFIG_TYPE, image_resource
from shared_models.host_runtime import domains


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def layout(tmp_path, change=None, arch="amd64", variant=None):
    root = tmp_path / "oci"
    (root / "blobs/sha256").mkdir(parents=True)
    config = {
        "architecture": arch,
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]},
        "config": {"ExposedPorts": {"443/tcp": {}}, "Env": ["DO_NOT_EXPORT=fixture-value"], "Cmd": ["not-executed"]},
    }
    if variant:
        config["variant"] = variant
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": {},
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:" + "b" * 64,
                "size": 1234567890,
            }
        ],
    }
    if change:
        change(config, manifest)
    config_raw = raw(config)
    cs = hashlib.sha256(config_raw).hexdigest()
    manifest["config"] = {"mediaType": CONFIG_TYPE, "digest": "sha256:" + cs, "size": len(config_raw)}
    mraw = raw(manifest)
    ms = hashlib.sha256(mraw).hexdigest()
    (root / "oci-layout").write_bytes(raw({"imageLayoutVersion": "1.0.0"}))
    (root / "blobs/sha256" / cs).write_bytes(config_raw)
    (root / "blobs/sha256" / ms).write_bytes(mraw)
    descriptor = {
        "mediaType": MANIFEST_TYPE,
        "digest": "sha256:" + ms,
        "size": len(mraw),
        "platform": {"os": "linux", "architecture": arch, **({"variant": variant} if variant else {})},
    }
    (root / "index.json").write_bytes(raw({"schemaVersion": 2, "manifests": [descriptor]}))
    resource = (
        f"oci-layout://local/linux/{arch}" + ("/" + variant if variant else "") + f"/manifest/sha256/{ms}/root{root}"
    )
    scope = HostManifest(
        approval_reference="fixture/oci-reviewed",
        host_id="fixture-oci-artifact",
        environment="test",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[HostInput(input_id="image", kind="OCI_IMAGE_METADATA", path=resource)],
    )
    return root, scope


def target(scope):
    return TargetSpec(
        target_key="reviewed-oci",
        system_id="system-a",
        environment="test",
        owner="Fixture owner",
        collection_method="container",
        address="offline-reviewed-layout",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=datetime.now(timezone.utc) - timedelta(minutes=1),
        manifest=scope,
    )


@pytest.mark.parametrize("arch,variant", [("amd64", None), ("arm64", None), ("arm64", "v8")])
def test_pinned_metadata_without_layers_runtime_or_secrets(tmp_path, arch, variant):
    root, scope = layout(tmp_path, arch=arch, variant=variant)
    result = OfflineOciMetadataCollector().collect(target(scope))
    r = result.receipts[0]
    assert r.status == "PARSED", r
    fact = r.facts[0]
    assert fact.interface_sha256 == r.content_sha256 and domains(fact) == ["SBOM", "TechBOM"]
    assert fact.declared_ports == ["443/tcp"] and fact.configuration_basis == "DECLARED"
    assert fact.algorithm == fact.runtime_use == fact.operation_use == fact.pqc_assessment == "UNKNOWN"
    assert (
        fact.layer_contents_verified
        is fact.filesystem_materialized
        is fact.package_inventory_verified
        is fact.deployment_verified
        is False
    )
    assert not (root / "blobs/sha256" / ("b" * 64)).exists()  # No layer content was needed or verified.
    assert "DO_NOT_EXPORT" not in result.model_dump_json() and "not-executed" not in result.model_dump_json()
    assert r.byte_count > 2 * sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    HostSnapshot.model_validate(result.model_dump(mode="json"))


@pytest.mark.parametrize(
    "change",
    [
        lambda c, m: c.update(os="windows"),
        lambda c, m: c.update(architecture="386"),
        lambda c, m: c.update(rootfs={"type": "layers", "diff_ids": []}),
        lambda c, m: c.update(rootfs={"type": "layers", "diff_ids": ["md5:bad"]}),
        lambda c, m: c["config"].update(ExposedPorts={"0/tcp": {}}),
        lambda c, m: c["config"].update(ExposedPorts={"65536/tcp": {}}),
        lambda c, m: c["config"].update(ExposedPorts={"0443/tcp": {}}),
        lambda c, m: c["config"].update(ExposedPorts={"443/tcp": {"execute": True}}),
        lambda c, m: m.update(subject={"digest": "sha256:" + "c" * 64}),
        lambda c, m: m.update(artifactType="attestation"),
        lambda c, m: m.update(schemaVersion=True),
        lambda c, m: m["layers"][0].update(urls=["https://forbidden.invalid/layer"]),
        lambda c, m: m["layers"][0].update(data="embedded"),
        lambda c, m: m["layers"][0].update(mediaType="application/octet-stream"),
        lambda c, m: m["layers"][0].update(size=True),
        lambda c, m: m.update(annotations={"org.opencontainers.image.base.digest": "not-a-digest"}),
    ],
)
def test_malformed_metadata_is_gap_not_empty_image(tmp_path, change):
    _, scope = layout(tmp_path, change)
    receipt = collect(scope).receipts[0]
    assert receipt.status == "INVALID" and receipt.facts == [] and receipt.content_sha256 is None, receipt


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "manifest-hash",
        "config-hash",
        "descriptor-size",
        "platform",
        "duplicate",
        "index-json",
        "deep-json",
        "symlink",
        "hardlink",
        "parent-link",
        "index-changed",
    ],
)
def test_source_failure_never_selects_first_or_falls_back(tmp_path, monkeypatch, mode):
    root, scope = layout(tmp_path)
    index = json.loads((root / "index.json").read_bytes())
    desc = index["manifests"][0]
    if mode == "missing":
        (root / "blobs/sha256" / desc["digest"][7:]).unlink()
    elif mode == "manifest-hash":
        (root / "blobs/sha256" / desc["digest"][7:]).write_bytes(b"{}")
    elif mode == "config-hash":
        manifest = json.loads((root / "blobs/sha256" / desc["digest"][7:]).read_bytes())
        (root / "blobs/sha256" / manifest["config"]["digest"][7:]).write_bytes(b"{}")
    elif mode == "descriptor-size":
        desc["size"] += 1
    elif mode == "platform":
        desc["platform"]["architecture"] = "arm64"
    elif mode == "duplicate":
        index["manifests"].append(desc.copy())
    elif mode == "index-json":
        (root / "index.json").write_text('{"schemaVersion":2,"schemaVersion":2}')
    elif mode == "deep-json":
        (root / "index.json").write_text("[" * 25 + "0" + "]" * 25)
    elif mode in {"symlink", "hardlink"}:
        moved = tmp_path / "layout-original"
        (root / "oci-layout").rename(moved)
        if mode == "symlink":
            (root / "oci-layout").symlink_to(moved)
        else:
            import os

            os.link(moved, root / "oci-layout")
    elif mode == "parent-link":
        blobs = root / "blobs"
        moved = root / "real-blobs"
        blobs.rename(moved)
        blobs.symlink_to(moved, target_is_directory=True)
    elif mode == "index-changed":
        import inventory.host as host

        read = host._read
        calls = []

        def changing(path, *args):
            data = read(path, *args)
            if path.endswith("/index.json"):
                calls.append(path)
                if len(calls) == 1:
                    (root / "index.json").write_bytes(raw({**index, "annotations": {"change": "fixture"}}))
            return data

        monkeypatch.setattr(host, "_read", changing)
    if mode in {"descriptor-size", "platform", "duplicate"}:
        (root / "index.json").write_bytes(raw(index))
    receipt = collect(scope).receipts[0]
    assert receipt.status != "PARSED" and not receipt.facts and receipt.content_sha256 is None, receipt


@pytest.mark.parametrize("mode", ["budget", "total", "expired", "elevated", "wrong-platform"])
def test_guards_before_source_io(tmp_path, monkeypatch, mode):
    _, scope = layout(tmp_path)
    import inventory.host as host

    reads = []
    read = host._read
    monkeypatch.setattr(host, "_read", lambda *a: (reads.append(a[0]), read(*a))[1])
    if mode == "budget":
        scope = scope.model_copy(update={"max_file_bytes": 1})
    if mode == "total":
        scope = scope.model_copy(update={"max_total_bytes": 1})
    if mode == "expired":
        scope = scope.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    if mode == "elevated":
        monkeypatch.setattr(host, "elevated", lambda: True)
    if mode == "wrong-platform":
        scope = scope.model_copy(update={"platform": "windows"})
    receipt = collect(scope).receipts[0]
    assert receipt.status != "PARSED" and not receipt.facts
    if mode in {"expired", "elevated", "wrong-platform"}:
        assert not reads


@pytest.mark.parametrize("suffix", ["/", "?pull=1", "/../other", "%2Ffoo"])
def test_noncanonical_resource(tmp_path, suffix):
    _, scope = layout(tmp_path)
    with pytest.raises(ValidationError):
        HostInput(input_id="image", kind="OCI_IMAGE_METADATA", path=scope.inputs[0].path + suffix)


@pytest.mark.parametrize(
    "field,value",
    [
        ("algorithm", "RSA"),
        ("layer_contents_verified", True),
        ("package_inventory_verified", True),
        ("deployment_verified", True),
        ("interface_sha256", "0" * 64),
        ("identity_key", "running-container"),
        ("manifest_sha256", "0" * 64),
        ("declared_ports", ["0443/tcp"]),
        ("vendor", "guessed"),
    ],
)
def test_snapshot_tamper_and_promotions_refuse(tmp_path, field, value):
    _, scope = layout(tmp_path)
    snapshot = collect(scope).model_dump(mode="json")
    snapshot["receipts"][0]["facts"][0][field] = value
    with pytest.raises(ValidationError):
        HostSnapshot.model_validate(snapshot)


def test_not_admitted_by_linux_adapter_and_health_does_not_claim_qualification(tmp_path):
    _, scope = layout(tmp_path)
    with pytest.raises(ValueError):
        OfflineLinuxCollector().collect(target(scope).model_copy(update={"collection_method": "offline_host"}))
    health = OfflineOciMetadataCollector().health()
    assert (
        health["production_execution_qualified"]
        is health["server_execution"]
        is health["layer_contents_verified"]
        is False
    )


def test_existing_metadata_parser_explicit_selector_and_cli(tmp_path):
    from container_scanner.image.image_metadata_parser import parse_oci_index

    root, scope = layout(tmp_path)
    _, _, _, manifest = image_resource(scope.inputs[0].path)
    assert parse_oci_index(root / "index.json", manifest_digest="sha256:" + manifest)["digest"] == manifest
    with pytest.raises(ValueError):
        parse_oci_index(root / "index.json", manifest_digest="sha256:" + "0" * 64)
    path = tmp_path / "target.json"
    path.write_bytes(raw(target(scope).model_dump(mode="json")))
    output = tmp_path / "snapshot.json"
    command = [
        sys.executable,
        str(Path(__file__).resolve().parents[3] / "scripts/collect_oci_metadata.py"),
        "--target",
        str(path),
        "--approved-target-sha256",
        digest(target(scope)),
        "--output",
        str(output),
    ]
    # Freeze the same target instance; timestamp construction is deliberately not repeated.
    t = TargetSpec.model_validate_json(path.read_bytes())
    command[-3] = digest(t)
    result = subprocess.run(command, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert HostSnapshot.model_validate_json(output.read_bytes()).receipts[0].status == "PARSED"
    assert subprocess.run(command, capture_output=True, timeout=20).returncode == 64
