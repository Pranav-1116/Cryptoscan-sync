"""Synthetic OCI content/runtime seams; not independent real-container qualification."""

import gzip
import hashlib
import io
import json
import tarfile
import pytest
from services.inventory.tests.test_oci_image import layout, target, raw
from inventory.host import collect
from inventory.collection import OfflineContainerCollector, OfflineLinuxCollector, OfflineOciMetadataCollector
from shared_models.host_collection import HostInput, HostSnapshot, digest
from shared_models.oci_content import selected_bytes

DB = b"Package: openssl\nStatus: install ok installed\nVersion: 3.0-fixture\n\n"


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as handle:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                info.type, info.linkname = value
                handle.addfile(info)
            else:
                info.size = len(value)
                handle.addfile(info, io.BytesIO(value))
    return out.getvalue()


def content_layout(tmp_path, layers=None, compression="gzip", diff_bad=False):
    root, scope = layout(tmp_path)
    desc = json.loads((root / "index.json").read_bytes())["manifests"][0]
    manifest = json.loads((root / "blobs/sha256" / desc["digest"][7:]).read_bytes())
    config = json.loads((root / "blobs/sha256" / manifest["config"]["digest"][7:]).read_bytes())
    blobs, diffs = [], []
    for data in layers if layers is not None else [tar([("var/lib/dpkg/status", DB)])]:
        blob = gzip.compress(data, mtime=0) if compression == "gzip" else data
        sha = hashlib.sha256(blob).hexdigest()
        (root / "blobs/sha256" / sha).write_bytes(blob)
        blobs.append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if compression == "gzip" else ""),
                "digest": "sha256:" + sha,
                "size": len(blob),
            }
        )
        diffs.append("sha256:" + ("f" * 64 if diff_bad else hashlib.sha256(data).hexdigest()))
    config["rootfs"]["diff_ids"] = diffs
    cr = raw(config)
    cs = hashlib.sha256(cr).hexdigest()
    (root / "blobs/sha256" / cs).write_bytes(cr)
    manifest["config"].update(digest="sha256:" + cs, size=len(cr))
    manifest["layers"] = blobs
    mr = raw(manifest)
    ms = hashlib.sha256(mr).hexdigest()
    (root / "blobs/sha256" / ms).write_bytes(mr)
    desc.update(digest="sha256:" + ms, size=len(mr))
    (root / "index.json").write_bytes(raw({"schemaVersion": 2, "manifests": [desc]}))
    path = scope.inputs[0].path.replace("oci-layout://", "oci-content://").split("/manifest/")[0]
    scope = scope.model_copy(
        update={
            "inputs": [
                HostInput(input_id="image", kind="OCI_IMAGE_CONTENT", path=path + f"/manifest/sha256/{ms}/root{root}")
            ]
        }
    )
    return root, scope


@pytest.mark.parametrize("compression", ["gzip", "tar"])
def test_verified_layers_and_existing_package_parser(tmp_path, compression):
    _, scope = content_layout(tmp_path, compression=compression)
    snapshot = OfflineContainerCollector().collect(target(scope))
    r = snapshot.receipts[0]
    assert r.status == "PARSED", r
    f = r.facts[0]
    assert f.layer_contents_verified and f.final_filesystem_view_verified and not f.filesystem_materialized
    assert not f.package_inventory_verified and not f.deployment_verified
    assert [(p.name, p.version, p.layer_index) for p in f.packages] == [("openssl", "3.0-fixture", 0)]
    assert f.databases[1].status == "NOT_PRESENT_IN_VERIFIED_VIEW"
    assert hashlib.sha256(selected_bytes(f)).hexdigest() == f.interface_sha256 == r.content_sha256
    assert "DO_NOT_EXPORT" not in snapshot.model_dump_json()
    HostSnapshot.model_validate(snapshot.model_dump(mode="json"))


@pytest.mark.parametrize("opaque_first", [True, False])
def test_whiteouts_apply_only_to_lower_not_same_layer(tmp_path, opaque_first):
    entries = [("var/lib/dpkg/.wh..wh..opq", b""), ("var/lib/dpkg/status", DB.replace(b"3.0-fixture", b"4.0-fixture"))]
    if not opaque_first:
        entries.reverse()
    _, scope = content_layout(tmp_path, [tar([("var/lib/dpkg/status", DB)]), tar(entries)])
    r = collect(scope).receipts[0]
    assert r.status == "PARSED", r
    assert r.facts[0].packages[0].version == "4.0-fixture" and r.facts[0].packages[0].layer_index == 1


def test_deleted_database_is_not_installed_package_inventory(tmp_path):
    _, scope = content_layout(tmp_path, [tar([("var/lib/dpkg/status", DB)]), tar([("var/lib/dpkg/.wh.status", b"")])])
    r = collect(scope).receipts[0]
    assert r.status == "PARSED" and r.facts[0].packages == []
    assert all(d.status == "NOT_PRESENT_IN_VERIFIED_VIEW" for d in r.facts[0].databases)
    assert not r.facts[0].complete_inventory_verified


@pytest.mark.parametrize(
    "entries",
    [
        [("db/status", DB), ("var/lib/dpkg", (tarfile.SYMTYPE, "/db"))],
        [("original", DB), ("var/lib/dpkg/status", (tarfile.LNKTYPE, "original"))],
        [("lib/apk/db/installed", b"P:openssl\nV:3.0-fixture\n\n")],
    ],
)
def test_virtual_links_and_apk_never_materialize_host_files(tmp_path, entries):
    root, scope = content_layout(tmp_path, [tar(entries)])
    r = collect(scope).receipts[0]
    assert r.status == "PARSED", r
    assert r.facts[0].packages[0].name == "openssl"
    assert not (root / "var").exists()


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", b"bad")],
        [("/escape", b"bad")],
        [("a/../escape", b"bad")],
        [("a", (tarfile.SYMTYPE, "../../escape"))],
        [("a", (tarfile.FIFOTYPE, ""))],
        [("var/lib/dpkg/status", b"malformed")],
        [("a", b"one"), ("a", b"two")],
        [("var/lib/dpkg", (tarfile.SYMTYPE, "dpkg")), ("var/lib/dpkg/status", DB)],
        [("var/lib/dpkg/status", (tarfile.LNKTYPE, "missing"))],
        [("var/lib/dpkg/.wh.status", b"payload")],
        [("var/lib/dpkg", (tarfile.SYMTYPE, "/db")), ("db", (tarfile.SYMTYPE, "/var/lib/dpkg"))],
    ],
)
def test_hostile_layers_refuse_whole_positive(tmp_path, entries):
    _, scope = content_layout(tmp_path, [tar(entries)])
    r = collect(scope).receipts[0]
    assert r.status != "PARSED" and r.facts == [] and r.content_sha256 is None
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize(
    "mode", ["diff", "digest", "missing", "symlink", "hardlink", "budget", "bomb", "trailer", "unterminated", "tar"]
)
def test_integrity_budgets_and_compression_gaps(tmp_path, mode):
    import os

    layers = None
    if mode == "bomb":
        layers = [tar([("large", b"0" * 2_000_000)])]
    elif mode == "trailer":
        layers = [tar([("x", b"x")]) + b"bad" * 512]
    elif mode == "unterminated":
        layers = [tar([("x", b"x")])[:1024]]
    elif mode == "tar":
        layers = [b"not tar"]
    root, scope = content_layout(tmp_path, layers, diff_bad=mode == "diff")
    desc = json.loads((root / "index.json").read_bytes())["manifests"][0]
    m = json.loads((root / "blobs/sha256" / desc["digest"][7:]).read_bytes())
    blob = root / "blobs/sha256" / m["layers"][0]["digest"][7:]
    if mode == "digest":
        blob.write_bytes(b"changed")
    if mode == "missing":
        blob.unlink()
    if mode in {"symlink", "hardlink"}:
        other = root / "original"
        blob.rename(other)
        if mode == "symlink":
            blob.symlink_to(other)
        else:
            os.link(other, blob)
    if mode == "budget":
        scope = scope.model_copy(update={"max_file_bytes": 100})
    r = collect(scope).receipts[0]
    assert r.status != "PARSED" and not r.facts
    if mode in {"budget", "bomb"}:
        assert r.status == "BUDGET_EXCEEDED"


def test_opt_in_and_linux_authorization_guard(tmp_path):
    _, scope = content_layout(tmp_path)
    t = target(scope)
    with pytest.raises(ValueError):
        OfflineOciMetadataCollector().collect(t)
    with pytest.raises(ValueError):
        OfflineLinuxCollector().collect(t.model_copy(update={"collection_method": "offline_host"}))


@pytest.mark.parametrize(
    "field,value",
    [
        ("layer_contents_verified", False),
        ("package_inventory_verified", True),
        ("runtime_use", "OBSERVED"),
        ("rootfs_view_sha256", "a" * 64),
    ],
)
def test_changed_or_promoted_content_fact_refuses(tmp_path, field, value):
    _, scope = content_layout(tmp_path)
    s = collect(scope).model_dump(mode="json")
    s["receipts"][0]["facts"][0][field] = value
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(s)


BOOT = "11111111-2222-3333-4444-555555555555"
CID = "a" * 64
IMAGE = "b" * 64


def runtime_scope(scope):
    path = f"container-proc://linux/docker/{CID}/pid/123/start/900/boot/{BOOT}/manifest/sha256/{IMAGE}"
    return scope.model_copy(update={"inputs": [HostInput(input_id="runtime", kind="OCI_RUNTIME_PROCESS", path=path)]})


def kernel(monkeypatch, cgroup=None, change=False, state="S"):
    from inventory import linux_runtime

    calls = []

    def read(path, limit, magic, on_chunk):
        calls.append(path)
        if path.endswith("/boot_id"):
            data = (BOOT + "\n").encode()
        elif path.endswith("/stat"):
            start = "901" if change and calls.count(path) > 1 else "900"
            data = ("123 (fixture) " + state + " " + " ".join(["0"] * 18) + " " + start + " 0\n").encode()
        elif path.endswith("/comm"):
            data = b"fixture\n"
        elif path.endswith("/cgroup"):
            data = cgroup if cgroup is not None else f"0::/system.slice/docker-{CID}.scope\n".encode()
        else:
            raise AssertionError("Unapproved read " + path)
        on_chunk(data)
        return data

    monkeypatch.setattr(linux_runtime, "kernel_bytes", read)
    return calls


def test_runtime_exact_process_incarnation_not_image_attestation(tmp_path, monkeypatch):
    _, scope = content_layout(tmp_path)
    scope = runtime_scope(scope)
    calls = kernel(monkeypatch)
    r = collect(scope).receipts[0]
    assert r.status == "PARSED", r
    f = r.facts[0]
    assert f.process_observed and f.process.pid == 123 and f.process.process_start_ticks == 900
    assert not f.runtime_image_verified and not f.deployment_verified
    assert f.image_binding_basis == "OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED"
    assert set(calls) == {"/proc/123/comm", "/proc/123/stat", "/proc/123/cgroup", "/proc/sys/kernel/random/boot_id"}
    assert f.interface_sha256 == r.content_sha256


@pytest.mark.parametrize("mode", ["wrong-id", "ambiguous", "missing", "changed", "zombie", "boot", "budget"])
def test_runtime_failure_is_not_container_absence(tmp_path, monkeypatch, mode):
    _, scope = content_layout(tmp_path)
    scope = runtime_scope(scope)
    cg = None
    if mode == "wrong-id":
        cg = f"0::/docker/{'c' * 64}\n".encode()
    if mode == "ambiguous":
        cg = f"0::/docker/{CID}/docker/{'c' * 64}\n".encode()
    if mode == "missing":
        cg = b"0::/\n"
    kernel(monkeypatch, cg, change=mode == "changed", state="Z" if mode == "zombie" else "S")
    if mode == "boot":
        scope = scope.model_copy(
            update={
                "inputs": [
                    scope.inputs[0].model_copy(
                        update={"path": scope.inputs[0].path.replace(BOOT, "99999999-2222-3333-4444-555555555555")}
                    )
                ]
            }
        )
    if mode == "budget":
        scope = scope.model_copy(update={"max_file_bytes": 100})
    r = collect(scope).receipts[0]
    assert r.status != "PARSED" and r.facts == []


@pytest.mark.parametrize(
    "path",
    [
        "oci-content://remote/linux/amd64/manifest/sha256/" + IMAGE + "/root/tmp/layout",
        "oci-content://local/linux/amd64/manifest/sha256/" + IMAGE + "/root/tmp/../layout",
        "oci-content://local/linux/amd64/manifest/sha256/" + IMAGE + "/root/tmp/layout?pull=true",
        f"container-proc://linux/docker/{CID}/pid/self/start/900/boot/{BOOT}/manifest/sha256/{IMAGE}",
        f"container-proc://linux/docker/{CID}/pid/123/start/900/boot/{BOOT}/manifest/sha256/{IMAGE}?all=true",
    ],
)
def test_noncanonical_scope_refuses_before_acquisition(path):
    kind = "OCI_RUNTIME_PROCESS" if path.startswith("container-proc:") else "OCI_IMAGE_CONTENT"
    with pytest.raises(ValueError):
        HostInput(input_id="bad", kind=kind, path=path)


def test_cli_content_is_explicit_reviewed_and_exclusive(tmp_path):
    import subprocess, sys
    from pathlib import Path

    _, scope = content_layout(tmp_path)
    t = target(scope)
    file = tmp_path / "target.json"
    file.write_text(t.model_dump_json())
    out = tmp_path / "snapshot.json"
    command = [
        sys.executable,
        str(Path(__file__).resolve().parents[3] / "scripts/collect_oci_metadata.py"),
        "--target",
        str(file),
        "--approved-target-sha256",
        digest(t),
        "--output",
        str(out),
    ]
    assert subprocess.run(command, capture_output=True).returncode == 64 and not out.exists()
    assert subprocess.run([*command, "--include-verified-content-runtime"], capture_output=True).returncode == 0
    snapshot = HostSnapshot.model_validate_json(out.read_bytes())
    assert snapshot.receipts[0].facts[0].layer_contents_verified
    original = out.read_bytes()
    assert subprocess.run([*command, "--include-verified-content-runtime"], capture_output=True).returncode == 64
    assert out.read_bytes() == original


def test_content_package_provenance_cannot_be_resealed_to_another_layer(tmp_path):
    from shared_models.oci_content import OciContentFact, seal

    _, scope = content_layout(tmp_path)
    f = collect(scope).receipts[0].facts[0].model_dump(mode="json")
    f.pop("interface_sha256")
    f["packages"][0]["layer_index"] = 99
    with pytest.raises(ValueError):
        seal(OciContentFact, **f)


def test_production_admission_not_delegated_to_import_or_environment(tmp_path, monkeypatch):
    from shared_models.container_admission import container_readiness, require_container_profile, CONTENT_PROFILE

    _, scope = content_layout(tmp_path)
    snapshot = collect(scope)
    monkeypatch.setenv("CRYPTOSCAN_CONTAINER_PRODUCTION_ADMITTED", "true")
    with pytest.raises(ValueError):
        require_container_profile(CONTENT_PROFILE)
    result = container_readiness(snapshot)
    assert not result["production_execution_qualified"] and not result["server_execution"]
    assert "NO_EXACT_RUNTIME_PROCESS_EVIDENCE" in result["blockers"]
    broken = snapshot.model_dump(mode="json")
    broken["production_execution_qualified"] = True
    with pytest.raises(ValueError):
        HostSnapshot.model_validate(broken)


@pytest.mark.parametrize(
    "entries",
    [
        [("var/lib/dpkg", (tarfile.SYMTYPE, "/missing"))],
        [("var/lib/dpkg", (tarfile.SYMTYPE, "/db")), ("var/lib/dpkg/.wh.status", b"")],
    ],
)
def test_dangling_or_whiteout_through_link_refuses(tmp_path, entries):
    # Link writes/whiteouts are never followed onto host or silently ignored.
    _, scope = content_layout(tmp_path, [tar(entries)])
    assert collect(scope).receipts[0].status != "PARSED"
