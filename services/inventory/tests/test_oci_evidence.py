"""Owned synthetic OCI bytes exercise the actual reader/CLI, not customer images."""

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest
from pydantic import ValidationError
from inventory import oci_evidence as runtime
from inventory.oci_evidence import OciRefused, collect_oci
from shared_models.host_collection import digest
from shared_models.oci_collection import CONFIG_MEDIA, LAYER_MEDIA, MANIFEST_MEDIA, ImageInput, OciEvidence, OciTarget
from shared_models.oci_projection import materialize_oci

ROOT = Path(__file__).resolve().parents[3]
DPKG = b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.17\n\n"
OS = b'ID=debian\nVERSION_ID="12"\nPASSWORD=not-exported\n'


def tar(entries, fmt=tarfile.USTAR_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=fmt) as archive:
        for path, content, kind in entries:
            item = tarfile.TarInfo(path)
            if kind == "file":
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
            else:
                item.type = {
                    "dir": tarfile.DIRTYPE,
                    "sym": tarfile.SYMTYPE,
                    "hard": tarfile.LNKTYPE,
                    "fifo": tarfile.FIFOTYPE,
                }[kind]
                item.linkname = "/outside/sentinel" if kind in {"sym", "hard"} else ""
                archive.addfile(item)
    return stream.getvalue()


def fixture(tmp_path, layers=None, inputs=None, config_update=None, manifest_update=None, compress=False):
    layout = tmp_path / "oci"
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True, exist_ok=True)
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    # An unrelated file is deliberately not part of approved collection.
    (layout / "index.json").write_text("DO NOT DISCOVER OR PARSE THIS")

    def put(raw):
        sha = hashlib.sha256(raw).hexdigest()
        (blobs / sha).write_bytes(raw)
        return sha

    if layers is None:
        layers = [
            tar(
                [
                    ("var/lib/dpkg/status", DPKG, "file"),
                    ("etc/os-release", OS, "file"),
                    ("usr/lib/libcrypto.so.3", b"\x7fELFowned-fixture-not-real-library", "file"),
                ]
            )
        ]
    descriptors, diff_ids = [], []
    for raw in layers:
        diff_ids.append("sha256:" + hashlib.sha256(raw).hexdigest())
        stored = gzip.compress(raw, mtime=0) if compress else raw
        descriptors.append(
            {
                "mediaType": LAYER_MEDIA + ("+gzip" if compress else ""),
                "digest": "sha256:" + put(stored),
                "size": len(stored),
            }
        )
    config = {
        "os": "linux",
        "architecture": "amd64",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "config": {
            "Env": ["API_SECRET=never-export-this"],
            "Cmd": ["never-run-me"],
            "ExposedPorts": {"443/tcp": {}},
            "Labels": {"org.opencontainers.image.vendor": "Fixture Vendor", "secret": "never-export-this"},
        },
    }
    if config_update:
        config_update(config)
    config_raw = json.dumps(config).encode()
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA,
        "config": {"mediaType": CONFIG_MEDIA, "digest": "sha256:" + put(config_raw), "size": len(config_raw)},
        "layers": descriptors,
    }
    if manifest_update:
        manifest_update(manifest)
    manifest_sha = put(json.dumps(manifest).encode())
    now = datetime.now(timezone.utc)
    target = OciTarget(
        target_id="payments-image",
        system_id="payments-api",
        environment="UAT",
        authorization_reference="change/approved-oci",
        layout_path=str(layout),
        manifest_sha256=manifest_sha,
        architecture="amd64",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        inputs=inputs
        or [
            ImageInput(input_id="packages", kind="DPKG_STATUS", path="var/lib/dpkg/status"),
            ImageInput(input_id="os", kind="LINUX_OS_RELEASE", path="etc/os-release"),
            ImageInput(input_id="library", kind="BINARY_METADATA", path="usr/lib/libcrypto.so.3"),
        ],
    )
    return target, manifest


def run(target):
    return collect_oci(target, digest(target))


@pytest.mark.parametrize("compress", [False, True])
def test_real_reader_and_six_projections(tmp_path, compress):
    target, _ = fixture(tmp_path, compress=compress)
    evidence = run(target)
    assert evidence.status == "COMPLETED"
    assert evidence.receipts[0].facts[0].software_version == "3.0.17"
    assert evidence.receipts[1].facts[0].local_basis == "DECLARED"
    assert not evidence.authenticity_verified and not evidence.image_executed
    assert not evidence.full_image_software_complete and evidence.runtime_use == "UNKNOWN"
    wire = evidence.model_dump_json()
    for secret in ["never-export-this", "never-run-me", "not-exported", "PASSWORD", "API_SECRET"]:
        assert secret not in wire
    projection = materialize_oci(evidence, digest(evidence))
    assert len(projection.SBOM.facts) == 2 and len(projection.TechBOM.facts) == 3
    assert projection.CBOM.state == projection.NBOM.state == projection.HBOM.state == "UNKNOWN"
    assert projection.VBOM.state == "DECLARED_ONLY"
    assert projection.VBOM.declared_vendor == "Fixture Vendor"
    assert evidence.declarations.exposed_ports == ["443/tcp"]
    assert not evidence.declarations.live_listeners_observed
    assert projection.SBOM.facts[0].evidence_id == projection.TechBOM.facts[0].evidence_id
    assert materialize_oci(evidence, digest(evidence)) == projection
    assert not projection.cyclonedx_export and not projection.graph_persisted


@pytest.mark.parametrize(
    "upper,expected",
    [
        ([("var/lib/dpkg/status", DPKG.replace(b"3.0.17", b"3.0.18"), "file")], "3.0.18"),
        ([("var/lib/dpkg/.wh.status", b"", "file")], None),
        ([("var/lib/.wh.dpkg", b"", "file")], None),
        ([("var/lib/dpkg/.wh..wh..opq", b"", "file")], None),
        ([(".wh..wh..opq", b"", "file")], None),
        # Same-layer replacement survives a whiteout regardless of tar order.
        ([("var/lib/dpkg/status", DPKG, "file"), ("var/lib/dpkg/.wh.status", b"", "file")], "3.0.17"),
        ([("var/lib/dpkg/status", DPKG, "file"), ("var/lib/dpkg/.wh..wh..opq", b"", "file")], "3.0.17"),
    ],
)
def test_overlay_whiteout_semantics(tmp_path, upper, expected):
    target, _ = fixture(tmp_path, layers=[tar([("var/lib/dpkg/status", DPKG, "file")]), tar(upper)])
    result = run(target)
    receipt = result.receipts[0]
    if expected:
        assert receipt.status == "PARSED" and receipt.facts[0].software_version == expected
        assert receipt.layer_sha256 == result.blobs[-1].sha256
    else:
        assert receipt.status == "UNAVAILABLE" and receipt.reason == "NOT_FOUND"
        assert not receipt.asset_absence_proven and not receipt.facts


@pytest.mark.parametrize("kind", ["sym", "hard", "fifo"])
@pytest.mark.parametrize("path", ["var", "var/lib/dpkg/status"])
def test_links_and_specials_never_followed(tmp_path, kind, path):
    target, _ = fixture(tmp_path, layers=[tar([("var/lib/dpkg/status", DPKG, "file")]), tar([(path, b"", kind)])])
    result = run(target)
    assert result.receipts[0].status == "UNSUPPORTED"
    assert result.receipts[0].reason == "LINK_OR_SPECIAL"


def test_replaced_directory_children_do_not_resurrect(tmp_path):
    target, _ = fixture(
        tmp_path,
        layers=[
            tar([("var/lib/dpkg/status", DPKG, "file")]),
            tar([("var/lib/dpkg", b"", "sym")]),
            tar([("var/lib/dpkg", b"", "dir")]),
        ],
    )
    assert run(target).receipts[0].status == "UNAVAILABLE"


@pytest.mark.parametrize("path", ["../sentinel", "/etc/passwd", "a/../../b", "a//b", "a/./b", "a\\b", "bad\nname"])
def test_unsafe_tar_names_refuse_entire_image(tmp_path, path):
    target, _ = fixture(tmp_path, layers=[tar([(path, b"owned", "file")])])
    with pytest.raises(OciRefused):
        run(target)


@pytest.mark.parametrize(
    "entries",
    [
        [("etc/os-release", OS, "file"), ("etc/os-release", OS, "file")],
        [(".wh.etc", b"not-empty", "file")],
        [(".wh.etc", b"", "sym")],
    ],
)
def test_ambiguous_tar_refused(tmp_path, entries):
    target, _ = fixture(tmp_path, layers=[tar(entries)])
    with pytest.raises(OciRefused):
        run(target)


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update(mediaType="application/vnd.docker.distribution.manifest.v2+json"),
        lambda m: m.update(schemaVersion=True),
        lambda m: m.update(subject={}),
        lambda m: m.update(layers=[]),
        lambda m: m["layers"][0].update(urls=["https://external.example/blob"]),
        lambda m: m["layers"][0].update(mediaType=LAYER_MEDIA + "+zstd"),
        lambda m: m["layers"][0].update(size=True),
        lambda m: m["layers"][0].update(size=0),
        lambda m: m["layers"][0].update(size=m["layers"][0]["size"] + 1),
        lambda m: m["layers"][0].update(digest="sha512:" + "0" * 128),
    ],
)
def test_manifest_and_descriptor_refusals(tmp_path, change):
    target, _ = fixture(tmp_path, manifest_update=change)
    with pytest.raises(OciRefused):
        run(target)


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c.update(os="windows"),
        lambda c: c.update(architecture="arm64"),
        lambda c: c["rootfs"].update(type="foreign"),
        lambda c: c["rootfs"].update(diff_ids=[]),
        lambda c: c["rootfs"].update(diff_ids=["sha256:" + "0" * 64]),
        lambda c: c["config"].update(ExposedPorts={"99999/tcp": {}}),
        lambda c: c["config"].update(ExposedPorts={"443": {}}),
        lambda c: c["config"].update(Labels=[]),
    ],
)
def test_platform_diffid_config_refusals(tmp_path, change):
    target, _ = fixture(tmp_path, config_update=change)
    with pytest.raises(OciRefused):
        run(target)


@pytest.mark.parametrize("link", ["symlink", "hardlink", "ancestor"])
def test_blobs_do_not_follow_filesystem_links(tmp_path, link):
    target, manifest = fixture(tmp_path)
    sha = manifest["layers"][0]["digest"][7:]
    path = Path(target.layout_path) / "blobs" / "sha256" / sha
    saved = tmp_path / "outside-blob"
    path.rename(saved)
    if link == "symlink":
        path.symlink_to(saved)
    elif link == "hardlink":
        os.link(saved, path)
    else:
        path.write_bytes(saved.read_bytes())
        folder = path.parent
        moved = tmp_path / "moved-blobs"
        folder.rename(moved)
        folder.symlink_to(moved, target_is_directory=True)
    with pytest.raises(OciRefused):
        run(target)


def test_changed_blob_content_refused(tmp_path):
    target, manifest = fixture(tmp_path)
    path = Path(target.layout_path) / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
    raw = bytearray(path.read_bytes())
    raw[100] ^= 1
    path.write_bytes(raw)
    with pytest.raises(OciRefused, match="COMMITMENT"):
        run(target)


@pytest.mark.parametrize("field,value", [("target_id", "different"), ("architecture", "arm64")])
def test_changed_target_does_not_reuse_approval(tmp_path, field, value):
    target, _ = fixture(tmp_path)
    approved = digest(target)
    changed = target.model_copy(update={field: value})
    with pytest.raises(OciRefused, match="TARGET_COMMITMENT"):
        collect_oci(changed, approved)


def test_window_and_privilege_refusal(tmp_path, monkeypatch):
    target, _ = fixture(tmp_path)
    expired = target.model_copy(
        update={
            "not_before": target.not_before - timedelta(hours=2),
            "expires_at": target.expires_at - timedelta(hours=2),
        }
    )
    with pytest.raises(OciRefused, match="WINDOW"):
        run(expired)
    monkeypatch.setattr(runtime, "elevated", lambda: True)
    with pytest.raises(OciRefused, match="ORDINARY_USER"):
        run(target)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"not a package database",
        DPKG + DPKG,
        DPKG.replace(b"Version: 3.0.17", b"Version: 3.0.17\nVersion: 3.0.18"),
    ],
)
def test_invalid_package_bytes_are_gaps_not_absence(tmp_path, value):
    target, _ = fixture(tmp_path, layers=[tar([("var/lib/dpkg/status", value, "file")])])
    result = run(target)
    assert result.status == "FAILED" and result.receipts[0].status == "INVALID"
    assert not result.receipts[0].facts and not result.receipts[0].asset_absence_proven


def test_apk_and_crypto_config_are_metadata_not_use(tmp_path):
    inputs = [
        ImageInput(input_id="apk", kind="APK_INSTALLED", path="lib/apk/db/installed"),
        ImageInput(input_id="tls", kind="NGINX_TLS_CONFIG", path="etc/nginx/tls.conf"),
    ]
    target, _ = fixture(
        tmp_path,
        inputs=inputs,
        layers=[
            tar(
                [
                    (inputs[0].path, b"P:libcrypto3\nV:3.3.2-r0\n", "file"),
                    (inputs[1].path, b"ssl_protocols TLSv1.3;\nssl_ciphers AES256-GCM-SHA384;\n", "file"),
                ]
            )
        ],
    )
    result = run(target)
    projection = materialize_oci(result, digest(result))
    assert len(projection.SBOM.facts) == len(projection.CBOM.facts) == 1
    assert projection.CBOM.facts[0].fact.local_basis == "DECLARED"
    assert projection.NBOM.state == "UNKNOWN" and projection.runtime_use == "UNKNOWN"


def test_budgets_and_trailing_data(tmp_path, monkeypatch):
    target, _ = fixture(tmp_path)
    monkeypatch.setattr(runtime, "MAX_ENTRIES", 1)
    with pytest.raises(OciRefused, match="ENTRY_BUDGET"):
        run(target)
    monkeypatch.setattr(runtime, "MAX_ENTRIES", 10000)
    monkeypatch.setattr(runtime, "MAX_RAW_LAYER", 100)
    with pytest.raises(OciRefused, match="RAW_LAYER_BUDGET"):
        run(target)


def test_no_subprocess_network_discovery_or_extraction(tmp_path, monkeypatch):
    target, _ = fixture(tmp_path)

    def denied(*args, **kwargs):
        raise AssertionError("Forbidden execution, discovery or extraction")

    import socket

    for name in ["system", "listdir", "scandir", "walk"]:
        monkeypatch.setattr(os, name, denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(tarfile.TarFile, "extractall", denied)
    monkeypatch.setattr(tarfile.TarFile, "extract", denied)
    assert run(target).status == "COMPLETED"


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b"\xff"])
def test_strict_json_refuses_ambiguity(raw):
    with pytest.raises(OciRefused):
        runtime.strict_json(raw)


def test_retained_evidence_and_projection_tamper_refusal(tmp_path):
    target, _ = fixture(tmp_path)
    evidence = run(target)
    commitment = digest(evidence)
    with pytest.raises(ValueError):
        materialize_oci(evidence, "0" * 64)
    data = evidence.model_dump()
    data["status"] = "FAILED"
    with pytest.raises(ValidationError):
        OciEvidence.model_validate(data)
    data = evidence.model_dump()
    data["receipts"][0]["facts"][0]["runtime_use"] = "OBSERVED"
    with pytest.raises(ValidationError):
        OciEvidence.model_validate(data)
    evidence.receipts.reverse()
    with pytest.raises(ValueError):
        materialize_oci(evidence, commitment)


def test_cli_collect_materialize_refuse_overwrite(tmp_path):
    target, _ = fixture(tmp_path, compress=True)
    target_path, result_path, view_path = [tmp_path / x for x in ["target.json", "evidence.json", "views.json"]]
    target_path.write_text(target.model_dump_json())
    base = [sys.executable, str(ROOT / "scripts/collect_oci_evidence.py")]
    args = [
        "collect",
        "--target",
        str(target_path),
        "--approved-target-sha256",
        digest(target),
        "--output",
        str(result_path),
    ]
    capture = subprocess.run(base + args, capture_output=True, text=True)
    assert capture.returncode == 0, capture.stderr
    result = OciEvidence.model_validate_json(result_path.read_bytes())
    assert result.status == "COMPLETED" and result_path.stat().st_mode & 0o777 == 0o600
    project = subprocess.run(
        base
        + [
            "materialize",
            "--evidence",
            str(result_path),
            "--approved-evidence-sha256",
            digest(result),
            "--output",
            str(view_path),
        ],
        capture_output=True,
        text=True,
    )
    assert project.returncode == 0, project.stderr
    original = result_path.read_bytes()
    repeat = subprocess.run(base + args, capture_output=True, text=True)
    assert repeat.returncode == 64 and result_path.read_bytes() == original
    assert "never-export" not in capture.stdout + capture.stderr
    # Optional public retained engineering witness from this actual CLI run.
    if os.environ.get("CRYPTOSCAN_OCI_WITNESS_DIR"):
        import shutil

        folder = Path(os.environ["CRYPTOSCAN_OCI_WITNESS_DIR"])
        folder.mkdir(parents=True, exist_ok=True)
        for path in [target_path, result_path, view_path]:
            shutil.copyfile(path, folder / path.name)


def test_cli_retains_partial_and_wrong_approval_creates_no_output(tmp_path):
    target, _ = fixture(tmp_path, layers=[tar([("etc/os-release", OS, "file")])])
    path = tmp_path / "target.json"
    path.write_text(target.model_dump_json())
    output = tmp_path / "result.json"
    base = [
        sys.executable,
        str(ROOT / "scripts/collect_oci_evidence.py"),
        "collect",
        "--target",
        str(path),
        "--output",
        str(output),
        "--approved-target-sha256",
    ]
    wrong = subprocess.run(base + ["0" * 64], capture_output=True)
    assert wrong.returncode == 64 and not output.exists()
    partial = subprocess.run(base + [digest(target)], capture_output=True)
    assert partial.returncode == 2
    assert OciEvidence.model_validate_json(output.read_bytes()).status == "PARTIAL"


def test_public_certificate_contributes_cbom_without_tls_or_hsm_claim(tmp_path):
    from services.inventory.tests.test_host import certificate

    item = ImageInput(input_id="cert", kind="PUBLIC_CERTIFICATE", path="etc/tls/public.pem")
    target, _ = fixture(tmp_path, inputs=[item], layers=[tar([(item.path, certificate("RSA2048"), "file")])])
    evidence = run(target)
    view = materialize_oci(evidence, digest(evidence))
    assert view.CBOM.facts[0].fact.algorithm == "RSA" and view.CBOM.facts[0].fact.key_size == 2048
    assert view.CBOM.facts[0].fact.runtime_use == "UNKNOWN"
    assert view.NBOM.state == view.HBOM.state == "UNKNOWN"
    assert "BEGIN CERTIFICATE" not in evidence.model_dump_json()


def test_private_certificate_input_never_exports_private_bytes(tmp_path):
    item = ImageInput(input_id="cert", kind="PUBLIC_CERTIFICATE", path="etc/tls/public.pem")
    raw = b"-----BEGIN PRIVATE KEY-----\nprivate-material-must-not-escape\n-----END PRIVATE KEY-----"
    target, _ = fixture(tmp_path, inputs=[item], layers=[tar([(item.path, raw, "file")])])
    result = run(target)
    assert result.status == "FAILED" and result.receipts[0].status == "INVALID"
    assert "private-material" not in result.model_dump_json()


def test_existing_bounded_rpm_parser_is_reused(tmp_path):
    from services.inventory.tests.test_rpm_metadata import database, header

    item = ImageInput(input_id="rpm", kind="RPM_SQLITE", path="usr/lib/sysimage/rpm/rpmdb.sqlite")
    target, _ = fixture(tmp_path, inputs=[item], layers=[tar([(item.path, database([header()]), "file")])])
    result = run(target)
    assert result.status == "COMPLETED" and result.receipts[0].facts[0].software_version == "1:3.2.2-5.el9"


def test_oversize_input_and_fact_overflow_are_explicit_gaps(tmp_path):
    target, _ = fixture(tmp_path, layers=[tar([("var/lib/dpkg/status", b"x" * (1048576 + 1), "file")])])
    assert run(target).receipts[0].status == "BUDGET_EXCEEDED"
    many = b"".join(DPKG.replace(b"openssl", ("pkg" + str(i)).encode()) for i in range(1001))
    target, _ = fixture(tmp_path, layers=[tar([("var/lib/dpkg/status", many, "file")])])
    result = run(target)
    assert result.receipts[0].status == "BUDGET_EXCEEDED" and not result.receipts[0].facts


@pytest.mark.parametrize(
    "raw", [b"not-a-tar", tar([]) + b"x" * 512, tar([("x" * 180, b"x", "file")], fmt=tarfile.PAX_FORMAT)]
)
def test_invalid_trailing_and_extended_tars_refuse(tmp_path, raw):
    target, _ = fixture(tmp_path, layers=[raw])
    with pytest.raises(OciRefused):
        run(target)


def test_invalid_gzip_total_budget_and_wrong_media_type(tmp_path, monkeypatch):
    target, _ = fixture(tmp_path, manifest_update=lambda m: m["layers"][0].update(mediaType=LAYER_MEDIA + "+gzip"))
    with pytest.raises(OciRefused, match="GZIP"):
        run(target)
    target, _ = fixture(tmp_path, manifest_update=lambda m: m["layers"][0].update(mediaType=[]))
    with pytest.raises(OciRefused, match="DESCRIPTOR"):
        run(target)
    target, _ = fixture(tmp_path)
    monkeypatch.setattr(runtime, "MAX_TOTAL", 1)
    with pytest.raises(OciRefused, match="TOTAL_BLOB"):
        run(target)


def test_wrong_scope_is_refused_before_any_io_and_candidate_has_no_admission(tmp_path, monkeypatch):
    target, _ = fixture(tmp_path)
    adapter = runtime.OfflineOciCollector(digest(target))
    assert adapter.validate_scope(target) is None
    assert adapter.collect(target).status == "COMPLETED"
    assert not adapter.health()["production_execution_qualified"]
    assert adapter.health()["state"] == "OFFLINE_CANDIDATE_NOT_SERVER_ADMITTED"

    def no_io(*args):
        raise AssertionError("Scope must precede IO")

    monkeypatch.setattr(runtime, "read_public", no_io)
    with pytest.raises(OciRefused, match="TARGET_COMMITMENT"):
        collect_oci(target, "0" * 64)


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret", "a/../b", "a//b", "a\\b", "."])
def test_noncanonical_input_scope_refused(path):
    with pytest.raises(ValueError):
        ImageInput(input_id="binary", kind="BINARY_METADATA", path=path)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(production_execution_qualified=True),
        lambda d: d.update(authenticity_verified=True),
        lambda d: d["coverage"].update(parsed_inputs=0),
        lambda d: d["receipts"][0].update(layer_sha256="0" * 64),
        lambda d: d["receipts"][0]["facts"][0].update(kind="CERTIFICATE"),
        lambda d: d.update(extra_assertion="bank-approved"),
    ],
)
def test_forged_result_claims_and_receipts_refused(tmp_path, change):
    target, _ = fixture(tmp_path)
    result = run(target)
    data = result.model_dump()
    change(data)
    with pytest.raises(ValueError):
        OciEvidence.model_validate(data)


def test_output_symlink_parent_and_duplicate_input_json_refused(tmp_path):
    from collect_oci_evidence import exclusive_output

    target, _ = fixture(tmp_path)
    result = run(target)
    destination = tmp_path / "owned.json"
    destination.write_text("do-not-overwrite")
    alias = tmp_path / "link.json"
    alias.symlink_to(destination)
    with pytest.raises(OSError):
        exclusive_output(str(alias), result)
    assert destination.read_text() == "do-not-overwrite"
    folder_alias = tmp_path / "directory-link"
    folder_alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        exclusive_output(str(folder_alias / "new.json"), result)
    assert not (tmp_path / "new.json").exists()
    plan = tmp_path / "duplicate.json"
    plan.write_text('{"target_id":"wrong",' + target.model_dump_json()[1:])
    output = tmp_path / "refused.json"
    process = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/collect_oci_evidence.py"),
            "collect",
            "--target",
            str(plan),
            "--approved-target-sha256",
            digest(target),
            "--output",
            str(output),
        ],
        capture_output=True,
    )
    assert process.returncode == 64 and not output.exists()
