"""Bounded, no-extraction OCI layout reader; never pulls, mounts or runs an image.

Only the exact approved manifest and its SHA256-addressed blobs are opened.
Layer whiteouts are applied to lower layers before same-layer entries. No tar
member is ever written to the filesystem or followed as a link.
"""

import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import zlib
from datetime import datetime, timezone

from inventory.host import Refused, _linux_fd, elevated
from shared_models.host_collection import MAX_FILE_BYTES, digest
from shared_models.oci_collection import (
    CONFIG_MEDIA,
    LAYER_MEDIA,
    MANIFEST_MEDIA,
    MAX_BLOB,
    MAX_ENTRIES,
    MAX_RAW_LAYER,
    MAX_TOTAL,
    BlobRef,
    ImageDeclarations,
    ImageReceipt,
    ImageCoverage,
    OciEvidence,
    OciTarget,
    relative_path,
)


class OciRefused(ValueError):
    """Safe public refusal code; never includes raw source/config/SDK errors."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OciRefused("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def strict_json(raw):
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(OciRefused("INVALID_JSON")),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OciRefused("INVALID_JSON") from exc


def read_public(path, limit):
    try:
        with _linux_fd(path) as fd:
            before = os.fstat(fd)
            if before.st_size > limit:
                raise OciRefused("INPUT_BUDGET")
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            stamp = lambda s: (s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(data) > limit or len(data) != before.st_size or stamp(before) != stamp(after):
                raise OciRefused("INPUT_CHANGED_OR_BUDGET")
            return bytes(data)
    except (OSError, Refused) as exc:
        raise OciRefused("INPUT_UNAVAILABLE_OR_UNSAFE") from exc


def _descriptor(value, media):
    if (
        not isinstance(value, dict)
        or set(value) - {"mediaType", "digest", "size", "annotations"}
        or not isinstance(value.get("mediaType"), str)
        or value.get("mediaType") not in media
        or type(value.get("size")) is not int
        or not 0 < value["size"] <= MAX_BLOB
        or not isinstance(value.get("digest"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
    ):
        raise OciRefused("UNSUPPORTED_DESCRIPTOR")
    # urls/data/artifactType/platform indirection and non-SHA256 are refused.
    return value["digest"][7:]


def _member_path(member):
    value = member.name
    if value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/") if member.isdir() else value
    if value in {"", "."} and member.isdir():
        return None
    try:
        return relative_path(value)
    except ValueError as exc:
        raise OciRefused("UNSAFE_TAR_PATH") from exc


def _layer(raw, layer_sha, selected, tree, counter):
    if len(raw) % 512:
        raise OciRefused("INVALID_TAR")
    entries, whiteouts, opaque = {}, [], []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                counter[0] += 1
                if counter[0] > MAX_ENTRIES:
                    raise OciRefused("ENTRY_BUDGET")
                if member.pax_headers or member.sparse is not None or member.size < 0:
                    raise OciRefused("UNSUPPORTED_TAR_EXTENSION")
                path = _member_path(member)
                if path is None:
                    continue
                if path in entries:
                    raise OciRefused("DUPLICATE_TAR_PATH")
                parent, _, name = path.rpartition("/")
                if name.startswith(".wh."):
                    if not member.isfile() or member.size:
                        raise OciRefused("UNSUPPORTED_WHITEOUT")
                    if name == ".wh..wh..opq":
                        opaque.append(parent)
                    else:
                        removed = (parent + "/" if parent else "") + name[4:]
                        relative_path(removed)
                        whiteouts.append(removed)
                    entries[path] = None
                    continue
                kind = "DIRECTORY" if member.isdir() else "FILE" if member.isfile() else "SPECIAL"
                content = None
                if path in selected and kind == "FILE" and member.size <= MAX_FILE_BYTES:
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise OciRefused("INVALID_TAR")
                    with handle:
                        content = handle.read(MAX_FILE_BYTES + 1)
                    if len(content) != member.size:
                        raise OciRefused("INVALID_TAR")
                entries[path] = (kind, content, member.size, layer_sha)
            # Refuse hidden concatenated archives/trailing nonzero bytes.
            if any(raw[archive.offset :]):
                raise OciRefused("TRAILING_TAR_DATA")
    except (tarfile.TarError, EOFError, RecursionError, ValueError) as exc:
        if isinstance(exc, OciRefused):
            raise
        raise OciRefused("INVALID_TAR") from exc
    # Whiteouts affect lower layers only, regardless of position in this tar.
    for path in list(tree):
        if any(path == w or path.startswith(w + "/") for w in whiteouts) or any(
            not d or path.startswith(d + "/") for d in opaque
        ):
            del tree[path]
    for path, entry in entries.items():
        if entry is not None:
            if entry[0] != "DIRECTORY":
                for child in list(tree):
                    if child.startswith(path + "/"):
                        del tree[child]
            tree[path] = entry
    if len(tree) > MAX_ENTRIES:
        raise OciRefused("ENTRY_BUDGET")


def _facts(kind, data):
    from inventory.host import _certificate, _config, _os_release
    from inventory.linux_packages import apk_installed
    from shared_models.host_collection import HostFact

    if kind == "DPKG_STATUS":
        # Refuse ambiguous identity/status fields rather than dict-last-wins.
        from inventory.host import _packages

        for block in re.split(r"\r?\n\r?\n", data.decode("utf-8")):
            keys = re.findall(r"(?m)^(Package|Version|Status):", block)
            if len(keys) != len(set(keys)):
                raise ValueError("Ambiguous package fields")
        facts = _packages(data)
        names = [f.software_name for f in facts]
        if len(set(names)) != len(names) or any(f.software_version is None for f in facts):
            raise ValueError("Ambiguous package identity")
        return facts
    if kind == "RPM_SQLITE":
        from inventory.rpm_metadata import rpm_sqlite

        return rpm_sqlite(data)
    if kind == "APK_INSTALLED":
        return apk_installed(data)
    if kind == "LINUX_OS_RELEASE":
        return _os_release(data)
    if kind == "PUBLIC_CERTIFICATE":
        return _certificate(data)
    if kind == "NGINX_TLS_CONFIG":
        return _config(data)
    if kind == "BINARY_METADATA":
        fmt = "ELF" if data.startswith(b"\x7fELF") else "PE" if data.startswith(b"MZ") else None
        if fmt is None:
            raise ValueError("Unsupported binary magic")
        return [HostFact(kind="BINARY", local_basis="OBSERVED", purpose="FILE_PRESENCE", binary_format=fmt)]
    raise ValueError("Unsupported metadata parser")


def _receipt(item, tree):
    base = dict(input_id=item.input_id, path=item.path)
    parts = item.path.split("/")
    if any(tree.get("/".join(parts[:i]), ("DIRECTORY",))[0] != "DIRECTORY" for i in range(1, len(parts))):
        return ImageReceipt(**base, status="UNSUPPORTED", reason="LINK_OR_SPECIAL")
    entry = tree.get(item.path)
    if entry is None:
        return ImageReceipt(**base, status="UNAVAILABLE", reason="NOT_FOUND")
    kind, data, size, layer = entry
    if kind != "FILE":
        return ImageReceipt(**base, status="UNSUPPORTED", reason="LINK_OR_SPECIAL", layer_sha256=layer)
    if size > MAX_FILE_BYTES:
        return ImageReceipt(**base, status="BUDGET_EXCEEDED", reason="LIMIT", layer_sha256=layer)
    base.update(content_sha256=hashlib.sha256(data).hexdigest(), layer_sha256=layer, byte_count=size)
    try:
        facts = _facts(item.kind, data)
        return ImageReceipt(**base, status="PARSED", reason="METADATA_ONLY", facts=facts)
    except Refused as exc:
        if exc.status == "BUDGET_EXCEEDED":
            return ImageReceipt(**base, status="BUDGET_EXCEEDED", reason="LIMIT")
        return ImageReceipt(**base, status="INVALID", reason="INVALID_FORMAT")
    except (ValueError, KeyError, UnicodeError, TypeError):
        return ImageReceipt(**base, status="INVALID", reason="INVALID_FORMAT")


def validate_oci_scope(target: OciTarget, approved_target_sha256: str):
    """Validate explicit candidate scope before opening any image bytes."""
    target = OciTarget.model_validate(target.model_dump())
    started = datetime.now(timezone.utc)
    if sys.platform != "linux":
        raise OciRefused("UNSUPPORTED_EXECUTION_PLATFORM")
    if elevated():
        raise OciRefused("ORDINARY_USER_REQUIRED")
    if approved_target_sha256 != digest(target):
        raise OciRefused("TARGET_COMMITMENT_MISMATCH")
    if not target.not_before <= started < target.expires_at:
        raise OciRefused("OUTSIDE_APPROVED_WINDOW")
    return target, started


def collect_oci(target: OciTarget, approved_target_sha256: str) -> OciEvidence:
    """Local candidate runtime. Approval digest must arrive via independent channel."""
    target, started = validate_oci_scope(target, approved_target_sha256)
    if strict_json(read_public(target.layout_path + "/oci-layout", 1024)) != {"imageLayoutVersion": "1.0.0"}:
        raise OciRefused("UNSUPPORTED_LAYOUT")
    refs = []

    def blob(sha, role, size=None):
        raw = read_public(target.layout_path + "/blobs/sha256/" + sha, MAX_BLOB)
        if hashlib.sha256(raw).hexdigest() != sha or (size is not None and len(raw) != size):
            raise OciRefused("BLOB_COMMITMENT_MISMATCH")
        refs.append(BlobRef(sha256=sha, byte_count=len(raw), role=role))
        if sum(r.byte_count for r in refs) > MAX_TOTAL:
            raise OciRefused("TOTAL_BLOB_BUDGET")
        return raw

    manifest = strict_json(blob(target.manifest_sha256, "MANIFEST"))
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schemaVersion")) is not int
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != MANIFEST_MEDIA
        or set(manifest) - {"schemaVersion", "mediaType", "config", "layers", "annotations"}
        or not isinstance(manifest.get("layers"), list)
        or not 1 <= len(manifest["layers"]) <= 16
    ):
        raise OciRefused("UNSUPPORTED_IMAGE_MANIFEST")
    config_descriptor = manifest.get("config")
    config_sha = _descriptor(config_descriptor, {CONFIG_MEDIA})
    config = strict_json(blob(config_sha, "CONFIG", config_descriptor["size"]))
    if (
        not isinstance(config, dict)
        or config.get("os") != "linux"
        or config.get("architecture") != target.architecture
        or not isinstance(config.get("rootfs"), dict)
        or config["rootfs"].get("type") != "layers"
        or not isinstance(config["rootfs"].get("diff_ids"), list)
        or len(config["rootfs"]["diff_ids"]) != len(manifest["layers"])
    ):
        raise OciRefused("UNSUPPORTED_PLATFORM_OR_ROOTFS")
    diff_ids, tree, count, raw_total = [], {}, [0], 0
    for descriptor, diff_id in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
        sha = _descriptor(descriptor, {LAYER_MEDIA, LAYER_MEDIA + "+gzip"})
        if not isinstance(diff_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id):
            raise OciRefused("UNSUPPORTED_DIFF_ID")
        raw = blob(sha, "LAYER", descriptor["size"])
        if descriptor["mediaType"].endswith("+gzip"):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    raw = compressed.read(MAX_RAW_LAYER + 1)
            except (OSError, EOFError, zlib.error) as exc:
                raise OciRefused("INVALID_GZIP") from exc
        raw_total += len(raw)
        if len(raw) > MAX_RAW_LAYER or raw_total > MAX_TOTAL:
            raise OciRefused("RAW_LAYER_BUDGET")
        if hashlib.sha256(raw).hexdigest() != diff_id[7:]:
            raise OciRefused("DIFF_ID_MISMATCH")
        diff_ids.append(diff_id[7:])
        _layer(raw, sha, {i.path for i in target.inputs}, tree, count)
    public_config = config.get("config", {})
    if not isinstance(public_config, dict):
        raise OciRefused("INVALID_IMAGE_CONFIG")
    ports, labels = public_config.get("ExposedPorts", {}), public_config.get("Labels", {})
    if ports is None:
        ports = {}
    if labels is None:
        labels = {}
    if not isinstance(ports, dict) or not isinstance(labels, dict):
        raise OciRefused("INVALID_IMAGE_CONFIG")
    try:
        declarations = ImageDeclarations(
            exposed_ports=sorted(ports),
            vendor=labels.get("org.opencontainers.image.vendor"),
            base_image_name=labels.get("org.opencontainers.image.base.name"),
            base_image_digest=labels.get("org.opencontainers.image.base.digest"),
        )
    except ValueError as exc:
        raise OciRefused("INVALID_PUBLIC_DECLARATIONS") from exc
    receipts = [_receipt(item, tree) for item in target.inputs]
    if sum(len(r.facts) for r in receipts) > 1000:
        raise OciRefused("FACT_BUDGET")
    success = sum(r.status == "PARSED" for r in receipts)
    return OciEvidence(
        target=target,
        target_sha256=digest(target),
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        status="COMPLETED" if success == len(receipts) else "PARTIAL" if success else "FAILED",
        blobs=refs,
        config_sha256=config_sha,
        diff_ids=diff_ids,
        declarations=declarations,
        receipts=receipts,
        coverage=ImageCoverage(parsed_inputs=success, approved_inputs=len(receipts)),
    )


class OfflineOciCollector:
    """Typed candidate adapter; not registered with the production job scheduler."""

    def __init__(self, approved_target_sha256: str):
        self.approved_target_sha256 = approved_target_sha256

    def validate_scope(self, target: OciTarget) -> None:
        validate_oci_scope(target, self.approved_target_sha256)

    def collect(self, target: OciTarget) -> OciEvidence:
        return collect_oci(target, self.approved_target_sha256)

    def health(self):
        return {
            "collector": "offline-oci/candidate-v1",
            "platform_supported": sys.platform == "linux",
            "state": "OFFLINE_CANDIDATE_NOT_SERVER_ADMITTED",
            "remote_execution": False,
            "image_execution": False,
            "production_execution_qualified": False,
        }
