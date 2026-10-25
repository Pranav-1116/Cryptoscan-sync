"""Bounded verified layer view. No host extraction, commands, registry or sockets."""

import gzip
import hashlib
import io
import json
import posixpath
import tarfile
from shared_models.oci_content import (
    OciContentFact,
    PackageRecord,
    PackageDatabase,
    DB_PATHS,
    content_resource,
    selected_bytes,
    seal,
)
from shared_models.oci_overlay import overlay, resolve, OPAQUE, WHITEOUT_PREFIX


def _path(name, directory=False):
    if name.startswith("./"):
        name = name[2:]
    if directory:
        name = name.rstrip("/")
    if name in {"", "."} and directory:
        return ""
    if (
        not name
        or len(name) > 1024
        or name.startswith("/")
        or "\\" in name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or any(p in {"", ".", ".."} for p in name.split("/"))
    ):
        raise ValueError("Unsafe/noncanonical image member")
    return name


def _target(path, name, hard=False):
    if not name or len(name) > 1024 or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Invalid image link")
    parts = [] if hard or name.startswith("/") else path.split("/")[:-1]
    for part in name.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ValueError("Image link escapes root")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise ValueError("Root-target link unsupported")
    return "/".join(parts)


def layer_view(raw, lower, index, member_budget):
    current, whiteouts, opaque = {}, set(), set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            member_budget[0] -= 1
            if member_budget[0] < 0:
                raise ValueError("Image member count limit")
            if member.issparse() or member.type not in {
                tarfile.REGTYPE,
                tarfile.AREGTYPE,
                tarfile.DIRTYPE,
                tarfile.SYMTYPE,
                tarfile.LNKTYPE,
            }:
                raise ValueError("Special/sparse image member refused")
            path = _path(member.name, member.isdir())
            if not path:
                continue
            if path in current:
                raise ValueError("Duplicate image member")
            name = path.split("/")[-1]
            if name.startswith(WHITEOUT_PREFIX):
                if not member.isfile() or member.size != 0:
                    raise ValueError("Whiteout must be an empty regular file")
                parent = posixpath.dirname(path)
                if name == OPAQUE:
                    opaque.add(parent)
                else:
                    if name[len(WHITEOUT_PREFIX) :] in {"", ".", ".."}:
                        raise ValueError("Empty/dot whiteout victim")
                    victim = _path("/".join(filter(None, (parent, name[len(WHITEOUT_PREFIX) :]))))
                    whiteouts.add(victim)
                current[path] = {"type": "whiteout"}
                continue
            value = {"type": "dir", "layer": index}
            if member.isfile():
                stream = archive.extractfile(member)
                data = stream.read(len(raw) + 1)
                if len(data) != member.size:
                    raise ValueError("Truncated/oversized image file")
                value = {
                    "type": "file",
                    "layer": index,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "data": data,
                }
            elif member.issym():
                if member.size != 0:
                    raise ValueError("Link with payload")
                value = {"type": "symlink", "layer": index, "target": _target(path, member.linkname)}
            elif member.islnk():
                target = _target(path, member.linkname, hard=True)
                # Freeze hardlink content at its archive position; refuse forward/non-file links.
                original = current.get(target)
                if not original or original["type"] != "file" or member.size != 0:
                    raise ValueError("Unresolved/non-file image hardlink")
                value = {**original, "layer": index}
            current[path] = value
        if len(raw) % 512 or len(raw) - archive.offset < 1024 or any(raw[archive.offset :]):
            raise ValueError("Nonzero/truncated/concatenated tar trailer")
    return overlay(lower, {p: v for p, v in current.items() if v["type"] != "whiteout"}, whiteouts, opaque)


def _collect_content(item, limit, charge):
    from inventory.host import _read, Refused
    from inventory.oci_image import collect_image
    from inventory.linux_packages import dpkg_status, apk_installed

    root, _, _, _ = content_resource(item.path)
    used = 0

    def counted(n):
        nonlocal used
        counted = min(n, max(0, limit - used))
        used += counted
        charge(counted)
        if n > counted:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")

    metadata_item = item.model_copy(
        update={"kind": "OCI_IMAGE_METADATA", "path": item.path.replace("oci-content://", "oci-layout://", 1)}
    )
    _, facts = collect_image(metadata_item, limit, counted)
    image = facts[0]
    view = {}
    members = [2048]
    for index, layer in enumerate(image.layers):
        blob = _read(root + "/blobs/sha256/" + layer.digest[7:], max(0, limit - used), counted)
        if len(blob) != layer.size or hashlib.sha256(blob).hexdigest() != layer.digest[7:]:
            raise ValueError("Layer content digest/size mismatch")
        if layer.media_type.endswith("+gzip"):
            with gzip.GzipFile(fileobj=io.BytesIO(blob)) as compressed:
                raw = compressed.read(max(0, limit - used) + 1)
            counted(len(raw))
        elif layer.media_type.endswith(".tar"):
            raw = blob  # Already charged; do not count identical uncompressed bytes twice.
        else:
            raise ValueError("Zstd is not qualified by this bounded content profile")
        if hashlib.sha256(raw).hexdigest() != layer.diff_id[7:]:
            raise ValueError("Uncompressed layer diff-ID mismatch")
        view = layer_view(raw, view, index, members)
    databases, packages = [], []
    for manager, path in DB_PATHS.items():
        resolved, entry = resolve(view, path)
        if entry is None:
            if resolved != path:
                raise ValueError("Dangling package database link")
            databases.append(PackageDatabase(manager=manager, path=path, status="NOT_PRESENT_IN_VERIFIED_VIEW"))
            continue
        if entry["type"] != "file":
            raise ValueError("Package database is not a regular virtual file")
        records = (dpkg_status if manager == "dpkg" else apk_installed)(entry["data"])
        # The nominal path is retained; digest/layer bind the resolved file contents.
        databases.append(
            PackageDatabase(
                manager=manager, path=path, status="PARSED", sha256=entry["sha256"], layer_index=entry["layer"]
            )
        )
        for record in records:
            packages.append(
                PackageRecord(
                    manager=manager,
                    name=record.software_name,
                    version=record.software_version,
                    source_path=path,
                    source_sha256=entry["sha256"],
                    layer_index=entry["layer"],
                )
            )
    if len(packages) > 500:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    tree = {p: {k: v for k, v in e.items() if k != "data"} for p, e in sorted(view.items())}
    rootfs_hash = hashlib.sha256(json.dumps(tree, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fact = seal(
        OciContentFact,
        identity_key=image.identity_key + ":content",
        image=image,
        rootfs_view_sha256=rootfs_hash,
        packages=sorted(packages, key=lambda p: (p.manager, p.name)),
        databases=databases,
    )
    data = selected_bytes(fact)
    counted(len(data))
    return data, [fact]


def collect_content(item, limit, charge):
    import zlib

    try:
        return _collect_content(item, limit, charge)
    except (tarfile.TarError, EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise ValueError("Invalid/truncated layer archive") from exc
