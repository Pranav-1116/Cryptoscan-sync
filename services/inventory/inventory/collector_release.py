"""External Ed25519-signed stage source lock + measured interpreter file.

Runs the verified source COPY, not a hash-then-import of mutable checkout files.
This is installed-source binding, NOT host/boot/dependency or runtime attestation.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys
from contextlib import contextmanager
import tempfile
from pydantic import Field
from shared_models.host_common import Strict
from shared_models.host_collection import Digest
from shared_models.collector_identity import decode
from shared_models.qualified_export import bounded_json

ROOTS = ("services/inventory/inventory/", "shared/shared_models/shared_models/")
SCRIPTS = {"scripts/_bootstrap.py", "scripts/_isolated_host_stage.py"}
MAX_FILES = 256
MAX_BYTES = 8 * 1024 * 1024


class SourceLock(Strict):
    schema_version: str = Field(pattern=r"^cryptoscan.collector-source-lock/v1$")
    interpreter_sha256: Digest
    files: dict[str, Digest] = Field(min_length=1, max_length=MAX_FILES)


def permitted(path):
    parts = path.split("/")
    return (
        not any(p in {"", ".", ".."} or p.startswith(".") for p in parts)
        and "\\" not in path
        and (path in SCRIPTS or path.startswith(ROOTS) and Path(path).suffix in {".py", ".json", ".csv"})
    )


def read_regular(path, limit):
    # Descriptor-relative traversal pins every no-follow ancestor.
    from inventory.host import _linux_fd

    with _linux_fd(str(path)) as fd:
        before = os.fstat(fd)
        if before.st_size > limit:
            raise ValueError("Release artifact size limit")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("Release artifact size limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Release artifact changed")
        return bytes(data)


def source_files(root):
    root = Path(root).absolute()
    paths = set(SCRIPTS)
    for prefix in ROOTS:
        base = root / prefix
        for item in base.rglob("*"):
            if item.is_symlink():
                raise ValueError("Release source symlink")
            if item.is_file() and item.suffix in {".py", ".json", ".csv"} and "__pycache__" not in item.parts:
                paths.add(item.relative_to(root).as_posix())
    if len(paths) > MAX_FILES:
        raise ValueError("Release file limit")
    return sorted(paths)


def build_lock(root):
    root = Path(root).absolute()
    files = {}
    total = 0
    for path in source_files(root):
        data = read_regular(root / path, MAX_BYTES - total)
        total += len(data)
        files[path] = hashlib.sha256(data).hexdigest()
    binary = read_regular(Path(sys.executable).resolve(), 32 * 1024 * 1024)
    return SourceLock(
        schema_version="cryptoscan.collector-source-lock/v1",
        interpreter_sha256=hashlib.sha256(binary).hexdigest(),
        files=files,
    )


@contextmanager
def verified_stage(root, lock_bytes, signature, public_key, expected_sha):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    root = Path(root).absolute()
    if len(lock_bytes) > 65536 or hashlib.sha256(lock_bytes).hexdigest() != expected_sha:
        raise ValueError("Unpinned collector source lock")
    try:
        Ed25519PublicKey.from_public_bytes(decode(public_key, 32)).verify(decode(signature, 64), lock_bytes)
    except InvalidSignature:
        raise ValueError("Collector release signature failed") from None
    lock = SourceLock.model_validate(bounded_json(lock_bytes, max_bytes=65536))
    required = SCRIPTS | {
        "services/inventory/inventory/__init__.py",
        "services/inventory/inventory/host.py",
        "services/inventory/inventory/isolation.py",
        "shared/shared_models/shared_models/__init__.py",
        "shared/shared_models/shared_models/host_collection.py",
    }
    if not required <= lock.files.keys() or any(not permitted(path) for path in lock.files):
        raise ValueError("Collector source lock path scope")
    if (
        hashlib.sha256(read_regular(Path(sys.executable).resolve(), 32 * 1024 * 1024)).hexdigest()
        != lock.interpreter_sha256
    ):
        raise ValueError("Collector interpreter file mismatch")
    with tempfile.TemporaryDirectory(prefix="cryptoscan-verified-stage-") as staging:
        total = 0
        for path, expected in sorted(lock.files.items()):
            data = read_regular(root / path, MAX_BYTES - total)
            total += len(data)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("Installed collector source mismatch")
            dest = Path(staging) / path
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(dest, "xb") as output:
                output.write(data)
            dest.chmod(stat.S_IRUSR)
        yield (
            Path(staging),
            {
                "source_lock_sha256": expected_sha,
                "verified_source_files": len(lock.files),
                "interpreter_file_sha256": lock.interpreter_sha256,
                "host_attested": False,
                "dependencies_attested": False,
            },
        )
