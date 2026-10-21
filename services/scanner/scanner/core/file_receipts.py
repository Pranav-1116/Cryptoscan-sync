"""Bounded file-byte identity around source parsing (not estate completeness).

Controlled production staging is private and the parser input is read-only.
Legacy mutable targets can only establish matching before/after hashes, not an
atomic filesystem snapshot. Archives/secondary collectors need their own proof.
"""
import hashlib
import os
import stat

MAX_RECEIPTS = 1000
MAX_FIXTURE_BYTES = 1048576


def capture(root, paths):
    result = {}
    for path in sorted(paths)[:MAX_RECEIPTS]:
        try:
            relative = path.relative_to(root).as_posix()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FIXTURE_BYTES:
                    continue
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(MAX_FIXTURE_BYTES + 1)
                if len(data) > MAX_FIXTURE_BYTES:
                    continue
                result[relative] = hashlib.sha256(data).hexdigest()
            finally:
                os.close(fd)
        except (OSError, ValueError):
            continue  # no invented hash; absence blocks fixture/negative proof
    return result


def finish(root, paths, before, parsed):
    after = capture(root, paths)
    parsed = {p.relative_to(root).as_posix() for p in parsed}
    return [{"file": name, "sha256": sha, "parser_completed": True,
             "binding": "MATCHING_BEFORE_AFTER_HASHES_NOT_AN_ATOMIC_MUTABLE_SNAPSHOT"}
            for name, sha in sorted(before.items()) if after.get(name) == sha and name in parsed]
