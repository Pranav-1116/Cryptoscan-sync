"""Bounded local public-artifact IO and Linux verifier-owned challenge storage.

No network, private signing key, arbitrary command or automatic challenge reset.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys
from shared_models.qualified_export import bounded_json
from shared_models.tpm_quote_verification import canonical


def read_public(path, limit):
    from inventory.host import _linux_fd, _windows_fd

    opener = _windows_fd if sys.platform == "win32" else _linux_fd
    with opener(str(Path(path).absolute())) as fd:
        before = os.fstat(fd)
        data = bytearray()
        if before.st_size > limit:
            raise ValueError("Artifact size bound")
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("Artifact size bound")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("Artifact changed while reading")
        return bytes(data)


def read_json(path, limit=131072):
    return bounded_json(read_public(path, limit), max_bytes=limit)


def exclusive_public(path, data):
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
    ) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class ChallengeStore:
    """Local Linux verifier state, not an attested or distributed authority.

    A consumed marker IS the durable report, so a failed downstream output copy
    can be recovered without accepting the proof again. A partial crash marker
    fails closed; only explicit operator review can resolve it.
    """

    def __init__(self, root):
        if not sys.platform.startswith("linux"):
            raise ValueError("Challenge storage requires qualified Linux file semantics")
        self.root = Path(root).absolute()
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(self.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(self.fd)
            raise ValueError("Verifier-owned mode-0700 state directory required")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)

    def name(self, identifier, suffix):
        import re

        if not re.fullmatch("[0-9a-f]{32}", identifier):
            raise ValueError("Invalid challenge ID")
        return identifier + suffix

    def write(self, identifier, suffix, data):
        name = self.name(identifier, suffix)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)

    def issue(self, challenge):
        self.write(challenge.challenge_id, ".challenge.json", canonical(challenge))

    def get(self, identifier):
        from shared_models.tpm_quote_verification import QuoteChallenge

        fd = os.open(
            self.name(identifier, ".challenge.json"),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=self.fd,
        )
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("Challenge storage permissions/type changed")
            data = stream.read(8193)
        challenge = QuoteChallenge.model_validate(bounded_json(data, max_bytes=8192))
        if challenge.challenge_id != identifier:
            raise ValueError("Challenge file identity mismatch")
        return challenge

    def consume(self, challenge, report):
        if canonical(self.get(challenge.challenge_id)) != canonical(challenge):
            raise ValueError("Challenge changed")
        self.write(
            challenge.challenge_id,
            ".accepted.json",
            canonical({"challenge_sha256": hashlib.sha256(canonical(challenge)).hexdigest(), "report": report}),
        )
