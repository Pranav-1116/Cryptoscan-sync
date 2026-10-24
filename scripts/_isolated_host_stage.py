# ruff: noqa: F401
"""Private fixed child entry. Parent owns pipes/deadline; never run in API."""

import json
import os
import sys
from _bootstrap import bootstrap

bootstrap()
# Preload all parsers/native modules before restricting filesystem imports.
from inventory.host import collect
from inventory.isolation import install, approved_paths, set_limits
from inventory.linux_packages import apk_installed
from inventory.rpm_metadata import rpm_sqlite
from shared_models.collection import TargetSpec
from shared_models.qualified_export import bounded_json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from inventory.collection import OfflineLinuxCollector


def main():
    try:
        target = TargetSpec.model_validate(bounded_json(sys.stdin.buffer.read(131073), max_bytes=131072))
        OfflineLinuxCollector().validate_scope(target)
        paths = approved_paths(target.manifest)
        set_limits()
        isolation = install(paths)
        snapshot = collect(target.manifest)
        output = json.dumps(
            {"snapshot": snapshot.model_dump(mode="json"), "isolation": isolation},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(output) > 1500000:
            raise ValueError("Result limit")
        while output:
            written = os.write(1, output)
            if written <= 0:
                raise OSError("Closed result pipe")
            output = output[written:]
        return 0
    except (ValueError, OSError):
        os.write(2, b"Isolated collector refused; no fallback\n")
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
