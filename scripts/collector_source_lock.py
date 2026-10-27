#!/usr/bin/env python3
"""Build the public bytes for an EXTERNAL collector source-lock signer."""

import argparse
import os
from pathlib import Path
from _bootstrap import bootstrap

bootstrap()
from inventory.collector_release import build_lock
from inventory.host import Refused


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        data = build_lock(args.root).model_dump_json(indent=2).encode()
        with os.fdopen(
            os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
        ) as out:
            out.write(data)
        return 0
    except (ValueError, OSError, Refused):
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
