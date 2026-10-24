#!/usr/bin/env python3
"""Run one administrator-bound development host job; external signing follows."""

import argparse
import os
from pathlib import Path
from uuid import UUID
from _bootstrap import bootstrap

bootstrap()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--acknowledge-local-development", action="store_true", required=True)
    p.add_argument("--binding", type=Path, required=True)
    p.add_argument("--source-lock", type=Path, required=True)
    p.add_argument("--release-signature", type=Path, required=True)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--job-id", type=UUID, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    from inventory.collector_release import read_regular
    from shared_models.host_worker import LocalWorkerBinding
    from shared_models.qualified_export import bounded_json
    from db.connection.session import SessionLocal, configure_session

    configure_session()
    from api.assurance.host_worker import run_local

    try:
        # Binding path is supplied by the local administrator, never a queue.
        binding = LocalWorkerBinding.model_validate(bounded_json(read_regular(a.binding, 8192), max_bytes=8192))
        if a.output.exists() or a.output.is_symlink():
            raise ValueError("Output already exists")
        snapshot = run_local(
            SessionLocal,
            binding,
            str(a.job_id),
            a.root,
            read_regular(a.source_lock, 65536),
            read_regular(a.release_signature, 128).decode("ascii").strip(),
        )
        with os.fdopen(
            os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb"
        ) as out:
            out.write(snapshot.model_dump_json(indent=2).encode())
        return 0
    except Exception:
        # Do not leak source paths, SQL credentials or artifact content.
        print("LOCAL_WORKER_REFUSED", file=__import__("sys").stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
