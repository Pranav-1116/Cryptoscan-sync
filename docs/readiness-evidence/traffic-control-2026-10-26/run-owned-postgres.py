"""Reproduce the isolated traffic validation gate on a fresh owned PostgreSQL; no existing DB URL is used."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from pgserver import get_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    root = args.root.resolve()
    output = Path(__file__).resolve().parent
    parent = Path(tempfile.mkdtemp(prefix="cryptoscan-owned-traffic-pg-", dir=Path.home()))
    pgdata = parent / "pgdata"
    try:
        with get_server(pgdata, cleanup_mode="delete") as server:
            env = os.environ.copy()
            env["CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL"] = server.get_uri(
                database="cryptoscan_e2e_traffic_control"
            ).replace("postgresql://", "postgresql+psycopg2://", 1)
            env["PYTHONPATH"] = ":".join(
                [str(root), str(root / "scripts"), str(root / "services/api/tests/unit")]
                + [str(p) for folder in ("services", "shared") for p in (root / folder).iterdir() if p.is_dir()]
            )
            with (output / "postgres-tests.txt").open("w") as log:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "services/api/tests/unit/test_traffic_control_postgres.py",
                        "-q",
                        "--junitxml=" + str(output / "postgres-tests.xml"),
                    ],
                    cwd=root,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=180,
                )
        return result.returncode
    finally:
        if pgdata.exists():
            raise RuntimeError("Owned PostgreSQL cleanup incomplete")
        parent.rmdir()
        (output / "postgres-cleanup.txt").write_text("Owned server stopped; temporary pgdata and parent removed.\n")


if __name__ == "__main__":
    raise SystemExit(main())
