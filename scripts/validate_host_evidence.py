#!/usr/bin/env python3
"""Opt-in, unprivileged, owned disposable PostgreSQL host-evidence witness.

No customer URL, collector execution, external network or production change.
Requires the optional pgserver validation dependency, not a product dependency.
"""

import argparse
import os
from pathlib import Path
import tempfile

from _bootstrap import bootstrap

bootstrap()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-local-synthetic", action="store_true", required=True)
    parser.add_argument("--junitxml", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="cryptoscan-host-witness-", dir=Path.home()) as owned:
        root = Path(owned)
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        import pgserver
        from sqlalchemy import create_engine, text
        from sqlalchemy.engine import make_url

        server = pgserver.get_server(root / "pgdata", cleanup_mode="delete")
        try:
            url = make_url(server.get_uri()).set(drivername="postgresql+psycopg2")
            engine = create_engine(url)
            with engine.connect() as connection:
                print("Owned disposable backend:", connection.execute(text("SELECT version()")).scalar())
            engine.dispose()
            os.environ["CRYPTOSCAN_PROVENANCE_TEST_DATABASE_URL"] = url.set(
                database="cryptoscan_e2e_host_base"
            ).render_as_string(hide_password=False)
            import sys

            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/api/tests/unit"))
            import pytest

            return pytest.main(
                ["-q", "services/api/tests/unit/test_host_evidence_postgres.py", "--junitxml=" + args.junitxml]
            )
        finally:
            server.cleanup()
            print("Owned PostgreSQL cleanup completed; no customer deployment touched.")


if __name__ == "__main__":
    raise SystemExit(main())
