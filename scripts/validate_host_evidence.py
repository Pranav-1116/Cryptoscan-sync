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
    parser.add_argument(
        "--include-associations", action="store_true", help="Also qualify the host-to-estate association adapter"
    )
    parser.add_argument(
        "--include-foundation", action="store_true", help="Also qualify universal registry/jobs and Linux extension"
    )
    parser.add_argument(
        "--include-worker",
        action="store_true",
        help="Also exercise the development local worker and actual SQL claim races",
    )
    parser.add_argument(
        "--include-qualification",
        action="store_true",
        help="Also exercise named-human evidence receipt, signatures, atomic audit and SQL revision races",
    )
    parser.add_argument(
        "--include-surface-coverage",
        action="store_true",
        help="Check read-only per-surface coverage over existing evidence",
    )
    parser.add_argument(
        "--include-linux-software", action="store_true", help="Check Linux software projections over original evidence"
    )
    parser.add_argument(
        "--include-linux-projections",
        action="store_true",
        help="Check Linux relationships and official CycloneDX export",
    )
    parser.add_argument(
        "--include-windows-certificate-candidate",
        action="store_true",
        help="Check portable Windows certificate receipt custody, not native qualification",
    )
    parser.add_argument(
        "--include-windows-image-candidate",
        action="store_true",
        help="Check portable Windows process/module custody, not native qualification",
    )
    parser.add_argument(
        "--include-windows-cng-candidate",
        action="store_true",
        help="Check portable CNG registration custody, not native qualification",
    )
    parser.add_argument(
        "--include-windows-tpm-candidate",
        action="store_true",
        help="Check portable Windows TPM metadata custody, not native qualification",
    )
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

            files = ["services/api/tests/unit/test_host_evidence_postgres.py"]
            if args.include_associations:
                files.append("services/api/tests/unit/test_host_associations_postgres.py")
            if args.include_foundation:
                files.append("services/api/tests/unit/test_collection_foundation_postgres.py")
            if args.include_worker:
                files.append("services/api/tests/unit/test_host_worker_postgres.py")
            if args.include_qualification:
                files.append("services/api/tests/unit/test_qualification_workflow_postgres.py")
            if args.include_surface_coverage:
                files.append("services/api/tests/unit/test_collection_surface_coverage_postgres.py")
            if args.include_linux_software:
                files.append("services/api/tests/unit/test_linux_software_inventory_postgres.py")
            if args.include_linux_projections:
                files.append("services/api/tests/unit/test_linux_phase2_projections_postgres.py")
            if args.include_windows_certificate_candidate:
                files.append("services/api/tests/unit/test_windows_certificate_candidate_postgres.py")
            if args.include_windows_image_candidate:
                files.append("services/api/tests/unit/test_windows_image_candidate_postgres.py")
            if args.include_windows_cng_candidate:
                files.append("services/api/tests/unit/test_windows_cng_candidate_postgres.py")
            if args.include_windows_tpm_candidate:
                files.append("services/api/tests/unit/test_windows_tpm_candidate_postgres.py")
            return pytest.main(["-q", *files, "--junitxml=" + args.junitxml])
        finally:
            server.cleanup()
            print("Owned PostgreSQL cleanup completed; no customer deployment touched.")


if __name__ == "__main__":
    raise SystemExit(main())
