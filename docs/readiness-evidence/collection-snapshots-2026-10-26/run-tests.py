"""Run bounded collection snapshot regression suites on an explicit source tree."""

import argparse
import os
from pathlib import Path
import subprocess
import sys

API = "services/api/tests/unit/"
SUITES = {
    "models-inventory": ["shared/shared_models/tests", "services/inventory/tests"],
    "graph-drift": ["services/graph_engine/tests", "services/drift/tests"],
    "workflow": [
        API + "test_" + name + ".py"
        for name in ("collection_foundation", "collection_views_api", "oci_collection_api", "oci_truth_api")
    ],
    "host-compatibility": [
        API + "test_" + name + ".py"
        for name in (
            "host_associations",
            "host_evidence",
            "host_worker",
            "linux_phase2_projections",
            "linux_software_inventory",
        )
    ],
    "adapter-compatibility": [
        API + "test_" + name + ".py"
        for name in (
            "oci_metadata_candidate",
            "container_content_candidate",
            "tls_session_candidate",
            "tls_key_share_candidate",
            "tls_hybrid_candidate",
            "windows_metadata_candidates",
        )
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    root = args.root.resolve()
    output = Path(__file__).resolve().parent
    env = os.environ.copy()
    env["PYTHONPATH"] = ":".join(
        [str(root), str(root / "scripts"), str(root / "services/api/tests/unit")]
        + [str(p) for folder in ("services", "shared") for p in (root / folder).iterdir() if p.is_dir()]
    )
    if args.suite == "workflow":
        env["CRYPTOSCAN_COLLECTION_VIEWS_WITNESS_DIR"] = str(output / "public-witness")
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *SUITES[args.suite],
        "-q",
        "--tb=short",
        "--junitxml=" + str(output / (args.suite + ".xml")),
    ]
    (output / (args.suite + "-command.txt")).write_text(" ".join(cmd) + "\n")
    with (output / (args.suite + ".txt")).open("w") as log:
        result = subprocess.run(cmd, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    print("\n".join((output / (args.suite + ".txt")).read_text().splitlines()[-5:]))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
