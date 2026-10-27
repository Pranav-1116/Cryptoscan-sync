"""Build provenance inventory and independent-validation intake, not certification."""

import hashlib
import json
import platform
from pathlib import Path
import subprocess
import tarfile

from tools.disposable_tbf.build import sha
from tools.disposable_tbf.runner import canonical, strict_json
from tools.routed_tbf.authority import verify

HERE = Path(__file__).resolve().parent


def environment():
    def output(args):
        p = subprocess.run(args, capture_output=True, text=True, timeout=10, check=True)
        return p.stdout.strip()

    record = {
        "os_release": Path("/etc/os-release").read_text(),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "compiler": output(["/usr/bin/gcc", "--version"]),
        "system_python_sha256": sha("/usr/bin/python3.11"),
        "system_libc_sha256": sha("/lib/x86_64-linux-gnu/libc.so.6"),
        "compiler_sha256": sha("/usr/bin/gcc"),
    }
    record["environment_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    return record


def inventory(cache):
    lock = strict_json((HERE / "assets.lock.json").read_bytes())
    records = []
    for a in lock["assets"]:
        archive = cache / (a["name"] + "-source.tar.gz")
        if archive.is_symlink() or archive.stat().st_size != a["bytes"] or sha(archive) != a["sha256"]:
            raise ValueError("dependency archive commitment")
        licenses = []
        with tarfile.open(archive) as tar:
            for m in tar:
                if m.isfile() and Path(m.name).name.lower() in (
                    "copying",
                    "copying.lib",
                    "copyright",
                    "license",
                    "license.txt",
                    "license.md",
                ):
                    if m.size > 262144:
                        continue
                    raw = tar.extractfile(m).read()
                    licenses.append(
                        {
                            "path": m.name,
                            "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "excerpt": raw[:300].decode(errors="replace"),
                        }
                    )
                    if len(licenses) >= 20:
                        break
        records.append(
            {
                "name": a["name"],
                "url": a["url"],
                "sha256": a["sha256"],
                "bytes": a["bytes"],
                "license_files": licenses,
                "license_review": "PENDING" if licenses else "UNKNOWN_NO_LICENSE_FILE_FOUND",
                "upstream_authenticity": "UNVERIFIED",
                "vulnerability_review": "UNKNOWN_NOT_INDEPENDENTLY_REVIEWED",
            }
        )
    return {
        "version": "LAB_DEPENDENCY_REVIEW_V1",
        "assets": records,
        "environment": environment(),
        "system_runtime_inventory": "See bundle guest_runtime_files and emulator file hashes; not a complete licensed component SBOM.",
        "release_gate": "BLOCKED_PENDING_LICENSE_SECURITY_AND_INDEPENDENT_REVIEW",
        "second_supported_environment_completed": False,
        "independent_review_completed": False,
        "reproducibility": "NOT_ESTABLISHED",
        "production_execution_qualified": False,
    }


def compare(local, peer, trusted_reviewer_public_key):
    """Accept only an externally pinned reviewer key, different environment, exact profile.
    A signature authenticates the supplied review record, not reviewer competence or
    physical-machine identity. The operator must independently establish key ownership.
    """
    verify(trusted_reviewer_public_key, peer["signature"], peer["payload"])
    p = peer["payload"]
    if (
        p["environment"]["environment_sha256"] == local["environment"]["environment_sha256"]
        or p["profile_sources"] != local["profile_sources"]
        or p["acceptance_sha256"] != local["acceptance_sha256"]
        or p["result_verdict"] != "LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES"
        or not p["independent_reviewer"]
        or not p["reviewed_launcher_and_runtime"]
        or p["production_execution_qualified"] is not False
    ):
        raise ValueError("independent validation evidence incomplete or not a distinct environment")
    changes = {
        k: {"local": v, "peer": p["binary_hashes"].get(k)}
        for k, v in local["binary_hashes"].items()
        if p["binary_hashes"].get(k) != v
    }
    return {
        "status": "SIGNED_EXTERNAL_REVIEW_RECORD_ACCEPTED_NOT_SECURITY_CERTIFICATION",
        "build_differences": changes,
        "production_execution_qualified": False,
    }


def validation_record(bundle, receipt, expected_receipt_sha256, trusted_adapter_public_key):
    from tools.routed_tbf.runner import verify_receipt, verify_bundle, source_bindings

    verdict = verify_receipt(receipt, expected_receipt_sha256, trusted_adapter_public_key)
    manifest_path = bundle / "bundle.json"
    verify_bundle(bundle, sha(manifest_path))
    manifest = strict_json(manifest_path.read_bytes())
    return {
        "environment": environment(),
        "profile_sources": source_bindings(),
        "acceptance_sha256": sha(HERE / "acceptance.json"),
        "binary_hashes": {r["path"]: r["sha256"] for r in manifest["files"]},
        "result_sha256": expected_receipt_sha256,
        "result_verdict": verdict,
        "independent_reviewer": None,
        "reviewed_launcher_and_runtime": False,
        "production_execution_qualified": False,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inventory")
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("record")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    p.add_argument("--receipt-sha256", required=True)
    p.add_argument("--trusted-adapter-public-key", required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("compare")
    p.add_argument("--local", type=Path, required=True)
    p.add_argument("--peer", type=Path, required=True)
    p.add_argument("--trusted-reviewer-public-key", required=True)
    args = parser.parse_args()
    if args.command == "record":
        result = validation_record(args.bundle, args.receipt, args.receipt_sha256, args.trusted_adapter_public_key)
        with args.output.open("x") as f:
            f.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    elif args.command == "inventory":
        result = inventory(args.cache)
        with args.output.open("x") as f:
            f.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    else:
        print(
            json.dumps(
                compare(
                    strict_json(args.local.read_bytes()),
                    strict_json(args.peer.read_bytes()),
                    args.trusted_reviewer_public_key,
                ),
                sort_keys=True,
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
