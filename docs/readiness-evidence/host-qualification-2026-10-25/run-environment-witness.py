"""Read-only current-host evidence. Never substitutes fixtures for native passes."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from inventory.collector_release import build_lock
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostInput, HostManifest
from shared_models.qualification_acceptance import NativePlan, NativeEvidence, evaluate_native
from shared_models.tpm_quote_verification import canonical, sha


def main():
    result = {
        "native_os": platform.system(),
        "hardware_origin_verified": False,
        "independent_reviews_supplied": False,
        "production_execution_qualified": False,
        "categories": {},
    }
    with tempfile.TemporaryDirectory(prefix="cryptoscan-qualification-environment-") as owned:
        root = Path(owned)
        lock = root / "source-lock.json"
        lock.write_bytes(canonical(build_lock(ROOT)))
        for category, kind, path, pattern in [
            (
                "systemd",
                "LINUX_SERVICE",
                "systemd://dbus.service",
                {"kind": "SERVICE", "service_name": "dbus.service", "service_state": "active"},
            ),
            ("dmi", "LINUX_HARDWARE", "linux-hardware://dmi", {"kind": "HARDWARE", "hardware_type": "SYSTEM_DMI"}),
            (
                "tpm",
                "LINUX_HARDWARE",
                "linux-hardware://tpm0",
                {"kind": "HARDWARE", "hardware_type": "TPM", "tpm_major_version": 2},
            ),
            (
                "windows",
                "WINDOWS_SERVICE",
                "windows-service://EventLog",
                {"kind": "SERVICE", "service_name": "EventLog", "service_state": "RUNNING"},
            ),
        ]:
            now = datetime.now(timezone.utc)
            manifest = HostManifest(
                approval_reference="engineering/negative-environment-witness",
                host_id="owned-verifier-host",
                environment="test",
                platform="windows" if category == "windows" else "linux",
                expires_at=now + timedelta(minutes=10),
                inputs=[HostInput(input_id="native", kind=kind, path=path)],
            )
            target = TargetSpec(
                target_key="owned-" + category,
                system_id="owned-engineering",
                owner="Engineering",
                environment="test",
                collection_method="offline_host",
                address="owned-verifier-host",
                allowed_operations=["READ_APPROVED_METADATA"],
                not_before=now - timedelta(seconds=1),
                manifest=manifest,
            )
            plan = NativePlan(
                target_sha256=sha(target),
                expected=[{"input_id": "native", "facts": [pattern]}],
                reviewer_reference="negative-engineering-not-independent-approval",
            )
            target_file = root / "target.json"
            plan_file = root / "plan.json"
            output = root / (category + ".json")
            target_file.write_bytes(canonical(target))
            plan_file.write_bytes(canonical(plan))
            command = [
                sys.executable,
                str(ROOT / "scripts/capture_native_qualification.py"),
                "--category",
                category,
                "--target",
                str(target_file),
                "--plan",
                str(plan_file),
                "--source-lock",
                str(lock),
                "--approved-plan-sha256",
                sha(plan),
                "--output",
                str(output),
            ]
            run = subprocess.run(command, capture_output=True, timeout=15, cwd=ROOT)
            record = {"exit": run.returncode, "artifact_written": output.exists(), "positive_native_qualified": False}
            if output.exists():
                evidence = NativeEvidence.model_validate_json(output.read_bytes())
                record.update(
                    evaluation=evaluate_native(evidence),
                    receipts=[
                        {"input_id": r.input_id, "status": r.status, "reason": r.reason, "facts": len(r.facts)}
                        for r in evidence.snapshot.receipts
                    ],
                )
            else:
                record["reason"] = "NATIVE_OS_OR_EXECUTION_REFUSED"
            assert run.returncode in {2, 64}, (
                "Unexpected positive; obtain independently approved expected truth before accepting it"
            )
            result["categories"][category] = record
    result["owned_temporary_directory_removed"] = not root.exists()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
