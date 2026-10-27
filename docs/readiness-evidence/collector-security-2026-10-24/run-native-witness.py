"""Owned actual native/CLI witnesses; in-memory test signer, never bank trust."""

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap

bootstrap()
from inventory.isolation import collect_isolated
from shared_models.collection import TargetSpec
from shared_models.host_collection import HostManifest, HostInput, digest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def target(inputs):
    now = datetime.now(timezone.utc)
    return TargetSpec(
        target_key="owned-native-fixture",
        system_id="engineering-sandbox",
        owner="Engineering",
        environment="test",
        collection_method="offline_host",
        address="owned-local-fixture",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=now - timedelta(seconds=1),
        manifest=HostManifest(
            approval_reference="engineering/native-not-bank",
            host_id="owned-sandbox",
            environment="test",
            platform="linux",
            expires_at=now + timedelta(minutes=10),
            inputs=[HostInput(**i) for i in inputs],
        ),
    )


def run(command, expected):
    result = subprocess.run([sys.executable, *command], cwd=ROOT, capture_output=True, text=True, timeout=30)
    if result.returncode != expected:
        raise ValueError(f"Unexpected CLI exit {result.returncode}: {result.stdout} {result.stderr}")
    return result.returncode


def main():
    report = {
        "signer": "DISPOSABLE_IN_MEMORY_TEST_KEY_NOT_BANK_OR_RELEASE_SIGNER",
        "production_execution_qualified": False,
        "windows_native_execution": False,
    }
    with tempfile.TemporaryDirectory(prefix="cryptoscan-security-witness-") as owned:
        folder = Path(owned)
        actual = target([{"input_id": "os", "kind": "LINUX_OS_RELEASE", "path": "/usr/lib/os-release"}])
        snapshot, isolation = collect_isolated(actual)
        assert snapshot.receipts[0].status == "PARSED"
        report["actual_isolated_stage"] = isolation
        # Synthetic public/header/package inputs under ACTUAL kernel isolation.
        # This tests supported parsers in the sandbox, not a native RPM estate.
        from services.inventory.tests.test_host import certificate
        from services.inventory.tests.test_rpm_metadata import database, header

        contents = [
            ("PUBLIC_CERTIFICATE", certificate()),
            ("NGINX_TLS_CONFIG", b"ssl_protocols TLSv1.2 TLSv1.3;\n"),
            ("BINARY_METADATA", b"\x7fELFfixture-header-only"),
            ("DPKG_STATUS", b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.1\n\n"),
            ("APK_INSTALLED", b"P:openssl\nV:3.0.1-r0\n"),
            ("RPM_SQLITE", database([header()])),
        ]
        file_inputs = []
        for index, (kind, data) in enumerate(contents):
            file = folder / f"fixture-{index}"
            file.write_bytes(data)
            file_inputs.append({"input_id": f"fixture-{index}", "kind": kind, "path": str(file)})
        parsers, parser_isolation = collect_isolated(target(file_inputs))
        assert all(r.status == "PARSED" for r in parsers.receipts), parsers.receipts
        report["synthetic_inputs_actual_isolation"] = [
            {"kind": item.kind, "status": receipt.status, "facts": len(receipt.facts)}
            for item, receipt in zip(parsers.manifest.inputs, parsers.receipts)
        ]

        approval_time = actual.not_before
        private = Ed25519PrivateKey.generate()
        policy = {
            "key_id": "engineering-disposable",
            "public_key": base64.b64encode(
                private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ).decode(),
            "release_sha256": "a" * 64,
        }
        approval = {
            "subject_id": "12345678-1234-1234-1234-123456789abc",
            "created_at": approval_time.isoformat(),
            "payload": {
                "manifest_sha256": snapshot.manifest_sha256,
                "collector_identity": policy,
                "collector_nonce": "b" * 64,
            },
        }
        approval_file = folder / "approval.json"
        approval_file.write_text(json.dumps(approval))
        snapshot_file = folder / "snapshot.json"
        snapshot_file.write_text(snapshot.model_dump_json())
        prepared = folder / "statement.json"
        command = [
            "scripts/collector_identity.py",
            "prepare",
            "--approval",
            str(approval_file),
            "--snapshot",
            str(snapshot_file),
            "--output",
            str(prepared),
        ]
        report["prepare_exit"] = run(command, 0)
        assert prepared.stat().st_mode & 0o777 == 0o600
        statement = prepared.read_bytes()
        proof = folder / "proof.json"
        proof.write_text(
            json.dumps(
                {"statement": json.loads(statement), "signature": base64.b64encode(private.sign(statement)).decode()}
            )
        )
        verification = folder / "verified.json"
        report["verify_exit"] = run(
            [
                "scripts/collector_identity.py",
                "verify",
                "--approval",
                str(approval_file),
                "--snapshot",
                str(snapshot_file),
                "--proof",
                str(proof),
                "--output",
                str(verification),
            ],
            0,
        )
        report["signature_verification"] = json.loads(verification.read_text())
        report["overwrite_refusal_exit"] = run(command, 64)
        # Actual legacy SQLite public row timestamp representation is naive UTC.
        approval["created_at"] = approval_time.replace(tzinfo=None).isoformat()
        approval_file.write_text(json.dumps(approval))
        sqlite_statement = folder / "sqlite-statement.json"
        sqlite_command = command[:-1] + [str(sqlite_statement)]
        report["sqlite_public_timestamp_prepare_exit"] = run(sqlite_command, 0)

        for label, inputs, expectations in [
            (
                "native_os",
                [{"input_id": "os", "kind": "LINUX_OS_RELEASE", "path": "/usr/lib/os-release"}],
                [
                    {
                        "input_id": "os",
                        "facts": [{"kind": "OS_RELEASE", "software_name": "debian", "software_version": "12"}],
                    }
                ],
            ),
            (
                "native_required_interfaces",
                [
                    {
                        "input_id": "service",
                        "kind": "LINUX_SERVICE",
                        "path": "systemd://cryptoscan-nonexistent-witness.service",
                    },
                    {"input_id": "dmi", "kind": "LINUX_HARDWARE", "path": "linux-hardware://dmi"},
                    {"input_id": "tpm", "kind": "LINUX_HARDWARE", "path": "linux-hardware://tpm0"},
                ],
                [
                    {"input_id": "service", "facts": [{"kind": "SERVICE"}]},
                    {"input_id": "dmi", "facts": [{"kind": "HARDWARE"}]},
                    {"input_id": "tpm", "facts": [{"kind": "HARDWARE"}]},
                ],
            ),
        ]:
            approved = target(inputs)
            plan = {
                "schema_version": "cryptoscan.native-fixture/v1",
                "target_sha256": digest(approved),
                "reviewer_reference": "engineering/owned-not-independent",
                "expected": expectations,
            }
            tf = folder / (label + "-target.json")
            tf.write_text(approved.model_dump_json())
            pf = folder / (label + "-plan.json")
            pf.write_text(json.dumps(plan))
            output = folder / (label + "-result.json")
            report[label + "_exit"] = run(
                [
                    "scripts/qualify_host_profile.py",
                    "--target",
                    str(tf),
                    "--expectations",
                    str(pf),
                    "--output",
                    str(output),
                ],
                0 if label == "native_os" else 2,
            )
            report[label] = json.loads(output.read_text())
    report["owned_temporary_directory_removed"] = not folder.exists()
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
