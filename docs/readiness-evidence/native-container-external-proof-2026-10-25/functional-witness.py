"""Owned engineering vectors: actual software signatures / actual namespace fixture / signed fixture register."""

from pathlib import Path
from datetime import datetime, timezone
import json
import platform
from shared.shared_models.tests.test_operation_evidence_v2 import packet
from shared.shared_models.tests.test_software_estate import fixture
from shared_models.operation_evidence_v2 import verify_operation_v2
from shared_models.software_estate import reconcile_estate
from shared_models.tpm_quote_verification import sha
from inventory.collector_release import build_lock
from qualify_owned_namespace_container import fixture_plan, run_owned

vectors = []
for mechanism in ["RSA_PKCS1_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"]:
    approval, evidence, now, _ = packet(mechanism)
    vectors.append(
        {
            "fixture_basis": "EPHEMERAL_SOFTWARE_KEYS_NOT_CUSTOMER_OR_HSM",
            "approval": approval.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"),
            "verification": verify_operation_v2(approval, evidence, now),
        }
    )
plan, returns, artifacts, now = fixture()
report = {
    "schema_version": "cryptoscan.external-proof-path-functional-witness/v1",
    "baseline": "a434e5eb3415c4506563a833d105b7b9f1c7e0b5",
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "kernel": platform.release(),
    "source_lock_sha256": sha(build_lock(Path.cwd())),
    "source_lock_files": len(build_lock(Path.cwd()).files),
    "software_signature_vectors": vectors,
    "estate_fixture": {
        "basis": "SIGNED_TWO_ASSET_FIXTURE_NOT_REAL_ESTATE",
        "plan": plan.model_dump(mode="json"),
        "packet": returns.model_dump(mode="json"),
        "source_artifacts": {k: v.decode() for k, v in artifacts.items()},
        "result": reconcile_estate(plan, returns, artifacts, now),
    },
    "native_namespace_container": run_owned(sha(fixture_plan())),
    "customer_application_or_physical_hsm_executed": False,
    "actual_windows_executed": False,
    "docker_or_kubernetes_qualified": False,
    "whole_estate_software_complete": False,
    "independent_acceptance": False,
    "production_execution_qualified": False,
}
Path("/home/user/next-proof-functional-witness.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print("Actual software signature mechanisms:", [v["verification"]["mechanism"] for v in vectors])
print(
    "Signed fixture register:",
    report["estate_fixture"]["result"]["matched_units"],
    "of",
    report["estate_fixture"]["result"]["required_units"],
    "units; not actual estate truth",
)
print(
    "Actual owned namespace-container:",
    report["native_namespace_container"]["actual_native_namespace_execution"],
    "cancellation:",
    report["native_namespace_container"]["cancellation_exercised"],
    "cleanup:",
    report["native_namespace_container"]["owned_work_directory_removed"],
)
print(
    "Customer/physical HSM, Windows, Docker/Kubernetes, authoritative estate, independent/production acceptance: NOT executed/qualified."
)
