"""Owned-only actual TCP/software-signature/dpkg-record witness, not native qualification."""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone, timedelta
from services.inventory.tests.test_tls_hybrid import hybrid_server, hybrid_target
from shared.shared_models.tests.test_operation_evidence import packet
from inventory.collection import ApprovedTlsSessionCollector
from inventory.host import collect
from shared_models.host_collection import HostManifest, HostInput, digest
from shared_models.software_truth import SoftwareTruthPlan, ExpectedSoftwareInput, ExpectedPackage, reconcile_software
from shared_models.operation_evidence import verify_operation
from shared_models.tpm_quote_verification import sha
from inventory.collector_release import build_lock

with hybrid_server() as state:
    target = hybrid_target(state)
    snapshot = ApprovedTlsSessionCollector(include_hybrid=True).collect(target)
    f = snapshot.receipts[0].facts[0]
    assert state["done"].wait(2) and state["completed"] and state["connections"] == 1
    hybrid = {
        "verdict": "ACTUAL_OWNED_TCP_HYBRID_HANDSHAKE_COMPLETED",
        "both_peers_completed": True,
        "connections": state["connections"],
        "peer_pin_matched": f.peer_fingerprint_matched,
        "target_sha256": sha(target),
        "snapshot_sha256": digest(snapshot),
        "interface_sha256": f.interface_sha256,
        "selected_group_id": f.selected_group_id,
        "group": f.key_exchange_group,
        "cipher": f.cipher_suite,
        "server_hello_bytes": len(bytes.fromhex(f.server_hello_hex)),
        "openssl_version": f.openssl_version,
        "pyopenssl_version": f.pyopenssl_version,
        "cryptography_version": f.cryptography_version,
        "provider_identity_basis": f.provider_identity_basis,
        "pqc_readiness_verified": False,
        "application_hsm_operation_use": "UNKNOWN",
        "customer_endpoint_tested": False,
        "production_execution_qualified": False,
    }
a, e, now = packet()
operation = verify_operation(a, e, now)
operation.update(
    actual_signature_implementation="EPHEMERAL_SOFTWARE_ED25519_FIXTURE",
    actual_hsm_provider_called=False,
    signing_private_keys_retained=False,
)
status = Path("/var/lib/dpkg/status")
before = hashlib.sha256(status.read_bytes()).hexdigest()
query = subprocess.run(
    ["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}\t${Package}\t${Version}\n"],
    capture_output=True,
    check=True,
    timeout=5,
)
expected = []
for line in query.stdout.decode().splitlines():
    state, name, version = line.split("\t")
    if state == "installed":
        expected.append(ExpectedPackage(name=name, version=version))
m = HostManifest(
    approval_reference="owned-sandbox/read-only-package-database",
    host_id="owned-sandbox-package-records",
    environment="test",
    platform="linux",
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    inputs=[HostInput(input_id="dpkg-status", kind="DPKG_STATUS", path=str(status))],
)
s = collect(m)
p = SoftwareTruthPlan(
    manifest_sha256=digest(m),
    reviewer_reference="owned-agent-check-not-independent-review",
    inputs=[
        ExpectedSoftwareInput(
            input_id="dpkg-status", kind="DPKG_STATUS", expected_content_sha256=before, records=expected
        )
    ],
)
software = reconcile_software(p, s)
assert hashlib.sha256(status.read_bytes()).hexdigest() == before and software["agreed_package_record_coverage_verified"]
software.update(
    actual_source="/var/lib/dpkg/status",
    source_bytes=status.stat().st_size,
    source_sha256=before,
    separate_implementation_truth_command="dpkg-query -W with installed-state Package/Version fields",
    truth_command_stdout_sha256=hashlib.sha256(query.stdout).hexdigest(),
    expected_records=len(expected),
    source_unchanged_across_measurement=True,
    independent_human_reviewed=False,
    product_collector_executes_package_tools=False,
)
report = {
    "schema_version": "cryptoscan.owned-functional-witness/v1",
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "baseline": "7b06710118fa5efd14bad223e543176544df15bd",
    "source_lock_sha256": sha(build_lock(Path.cwd())),
    "source_lock_files": len(build_lock(Path.cwd()).files),
    "hybrid_tls": hybrid,
    "software_operation": operation,
    "package_records": software,
    "native_availability": {
        "kernel": "Linux",
        "tools": {x: shutil.which(x) for x in ["docker", "podman", "wine", "pwsh", "softhsm2-util", "pkcs11-tool"]},
        "docker_socket_present": Path("/var/run/docker.sock").exists(),
        "podman_socket_present": Path("/run/podman/podman.sock").exists(),
        "actual_windows_execution_qualified": False,
        "actual_container_execution_qualified": False,
        "actual_physical_hsm_qualified": False,
    },
    "independent_bank_acceptance": False,
}
Path("/home/user/hybrid-functional-witness.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print("Actual owned TCP hybrid:", f.key_exchange_group, f.openssl_version)
print(
    "Actual software operation signatures and two public logs:",
    operation["operation_signature_verified"],
    operation["application_provider_logs_correlated"],
)
print(
    "Actual dpkg database / dpkg-query record match:",
    len(expected),
    software["verdict"],
    "bytes",
    status.stat().st_size,
)
print("Source-lock:", report["source_lock_files"], "files; native Windows/container/HSM NOT qualified")
