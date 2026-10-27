"""Server-owned container admission policy. Evidence quality is not execution clearance."""

from shared_models.oci_content import KINDS
from shared_models.host_collection import digest

# No qualified container executor/release has been accepted. This is not a request field,
# environment bypass, or an authority delegated to imported snapshot/review flags.
ADMITTED_CONTAINER_PROFILES = frozenset()
CONTENT_PROFILE = "offline-container-content/candidate-v1"


def require_container_profile(profile):
    if profile not in ADMITTED_CONTAINER_PROFILES:
        raise ValueError(
            "Container is a future capability: no qualified production container executor/release admitted"
        )


def container_readiness(snapshot):
    requested = [i for i in snapshot.manifest.inputs if i.kind in KINDS]
    inputs = {i.input_id: i for i in requested}
    receipts = [r for r in snapshot.receipts if r.input_id in inputs]
    content = [r.facts[0] for r in receipts if r.status == "PARSED" and inputs[r.input_id].kind == "OCI_IMAGE_CONTENT"]
    runtime = [
        r.facts[0] for r in receipts if r.status == "PARSED" and inputs[r.input_id].kind == "OCI_RUNTIME_PROCESS"
    ]
    images = {f.image.manifest_sha256 for f in content}
    blockers = []
    if not requested or any(r.status != "PARSED" for r in receipts):
        blockers.append("MISSING_OR_FAILED_APPROVED_CONTAINER_INPUTS")
    if not content:
        blockers.append("NO_VERIFIED_CONTENT_EVIDENCE")
    if not runtime:
        blockers.append("NO_EXACT_RUNTIME_PROCESS_EVIDENCE")
    if any(f.image_manifest_sha256 not in images for f in runtime):
        blockers.append("RUNTIME_DECLARED_IMAGE_WITHOUT_MATCHING_VERIFIED_CONTENT")
    # The profile deliberately does not authenticate daemon-reported image binding,
    # publisher, worker execution or external qualification; do not infer those from hashes.
    blockers += [
        "RUNTIME_TO_IMAGE_BINDING_NOT_INDEPENDENTLY_VERIFIED",
        "REAL_IMAGE_EXPECTED_TRUTH_AND_INDEPENDENT_ACCEPTANCE_REQUIRED",
        "SIGNED_RELEASE_AND_MEASURED_WORKER_PROVENANCE_REQUIRED",
        "CONTAINER_ISOLATION_CANCELLATION_RESOURCE_AND_RECOVERY_QUALIFICATION_REQUIRED",
        "NO_QUALIFIED_CONTAINER_EXECUTOR_ADMITTED",
    ]
    return {
        "schema_version": "cryptoscan.container-admission-readiness/v1",
        "profile": CONTENT_PROFILE,
        "snapshot_sha256": digest(snapshot),
        "source_basis": "IMPORTED",
        "verdict": "BLOCKED_NOT_PRODUCTION_ADMITTED",
        "approved_inputs": len(requested),
        "failed_inputs": [
            {"input_id": r.input_id, "status": r.status, "reason": r.reason} for r in receipts if r.status != "PARSED"
        ],
        "verified_content_observations": len(content),
        "package_database_records": sum(len(f.packages) for f in content),
        "runtime_process_observations": len(runtime),
        "runtime_image_binding_verified": False,
        "blockers": blockers,
        "production_execution_qualified": False,
        "server_execution": False,
        "windows_execution_qualified": False,
        "materialized_without_collection": True,
    }
