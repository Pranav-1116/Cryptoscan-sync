"""Ordinary-user offline capture bound to an existing authenticated API handoff."""

from datetime import datetime, timezone
from inventory.oci_evidence import OciRefused, collect_oci, validate_oci_scope
from shared_models.host_collection import digest
from shared_models.oci_intake import OciCaptureBinding, OciJobReturn


def capture_oci_job(target, binding, approved_target_sha256, approved_binding_sha256):
    target, _ = validate_oci_scope(target, approved_target_sha256)
    binding = OciCaptureBinding.model_validate(binding.model_dump())
    if digest(binding) != approved_binding_sha256 or binding.target_sha256 != digest(target):
        raise OciRefused("HANDOFF_COMMITMENT_MISMATCH")
    if not binding.issued_at <= datetime.now(timezone.utc) < binding.expires_at <= target.expires_at:
        raise OciRefused("OUTSIDE_HANDOFF_WINDOW")
    return OciJobReturn(binding=binding, evidence=collect_oci(target, approved_target_sha256))
