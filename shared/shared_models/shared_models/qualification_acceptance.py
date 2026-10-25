"""Independent, scope-bound evidence review. No automatic production enablement.

Signatures prove approved keys signed the retained statements, not that a model
observed an external host, that people are organizationally independent, or that
native evidence cannot be falsified by a compromised evidence producer.
"""

from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token, Digest, HostManifest, HostSnapshot
from shared_models.collection import TargetSpec
from shared_models.collector_identity import decode
from shared_models.tpm_quote_verification import canonical, sha

CATEGORIES = {"systemd", "dmi", "tpm", "windows"}
CHECKS = {
    "native_systemd",
    "native_dmi",
    "native_tpm",
    "native_windows",
    "host_enrollment",
    "quote_replay_and_pcr",
    "worker_authority",
    "worker_isolation",
    "worker_cancellation",
    "worker_cleanup",
    "evidence_export",
    "key_custody",
    "recovery",
    "adversarial_retest",
}


class ExpectedNativeInput(Strict):
    input_id: Token
    facts: list[dict] = Field(min_length=1, max_length=1000)


class NativePlan(Strict):
    schema_version: Literal["cryptoscan.native-fixture/v1"] = "cryptoscan.native-fixture/v1"
    target_sha256: Digest
    expected: list[ExpectedNativeInput] = Field(min_length=1, max_length=100)
    reviewer_reference: Token


class NativeEvidence(Strict):
    schema_version: Literal["cryptoscan.native-evidence/v1"] = "cryptoscan.native-evidence/v1"
    category: Literal["systemd", "dmi", "tpm", "windows"]
    source_lock_sha256: Digest
    source_binding: Literal["OPERATOR_SUPPLIED_IDENTIFIER_NOT_MEASURED_EXECUTION"] = (
        "OPERATOR_SUPPLIED_IDENTIFIER_NOT_MEASURED_EXECUTION"
    )
    native_system: Literal["Linux", "Windows"]
    target: TargetSpec
    plan: NativePlan
    snapshot: HostSnapshot


def evaluate_native(evidence):
    target, plan, snapshot = evidence.target, evidence.plan, evidence.snapshot
    expected_platform = "windows" if evidence.category == "windows" else "linux"
    if (
        evidence.native_system != ("Windows" if expected_platform == "windows" else "Linux")
        or snapshot.execution_platform != expected_platform
        or not target.manifest
        or target.manifest.platform != expected_platform
    ):
        raise ValueError("Native OS/evidence platform mismatch")
    if (
        sha(target) != plan.target_sha256
        or sha(target.manifest) != snapshot.manifest_sha256
        or canonical(target.manifest) != canonical(snapshot.manifest)
    ):
        raise ValueError("Native target/plan/snapshot commitment mismatch")
    if not target.not_before <= snapshot.started_at <= snapshot.finished_at < target.manifest.expires_at:
        raise ValueError("Native evidence outside approved window")
    wanted = {e.input_id: e for e in plan.expected}
    if len(wanted) != len(plan.expected) or set(wanted) != {i.input_id for i in target.manifest.inputs}:
        raise ValueError("Exact native expected-truth scope required")
    from shared_models.host_collection import HostFact
    from shared_models.host_runtime import RuntimeFact
    from shared_models.windows_images import WindowsImageFact

    fields = set(HostFact.model_fields) | set(RuntimeFact.model_fields) | set(WindowsImageFact.model_fields)
    matched = True
    for receipt in snapshot.receipts:
        patterns = wanted[receipt.input_id].facts
        if any(
            not p or "kind" not in p or set(p) - fields or any(isinstance(v, (dict, list)) for v in p.values())
            for p in patterns
        ):
            raise ValueError("Invalid native expected-truth assertions")
        actual = [f.model_dump(mode="json") for f in receipt.facts]
        used = set()
        matched &= receipt.status == "PARSED" and len(actual) == len(patterns)
        for pattern in patterns:
            candidates = [
                i
                for i, f in enumerate(actual)
                if i not in used and all(k in f and type(f[k]) is type(v) and f[k] == v for k, v in pattern.items())
            ]
            if not candidates:
                matched = False
            else:
                used.add(candidates[0])
    # Every explicitly approved input must pass; positive category coverage also
    # needs the real expected interface kind, not a generic OS-file fixture.
    observed = {}
    for item, receipt in zip(snapshot.manifest.inputs, snapshot.receipts):
        if receipt.status == "PARSED":
            observed[item.kind] = (item, receipt)
    if evidence.category == "systemd":
        present = "LINUX_SERVICE" in observed and any(
            f.interface == "SYSTEMD_READ_ONLY" for f in observed["LINUX_SERVICE"][1].facts
        )
    elif evidence.category in {"dmi", "tpm"}:
        present = False
        for item, receipt in zip(snapshot.manifest.inputs, snapshot.receipts):
            if item.kind != "LINUX_HARDWARE" or receipt.status != "PARSED":
                continue
            if evidence.category == "dmi":
                present |= item.path == "linux-hardware://dmi" and any(
                    f.hardware_type == "SYSTEM_DMI" for f in receipt.facts
                )
            else:
                present |= item.path.startswith("linux-hardware://tpm") and any(
                    f.hardware_type == "TPM" and f.tpm_major_version in {1, 2} for f in receipt.facts
                )
    else:
        present = {"WINDOWS_SERVICE", "WINDOWS_OS_RELEASE"} <= observed.keys()
    return {
        "verdict": "PASS_SCOPED_NATIVE_EVIDENCE" if matched and present else "BLOCKED_NATIVE_GAPS_OR_TRUTH_MISMATCH",
        "category": evidence.category,
        "target_sha256": sha(target),
        "plan_sha256": sha(plan),
        "snapshot_sha256": sha(snapshot),
        "native_host_execution_independently_observed": False,
        "host_identity_attested": False,
        "production_execution_qualified": False,
    }


class Reviewer(Strict):
    reviewer_id: Token
    role: Literal["independent_assessor", "bank_acceptor"]
    public_key: str = Field(min_length=44, max_length=44)

    @field_validator("public_key")
    @classmethod
    def public(cls, value):
        decode(value, 32)
        return value


class AcceptancePolicy(Strict):
    schema_version: Literal["cryptoscan.qualification-policy/v1"] = "cryptoscan.qualification-policy/v1"
    campaign_id: Token
    tenant_id: str | None = Field(max_length=36)
    scope_reference: Token
    release_sha256: Digest
    native_plan_sha256: dict[str, Digest]
    native_source_lock_sha256: dict[str, Digest]
    reviewers: list[Reviewer] = Field(min_length=2, max_length=20)

    @model_validator(mode="after")
    def complete(self):
        if set(self.native_plan_sha256) != CATEGORIES or set(self.native_source_lock_sha256) != CATEGORIES:
            raise ValueError("All four native plan/release commitments required")
        if len({r.reviewer_id for r in self.reviewers}) != len(self.reviewers) or len(
            {r.public_key for r in self.reviewers}
        ) != len(self.reviewers):
            raise ValueError("Reviewer identity and key separation required")
        if {r.role for r in self.reviewers} != {"independent_assessor", "bank_acceptor"}:
            raise ValueError("Independent assessor and bank acceptor required")
        return self


class EvidenceIndex(Strict):
    schema_version: Literal["cryptoscan.qualification-index/v1"] = "cryptoscan.qualification-index/v1"
    campaign_id: Token
    tenant_id: str | None = Field(max_length=36)
    policy_sha256: Digest
    release_sha256: Digest
    # Values are SHA256-addressed bytes in the operator's artifact directory.
    native: dict[str, Digest]
    checks: dict[str, list[Digest]]

    @model_validator(mode="after")
    def complete(self):
        if set(self.native) != CATEGORIES or set(self.checks) != CHECKS:
            raise ValueError("Full required native and worker evidence matrix required")
        if any(not 1 <= len(v) <= 32 or len(set(v)) != len(v) for v in self.checks.values()):
            raise ValueError("Bounded nonempty unique check artifacts required")
        return self


class ReviewStatement(Strict):
    schema_version: Literal["cryptoscan.qualification-review/v1"] = "cryptoscan.qualification-review/v1"
    reviewer_id: Token
    campaign_id: Token
    tenant_id: str | None = Field(max_length=36)
    policy_sha256: Digest
    release_sha256: Digest
    index_sha256: Digest
    decision: Literal["ACCEPT_SCOPED_EVIDENCE", "REJECT"]
    checks: dict[str, Literal["PASS", "FAIL", "NOT_RUN"]]
    evidence_reference: Token
    signed_at: datetime
    expires_at: datetime

    @field_validator("signed_at", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def interval(self):
        if not 0 < (self.expires_at - self.signed_at).total_seconds() <= 7 * 86400:
            raise ValueError("Review lifetime must be at most seven days")
        if set(self.checks) != CHECKS:
            raise ValueError("Exact independent check matrix required")
        return self


class SignedReview(Strict):
    statement: ReviewStatement
    signature: str = Field(min_length=88, max_length=88)


def verify_evidence(policy, index, artifacts):
    """Verify original artifacts before freezing product evidence or reviewing it."""
    import hashlib
    from shared_models.qualified_export import bounded_json

    if (
        index.campaign_id != policy.campaign_id
        or index.tenant_id != policy.tenant_id
        or index.policy_sha256 != sha(policy)
        or index.release_sha256 != policy.release_sha256
    ):
        raise ValueError("Qualification index policy/scope/release mismatch")
    required = set(index.native.values()) | {v for values in index.checks.values() for v in values}
    if set(artifacts) != required or len(required) > 256 or sum(len(v) for v in artifacts.values()) > 16 * 1024 * 1024:
        raise ValueError("Artifact scope/count/total size mismatch")
    for digest, data in artifacts.items():
        if (
            not isinstance(data, bytes)
            or not 0 < len(data) <= 2 * 1024 * 1024
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise ValueError("Missing, oversized or changed qualification artifact")
    for category, digest in index.native.items():
        evidence = NativeEvidence.model_validate(bounded_json(artifacts[digest], max_bytes=2 * 1024 * 1024))
        if (
            evidence.category != category
            or sha(evidence.plan) != policy.native_plan_sha256[category]
            or evidence.source_lock_sha256 != policy.native_source_lock_sha256[category]
            or evaluate_native(evidence)["verdict"] != "PASS_SCOPED_NATIVE_EVIDENCE"
        ):
            raise ValueError("Native qualification is missing, stale, cross-scope or not positive")
        if digest not in index.checks["native_" + category]:
            raise ValueError("Native check does not bind its original artifact")
    return len(required)


def verify_signed_review(policy, index, proof, now):
    """Validate identity, binding, time and signature, including signed rejections."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    if now.tzinfo is None:
        raise ValueError("Aware verifier time required")
    statement = proof.statement
    reviewer = next((r for r in policy.reviewers if r.reviewer_id == statement.reviewer_id), None)
    if reviewer is None:
        raise ValueError("Unknown reviewer")
    if (
        statement.campaign_id != policy.campaign_id
        or statement.tenant_id != policy.tenant_id
        or statement.policy_sha256 != sha(policy)
        or statement.release_sha256 != policy.release_sha256
        or statement.index_sha256 != sha(index)
    ):
        raise ValueError("Review scope/release/evidence mismatch")
    if not statement.signed_at <= now < statement.expires_at:
        raise ValueError("Review expired or not yet valid")
    try:
        Ed25519PublicKey.from_public_bytes(decode(reviewer.public_key, 32)).verify(
            decode(proof.signature, 64), canonical(statement)
        )
    except InvalidSignature:
        raise ValueError("Independent review signature invalid") from None
    return reviewer


def verify_acceptance(policy, index, reviews, artifacts, now):
    """Verify retained evidence and two approved signatures, never enable execution."""
    if now.tzinfo is None:
        raise ValueError("Aware verifier time required")
    count = verify_evidence(policy, index, artifacts)
    if not 2 <= len(reviews) <= len(policy.reviewers):
        raise ValueError("Both approved review roles required")
    seen = set()
    roles = set()
    for proof in reviews:
        reviewer = verify_signed_review(policy, index, proof, now)
        statement = proof.statement
        if statement.reviewer_id in seen:
            raise ValueError("Repeated reviewer")
        if statement.decision != "ACCEPT_SCOPED_EVIDENCE" or any(v != "PASS" for v in statement.checks.values()):
            raise ValueError("Review rejected or has unresolved checks")
        seen.add(statement.reviewer_id)
        roles.add(reviewer.role)
    if roles != {"independent_assessor", "bank_acceptor"}:
        raise ValueError("Both separate review roles required")
    return {
        "verdict": "VERIFIED_SCOPED_EXTERNAL_ACCEPTANCE_RECORD",
        "campaign_id": policy.campaign_id,
        "tenant_id": policy.tenant_id,
        "scope_reference": policy.scope_reference,
        "policy_sha256": sha(policy),
        "index_sha256": sha(index),
        "release_sha256": policy.release_sha256,
        "reviewers": sorted(seen),
        "verified_artifacts": count,
        "required_checks": sorted(CHECKS),
        "independent_signatures_verified": True,
        "organizational_independence_verified": False,
        "native_execution_observed_by_this_verifier": False,
        "hardware_origin_verified": False,
        "full_worker_production_clearance": False,
        "production_execution_qualified": False,
    }
