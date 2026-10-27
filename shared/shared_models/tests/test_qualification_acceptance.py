"""Synthetic review/native records test verification ONLY; no native positives."""

import base64
import hashlib
from datetime import datetime, timedelta, timezone
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shared_models.qualification_acceptance import (
    AcceptancePolicy,
    EvidenceIndex,
    Reviewer,
    NativeEvidence,
    NativePlan,
    ReviewStatement,
    SignedReview,
    CHECKS,
    evaluate_native,
    verify_acceptance,
)
from shared_models.tpm_quote_verification import canonical, sha
from shared_models.host_collection import HostManifest, HostInput, HostSnapshot, HostReceipt, HostFact
from shared_models.host_runtime import RuntimeFact
from shared_models.collection import TargetSpec


def native(category):
    now = datetime.now(timezone.utc)
    platform = "windows" if category == "windows" else "linux"
    if category == "systemd":
        pairs = [
            (
                HostInput(input_id="service", kind="LINUX_SERVICE", path="systemd://approved.service"),
                RuntimeFact(
                    kind="SERVICE",
                    interface="SYSTEMD_READ_ONLY",
                    identity_key="approved.service",
                    service_name="approved.service",
                    service_state="active",
                    interface_sha256="a" * 64,
                ),
            )
        ]
    elif category == "dmi":
        pairs = [
            (
                HostInput(input_id="dmi", kind="LINUX_HARDWARE", path="linux-hardware://dmi"),
                RuntimeFact(
                    kind="HARDWARE",
                    interface="LINUX_SYSFS",
                    identity_key="dmi",
                    hardware_type="SYSTEM_DMI",
                    manufacturer="Synthetic",
                    interface_sha256="a" * 64,
                ),
            )
        ]
    elif category == "tpm":
        pairs = [
            (
                HostInput(input_id="tpm", kind="LINUX_HARDWARE", path="linux-hardware://tpm0"),
                RuntimeFact(
                    kind="HARDWARE",
                    interface="LINUX_SYSFS",
                    identity_key="tpm0",
                    hardware_type="TPM",
                    tpm_major_version=2,
                    interface_sha256="a" * 64,
                ),
            )
        ]
    else:
        pairs = [
            (
                HostInput(input_id="service", kind="WINDOWS_SERVICE", path="windows-service://Approved"),
                RuntimeFact(
                    kind="SERVICE",
                    interface="WINDOWS_SCM",
                    identity_key="Approved",
                    service_name="Approved",
                    service_state="RUNNING",
                    interface_sha256="a" * 64,
                ),
            ),
            (
                HostInput(input_id="os", kind="WINDOWS_OS_RELEASE", path="windows-os://local/current-version"),
                HostFact(
                    kind="OS_RELEASE",
                    local_basis="DECLARED",
                    purpose="OS_RELEASE_METADATA",
                    software_name="Windows",
                    software_version="fixture",
                ),
            ),
        ]
    manifest = HostManifest(
        approval_reference="synthetic/not-qualification",
        host_id="fixture-" + platform,
        environment="test",
        platform=platform,
        expires_at=now + timedelta(minutes=30),
        inputs=[p[0] for p in pairs],
    )
    target = TargetSpec(
        target_key="fixture-" + category,
        system_id="fixture-system",
        owner="fixture",
        environment="test",
        collection_method="offline_host",
        address="fixture-" + platform,
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=now - timedelta(seconds=1),
        manifest=manifest,
    )
    snapshot = HostSnapshot(
        manifest=manifest,
        manifest_sha256=sha(manifest),
        started_at=now,
        finished_at=now,
        execution_platform=platform,
        receipts=[
            HostReceipt(
                input_id=i.input_id,
                status="PARSED",
                reason="METADATA_ONLY",
                byte_count=1,
                content_sha256="a" * 64,
                facts=[f],
            )
            for i, f in pairs
        ],
    )
    plan = NativePlan(
        target_sha256=sha(target),
        reviewer_reference="fixture/not-independent",
        expected=[
            {
                "input_id": i.input_id,
                "facts": [{"kind": f.kind, **({"hardware_type": f.hardware_type} if f.kind == "HARDWARE" else {})}],
            }
            for i, f in pairs
        ],
    )
    return NativeEvidence(
        category=category,
        source_lock_sha256="b" * 64,
        native_system="Windows" if platform == "windows" else "Linux",
        target=target,
        plan=plan,
        snapshot=snapshot,
    )


def setup():
    evidence = {c: native(c) for c in ["systemd", "dmi", "tpm", "windows"]}
    keys = [Ed25519PrivateKey.generate() for _ in range(2)]
    reviewers = [
        Reviewer(
            reviewer_id=f"fixture-reviewer-{i}",
            role=role,
            public_key=base64.b64encode(
                k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ).decode(),
        )
        for i, (k, role) in enumerate(zip(keys, ["independent_assessor", "bank_acceptor"]))
    ]
    policy = AcceptancePolicy(
        campaign_id="fixture-campaign",
        tenant_id="fixture-bank",
        scope_reference="fixture-not-real-acceptance",
        release_sha256="c" * 64,
        native_plan_sha256={c: sha(e.plan) for c, e in evidence.items()},
        native_source_lock_sha256={c: e.source_lock_sha256 for c, e in evidence.items()},
        reviewers=reviewers,
    )
    artifacts = {}
    natives = {}
    for c, e in evidence.items():
        data = canonical(e)
        digest = hashlib.sha256(data).hexdigest()
        artifacts[digest] = data
        natives[c] = digest
    # Worker checks refer to retained test bytes, NOT invented operational proof.
    worker = b"synthetic worker-test witness, never independent clearance"
    worker_sha = hashlib.sha256(worker).hexdigest()
    artifacts[worker_sha] = worker
    index = EvidenceIndex(
        campaign_id=policy.campaign_id,
        tenant_id=policy.tenant_id,
        policy_sha256=sha(policy),
        release_sha256=policy.release_sha256,
        native=natives,
        checks={c: [natives[c.removeprefix("native_")]] if c.startswith("native_") else [worker_sha] for c in CHECKS},
    )
    now = datetime.now(timezone.utc)
    reviews = []
    for key, reviewer in zip(keys, reviewers):
        statement = ReviewStatement(
            reviewer_id=reviewer.reviewer_id,
            campaign_id=policy.campaign_id,
            tenant_id=policy.tenant_id,
            policy_sha256=sha(policy),
            release_sha256=policy.release_sha256,
            index_sha256=sha(index),
            decision="ACCEPT_SCOPED_EVIDENCE",
            checks={c: "PASS" for c in CHECKS},
            evidence_reference="synthetic-only",
            signed_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(hours=1),
        )
        reviews.append(signed(key, statement))
    return policy, index, reviews, artifacts, now, keys


def signed(key, statement):
    return SignedReview(statement=statement, signature=base64.b64encode(key.sign(canonical(statement))).decode())


def test_separate_signed_records_do_not_claim_production_or_host_attestation():
    policy, index, reviews, artifacts, now, _ = setup()
    report = verify_acceptance(policy, index, reviews, artifacts, now)
    assert report["independent_signatures_verified"] and len(report["reviewers"]) == 2
    assert not report["full_worker_production_clearance"] and not report["hardware_origin_verified"]
    assert (
        not report["organizational_independence_verified"] and not report["native_execution_observed_by_this_verifier"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "artifact",
        "missing-artifact",
        "extra-artifact",
        "single-review",
        "repeated-review",
        "unknown-reviewer",
        "signature",
        "reject",
        "fail",
        "not-run",
        "expired",
        "future",
        "policy",
        "release",
        "index",
        "campaign",
        "tenant",
        "same-role",
        "wrong-native-plan",
        "wrong-native-release",
        "cross-category",
        "native-gap",
        "unreviewed-native",
        "wrong-scalar-type",
    ],
)
def test_changes_fail_closed_even_when_review_statements_are_resigned(change):
    policy, index, reviews, artifacts, now, keys = setup()
    if change == "artifact":
        artifacts[next(iter(artifacts))] += b" "
    elif change == "missing-artifact":
        del artifacts[next(iter(artifacts))]
    elif change == "extra-artifact":
        artifacts["d" * 64] = b"extra"
    elif change == "single-review":
        reviews = reviews[:1]
    elif change == "repeated-review":
        reviews = [reviews[0], reviews[0]]
    elif change == "signature":
        reviews[0] = reviews[0].model_copy(update={"signature": base64.b64encode(b"X" * 64).decode()})
    elif change == "same-role":
        reviewers = list(policy.reviewers)
        reviewers[1] = reviewers[1].model_copy(update={"role": "independent_assessor"})
        with pytest.raises(ValueError):
            AcceptancePolicy.model_validate({**policy.model_dump(), "reviewers": [r.model_dump() for r in reviewers]})
        return
    elif change.startswith("wrong-native"):
        field = "native_plan_sha256" if change == "wrong-native-plan" else "native_source_lock_sha256"
        policy = policy.model_copy(update={field: {**getattr(policy, field), "systemd": "d" * 64}})
        index = index.model_copy(update={"policy_sha256": sha(policy)})
        reviews = [
            signed(k, r.statement.model_copy(update={"policy_sha256": sha(policy), "index_sha256": sha(index)}))
            for k, r in zip(keys, reviews)
        ]
    elif change in {"cross-category", "native-gap", "unreviewed-native", "wrong-scalar-type"}:
        old = index.native["systemd"]
        e = NativeEvidence.model_validate_json(artifacts.pop(old))
        if change == "cross-category":
            e = e.model_copy(update={"category": "dmi"})
        elif change == "native-gap":
            receipts = [HostReceipt(input_id="service", status="UNAVAILABLE", reason="INTERFACE_UNAVAILABLE")]
            e = e.model_copy(update={"snapshot": e.snapshot.model_copy(update={"receipts": receipts})})
        elif change == "wrong-scalar-type":
            expected = e.plan.expected[0].model_copy(update={"facts": [{"kind": "SERVICE", "pid": True}]})
            e = e.model_copy(update={"plan": e.plan.model_copy(update={"expected": [expected]})})
            policy = policy.model_copy(
                update={"native_plan_sha256": {**policy.native_plan_sha256, "systemd": sha(e.plan)}}
            )
        data = canonical(e)
        new = hashlib.sha256(data).hexdigest()
        artifacts[new] = data
        checks = {
            **index.checks,
            "native_systemd": [new] if change != "unreviewed-native" else index.checks["worker_isolation"],
        }
        index = index.model_copy(
            update={"native": {**index.native, "systemd": new}, "checks": checks, "policy_sha256": sha(policy)}
        )
        reviews = [
            signed(k, r.statement.model_copy(update={"policy_sha256": sha(policy), "index_sha256": sha(index)}))
            for k, r in zip(keys, reviews)
        ]
    else:
        fields = {
            "unknown-reviewer": ("reviewer_id", "unknown"),
            "reject": ("decision", "REJECT"),
            "fail": ("checks", {**reviews[0].statement.checks, "worker_cleanup": "FAIL"}),
            "not-run": ("checks", {**reviews[0].statement.checks, "native_windows": "NOT_RUN"}),
            "expired": ("expires_at", now),
            "future": ("signed_at", now + timedelta(seconds=10)),
            "policy": ("policy_sha256", "d" * 64),
            "release": ("release_sha256", "d" * 64),
            "index": ("index_sha256", "d" * 64),
            "campaign": ("campaign_id", "other"),
            "tenant": ("tenant_id", "other-bank"),
        }
        field, value = fields[change]
        reviews[0] = signed(keys[0], reviews[0].statement.model_copy(update={field: value}))
    with pytest.raises(ValueError):
        verify_acceptance(policy, index, reviews, artifacts, now)


@pytest.mark.parametrize("category", ["systemd", "dmi", "tpm", "windows"])
def test_raw_native_snapshot_and_target_checked_without_self_reported_pass(category):
    evidence = native(category)
    assert evaluate_native(evidence)["verdict"] == "PASS_SCOPED_NATIVE_EVIDENCE"
    wrong = evidence.model_copy(update={"native_system": "Linux" if category == "windows" else "Windows"})
    with pytest.raises(ValueError):
        evaluate_native(wrong)


def test_policy_and_index_cannot_omit_gates_or_reuse_reviewer_key():
    policy, index, _, _, _, _ = setup()
    value = policy.model_dump()
    value["native_plan_sha256"].pop("windows")
    with pytest.raises(ValueError):
        AcceptancePolicy.model_validate(value)
    value = policy.model_dump()
    value["reviewers"][1]["public_key"] = value["reviewers"][0]["public_key"]
    with pytest.raises(ValueError):
        AcceptancePolicy.model_validate(value)
    value = index.model_dump()
    value["checks"].pop("key_custody")
    with pytest.raises(ValueError):
        EvidenceIndex.model_validate(value)
