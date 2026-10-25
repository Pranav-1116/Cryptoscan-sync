"""Actual CLI/storage/concurrency witnesses; cryptographic positives are synthetic."""

import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import pytest
from inventory.qualification_files import ChallengeStore, read_public
from shared_models.tpm_quote_verification import QuoteChallenge, canonical
from shared.shared_models.tests.test_tpm_quote_verification import fixture, quote_bytes, sign
from shared.shared_models.tests.test_qualification_acceptance import setup

ROOT = Path(__file__).resolve().parents[3]


def run(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *map(str, args)], capture_output=True, timeout=20, cwd=ROOT
    )


def quote_setup(tmp):
    key, policy, _, _ = fixture()
    policy_path = tmp / "policy.json"
    policy_path.write_bytes(canonical(policy))
    state = tmp / "state"
    state.mkdir(mode=0o700)
    scope = tmp / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "campaign_id": "fixture-campaign",
                "tenant_id": "fixture-bank",
                "target_sha256": "1" * 64,
                "source_lock_sha256": "2" * 64,
                "snapshot_sha256": "3" * 64,
                "worker_claim_sha256": "4" * 64,
            }
        )
    )
    output = tmp / "challenge.json"
    args = ["--state", state, "--policy", policy_path]
    result = run("verify_tpm_host_quote.py", *args, "issue", "--scope", scope, "--output", output)
    assert result.returncode == 0, result.stderr
    challenge = QuoteChallenge.model_validate(json.loads(output.read_bytes())["challenge"])
    data = quote_bytes(policy, challenge)
    quote = tmp / "quote.bin"
    quote.write_bytes(data)
    signature = tmp / "sig.bin"
    signature.write_bytes(sign(key, data))
    pcr = tmp / "pcr.json"
    pcr.write_text(json.dumps(policy.pcr_sha256))
    verify = [
        *args,
        "verify",
        "--challenge-id",
        challenge.challenge_id,
        "--attestation",
        quote,
        "--signature",
        signature,
        "--pcrs",
        pcr,
    ]
    return verify, state, challenge, quote, signature


def test_quote_cli_only_one_of_two_concurrent_consumptions_succeeds(tmp_path):
    args, state, challenge, _, _ = quote_setup(tmp_path)

    def attempt(i):
        return run("verify_tpm_host_quote.py", *args, "--output", tmp_path / f"result-{i}.json")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sorted(r.returncode for r in results) == [0, 64]
    marker = state / (challenge.challenge_id + ".accepted.json")
    report = json.loads(marker.read_bytes())["report"]
    assert report["quote_signature_verified"] and not report["hardware_origin_verified"]
    assert marker.stat().st_mode & 0o777 == 0o600
    assert run("verify_tpm_host_quote.py", *args, "--output", tmp_path / "again.json").returncode == 64


def test_failed_output_is_recoverable_without_quote_replay(tmp_path):
    args, state, challenge, _, _ = quote_setup(tmp_path)
    output = tmp_path / "exists.json"
    output.write_bytes(b"original")
    result = run("verify_tpm_host_quote.py", *args, "--output", output)
    assert result.returncode == 64 and output.read_bytes() == b"original"
    marker = state / (challenge.challenge_id + ".accepted.json")
    assert json.loads(marker.read_bytes())["report"]["quote_signature_verified"]
    assert run("verify_tpm_host_quote.py", *args, "--output", tmp_path / "retry.json").returncode == 64


def test_invalid_signature_does_not_consume_challenge(tmp_path):
    args, state, challenge, _, signature = quote_setup(tmp_path)
    original = signature.read_bytes()
    signature.write_bytes(b"bad")
    assert run("verify_tpm_host_quote.py", *args, "--output", tmp_path / "bad.json").returncode == 64
    assert not (state / (challenge.challenge_id + ".accepted.json")).exists()
    signature.write_bytes(original)
    assert run("verify_tpm_host_quote.py", *args, "--output", tmp_path / "good.json").returncode == 0


@pytest.mark.parametrize("change", ["mode", "symlink", "hardlink", "path", "wrong-id", "oversized"])
def test_challenge_store_and_public_file_scope(tmp_path, change):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    _, _, challenge, _ = fixture()
    if change == "mode":
        state.chmod(0o755)
        with pytest.raises(ValueError):
            ChallengeStore(state)
        return
    if change == "path":
        with ChallengeStore(state) as store:
            with pytest.raises(ValueError):
                store.get("../escape")
        return
    with ChallengeStore(state) as store:
        store.issue(challenge)
        name = state / (challenge.challenge_id + ".challenge.json")
        if change == "symlink":
            name.unlink()
            name.symlink_to(tmp_path / "anything")
            with pytest.raises(OSError):
                store.get(challenge.challenge_id)
        elif change == "hardlink":
            os.link(name, tmp_path / "alias")
            with pytest.raises(ValueError):
                store.get(challenge.challenge_id)
        elif change == "wrong-id":
            name.write_bytes(canonical(challenge.model_copy(update={"challenge_id": "a" * 32})))
            with pytest.raises(ValueError):
                store.get(challenge.challenge_id)
        else:
            name.write_bytes(b"x" * 8193)
            with pytest.raises(ValueError):
                store.get(challenge.challenge_id)


def test_public_reader_refuses_special_large_linked_and_changed_content(tmp_path):
    public = tmp_path / "public"
    public.write_bytes(b"public")
    assert read_public(public, 6) == b"public"
    with pytest.raises(ValueError):
        read_public(public, 5)
    alias = tmp_path / "alias"
    alias.symlink_to(public)
    with pytest.raises(OSError):
        read_public(alias, 100)


def test_external_reviews_cli_requires_original_artifacts_and_separate_signatures(tmp_path):
    policy, index, reviews, artifacts, _, _ = setup()
    paths = []
    for name, value in [("policy", policy), ("index", index)]:
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical(value))
        paths.append(path)
    reviews_path = tmp_path / "reviews.json"
    reviews_path.write_bytes(canonical([r.model_dump(mode="json") for r in reviews]))
    directory = tmp_path / "artifacts"
    directory.mkdir()
    for digest, data in artifacts.items():
        (directory / digest).write_bytes(data)
    output = tmp_path / "acceptance.json"
    args = [
        "--policy",
        paths[0],
        "--index",
        paths[1],
        "--reviews",
        reviews_path,
        "--artifacts",
        directory,
        "--output",
        output,
    ]
    result = run("verify_independent_host_qualification.py", *args)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_bytes())
    assert report["independent_signatures_verified"] and not report["full_worker_production_clearance"]
    assert run("verify_independent_host_qualification.py", *args).returncode == 64
    output.unlink()
    (directory / next(iter(artifacts))).unlink()
    assert run("verify_independent_host_qualification.py", *args).returncode == 64 and not output.exists()


def test_actual_linux_missing_tpm_and_windows_native_refusal(tmp_path):
    from datetime import datetime, timedelta, timezone
    from shared_models.host_collection import HostManifest, HostInput
    from shared_models.collection import TargetSpec
    from shared_models.qualification_acceptance import NativePlan, NativeEvidence, evaluate_native
    from shared_models.tpm_quote_verification import sha

    now = datetime.now(timezone.utc)
    manifest = HostManifest(
        approval_reference="owned/negative-native-witness",
        host_id="owned-local",
        environment="test",
        platform="linux",
        expires_at=now + timedelta(minutes=10),
        inputs=[HostInput(input_id="tpm", kind="LINUX_HARDWARE", path="linux-hardware://tpm999")],
    )
    target = TargetSpec(
        target_key="owned-negative",
        system_id="owned",
        owner="engineering",
        environment="test",
        collection_method="offline_host",
        address="owned-local",
        allowed_operations=["READ_APPROVED_METADATA"],
        not_before=now - timedelta(seconds=1),
        manifest=manifest,
    )
    plan = NativePlan(
        target_sha256=sha(target),
        expected=[{"input_id": "tpm", "facts": [{"kind": "HARDWARE", "hardware_type": "TPM", "tpm_major_version": 2}]}],
        reviewer_reference="engineering-negative-only",
    )
    target_path = tmp_path / "target.json"
    target_path.write_bytes(canonical(target))
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical(plan))
    lock = tmp_path / "source-lock.json"
    lock.write_bytes(b"public-scope-identifier-not-measured-code")
    output = tmp_path / "native.json"
    args = [
        "--target",
        target_path,
        "--plan",
        plan_path,
        "--source-lock",
        lock,
        "--approved-plan-sha256",
        sha(plan),
        "--output",
        output,
    ]
    result = run("capture_native_qualification.py", "--category", "tpm", *args)
    assert result.returncode == 2, result.stderr
    evidence = NativeEvidence.model_validate_json(output.read_bytes())
    assert evaluate_native(evidence)["verdict"] == "BLOCKED_NATIVE_GAPS_OR_TRUTH_MISMATCH"
    assert evidence.snapshot.receipts[0].status == "UNAVAILABLE"
    output.unlink()
    assert (
        run("capture_native_qualification.py", "--category", "windows", *args).returncode == 64 and not output.exists()
    )
    changed = [str(x) for x in args]
    changed[changed.index("--approved-plan-sha256") + 1] = "a" * 64
    assert run("capture_native_qualification.py", "--category", "tpm", *changed).returncode == 64


@pytest.mark.parametrize("change", ["tenant", "caller-nonce"])
def test_issuer_cannot_rebind_enrollment_tenant_or_take_caller_nonce(tmp_path, change):
    _, policy, _, _ = fixture()
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical(policy))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    scope = {
        "campaign_id": "fixture-campaign",
        "tenant_id": "other-bank" if change == "tenant" else "fixture-bank",
        "target_sha256": "1" * 64,
        "source_lock_sha256": "2" * 64,
        "snapshot_sha256": "3" * 64,
        "worker_claim_sha256": "4" * 64,
    }
    if change == "caller-nonce":
        scope["nonce"] = "a" * 64
    scope_path = tmp_path / "scope.json"
    scope_path.write_bytes(canonical(scope))
    output = tmp_path / "out.json"
    result = run(
        "verify_tpm_host_quote.py",
        "--state",
        state,
        "--policy",
        policy_path,
        "issue",
        "--scope",
        scope_path,
        "--output",
        output,
    )
    assert result.returncode == 64 and not output.exists() and not list(state.iterdir())
