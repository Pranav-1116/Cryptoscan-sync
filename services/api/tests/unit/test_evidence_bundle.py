"""The evidence bundle: what a bank-side collector may hand the platform (spec 100).

These tests exist because every one of them is a way the format could lie:

* a bundle with nothing in it, reported ``VERIFIED`` (the cheapest false green);
* a manifest verified against its own embedded key, so a tampered transfer passes;
* a file the manifest never covered, silently ingested;
* coverage reported as a percentage, so seven uncollected hosts read as "95% done";
* a signature that is malformed and produces a traceback rather than a verdict.

The bundle is built and verified by the same code the API will call, so the round trip
here is the round trip an operator gets.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from shared_models import evidence_bundle, release_signature


@pytest.fixture
def keys(tmp_path: Path):
    return release_signature.generate_keypair(tmp_path / "keys", name="collector")


@pytest.fixture
def members() -> dict[str, bytes]:
    return {
        "observations/linux/host-01.json": b'{"host":"host-01","packages":["openssl"]}',
        "observations/network/tls-01.json": b'{"endpoint":"10.0.0.5:443","tls":"1.3"}',
        "coverage.json": b"{}",
    }


def _manifest(keys, members, *, coverage=None):
    manifest = evidence_bundle.build_manifest(
        bundle_id="BND-2026-00182",
        organization_id="BANK-001",
        environment="production",
        scan_id="SCAN-2026-00182",
        collector_version="1.0.0",
        scope_revision="REV-192",
        created_at="2026-10-29T08:30:00Z",
        members=members,
        coverage=coverage,
    )
    private = release_signature.load_private_key(keys["private_key"])
    manifest["signature"] = release_signature.sign_document(manifest, private)
    return manifest


def test_a_signed_bundle_verifies_against_the_trusted_key(keys, members, tmp_path):
    manifest = _manifest(keys, members)
    trusted = release_signature.load_public_key(keys["public_key"])

    result = evidence_bundle.verify_bundle(manifest, members, trusted_key=trusted)

    assert result["state"] == evidence_bundle.VERIFIED
    assert result["accepted"] is True
    assert result["reasons"] == []
    assert result["members_checked"] == 3
    assert result["members_missing"] == [] and result["members_mismatched"] == []
    assert result["manifest_digest"] == evidence_bundle.manifest_digest(manifest)

    # the same bytes on disk round trip through the air-gapped path
    root = evidence_bundle.write_bundle(tmp_path / "bundle", manifest, members)
    read_manifest, read_members = evidence_bundle.read_bundle(root)
    again = evidence_bundle.verify_bundle(read_manifest, read_members, trusted_key=trusted)
    assert again["state"] == evidence_bundle.VERIFIED
    assert evidence_bundle.all_paths(root) == sorted(members)


def test_a_signed_bundle_without_a_trust_root_is_not_verified(keys, members):
    manifest = _manifest(keys, members)

    result = evidence_bundle.verify_bundle(manifest, members)

    assert result["state"] == evidence_bundle.SIGNATURE_UNCHECKED
    assert result["accepted"] is False
    assert "no trusted key" in result["signature"]["reason"]
    assert "do not ingest on trust" in result["next"]


def test_an_unsigned_bundle_matches_its_hashes_and_proves_nothing(keys, members):
    manifest = evidence_bundle.build_manifest(
        bundle_id="BND-2", organization_id="BANK-001", environment="production",
        scan_id="SCAN-2", collector_version="1.0.0", scope_revision=None,
        created_at="2026-10-29T08:30:00Z", members=members,
    )
    trusted = release_signature.load_public_key(keys["public_key"])

    result = evidence_bundle.verify_bundle(manifest, members, trusted_key=trusted)

    assert result["state"] == evidence_bundle.UNSIGNED
    assert result["accepted"] is False
    assert result["members_checked"] == 3


def test_a_tampered_member_is_rejected_and_named(keys, members):
    manifest = _manifest(keys, members)
    trusted = release_signature.load_public_key(keys["public_key"])
    altered = dict(members)
    altered["observations/network/tls-01.json"] = b'{"endpoint":"10.0.0.5:443","tls":"1.0"}'

    result = evidence_bundle.verify_bundle(manifest, altered, trusted_key=trusted)

    assert result["state"] == evidence_bundle.REJECTED
    assert evidence_bundle.MEMBER_DIGEST_MISMATCH in result["reasons"]
    assert result["members_mismatched"] == ["observations/network/tls-01.json"]


def test_a_file_the_manifest_does_not_cover_is_a_rejection(keys, members):
    manifest = _manifest(keys, members)
    trusted = release_signature.load_public_key(keys["public_key"])
    smuggled = dict(members)
    smuggled["observations/linux/host-99.json"] = b'{"host":"host-99"}'

    result = evidence_bundle.verify_bundle(manifest, smuggled, trusted_key=trusted)

    assert result["state"] == evidence_bundle.REJECTED
    assert evidence_bundle.MEMBER_NOT_IN_MANIFEST in result["reasons"]
    assert result["members_unlisted"] == ["observations/linux/host-99.json"]


def test_a_missing_member_is_rejected_and_named(keys, members):
    manifest = _manifest(keys, members)
    trusted = release_signature.load_public_key(keys["public_key"])
    truncated = {path: data for path, data in members.items() if not path.endswith("host-01.json")}

    result = evidence_bundle.verify_bundle(manifest, truncated, trusted_key=trusted)

    assert result["state"] == evidence_bundle.REJECTED
    assert result["members_missing"] == ["observations/linux/host-01.json"]


def test_an_empty_bundle_cannot_be_built(keys):
    with pytest.raises(ValueError, match="no members"):
        evidence_bundle.build_manifest(
            bundle_id="BND-0", organization_id="BANK-001", environment="production",
            scan_id="SCAN-0", collector_version="1.0.0", scope_revision=None,
            created_at="2026-10-29T08:30:00Z", members={},
        )


def test_a_manifest_listing_nothing_is_rejected_not_verified(keys):
    manifest = _manifest(keys, {"observations/linux/host-01.json": b"{}"})
    manifest["members"] = []
    result = evidence_bundle.verify_bundle(manifest, {}, trusted_key=None)

    assert result["state"] == evidence_bundle.REJECTED
    assert evidence_bundle.BUNDLE_EMPTY in result["reasons"]


def test_a_malformed_signature_is_a_verdict_not_a_traceback(keys, members):
    manifest = _manifest(keys, members)
    manifest["signature"] = {"schema": "cryptoscan.signature/1", "alg": "Ed25519", "public_key": "not base64!", "signature": "x"}

    result = evidence_bundle.verify_bundle(manifest, members)

    assert result["state"] == evidence_bundle.REJECTED
    assert evidence_bundle.SIGNATURE_MALFORMED in result["reasons"]


def test_a_wrong_trusted_key_is_rejected(keys, members, tmp_path):
    manifest = _manifest(keys, members)
    other = release_signature.generate_keypair(tmp_path / "other", name="someone-else")
    wrong = release_signature.load_public_key(other["public_key"])

    result = evidence_bundle.verify_bundle(manifest, members, trusted_key=wrong)

    assert result["state"] == evidence_bundle.REJECTED
    assert evidence_bundle.SIGNATURE_KEY_MISMATCH in result["reasons"]


def test_paths_that_escape_the_bundle_are_refused(keys):
    for bad in ("../etc/passwd", "/etc/passwd", "observations\\win.json", "secrets/key.pem"):
        with pytest.raises(ValueError):
            evidence_bundle.build_manifest(
                bundle_id="BND-x", organization_id="BANK-001", environment="production",
                scan_id="SCAN-x", collector_version="1.0.0", scope_revision=None,
                created_at="2026-10-29T08:30:00Z", members={bad: b"x"},
            )


def test_coverage_names_the_targets_nobody_accounted_for():
    report = evidence_bundle.summarise_coverage(
        {"expected": 150, "attempted": 145, "collected": 143, "partial": 4, "failed": 2, "unauthorized": 1}
    )

    # 143 + 4 + 2 + 1 = 150 accounted for: every expected target has an outcome, but
    # three of them are bad outcomes, so the collection is PARTIAL and not "done".
    assert report["accounted"] == 150
    assert report["unaccounted"] == 0
    assert report["state"] == "PARTIAL"
    assert evidence_bundle.COVERAGE_FAILED_TARGETS in report["reasons"]

    gap = evidence_bundle.summarise_coverage({"expected": 150, "collected": 143})
    assert gap["unaccounted"] == 7
    assert gap["state"] == "PARTIAL"
    assert evidence_bundle.COVERAGE_UNACCOUNTED_TARGETS in gap["reasons"]
    # the fraction never appears without its denominator
    assert gap["observed_fraction"] == pytest.approx(143 / 150)
    assert "not a share of the bank" in gap["observed_note"]


def test_coverage_with_no_registered_scope_is_unknown_not_complete():
    report = evidence_bundle.summarise_coverage({"expected": 0, "collected": 0})

    assert report["state"] == "UNKNOWN"
    assert report["observed_fraction"] is None
    assert evidence_bundle.COVERAGE_UNKNOWN in report["reasons"]

    missing = evidence_bundle.summarise_coverage(None)
    assert missing["state"] == "UNKNOWN"
    assert missing["counts"]["expected"] is None


def test_a_failed_target_keeps_coverage_partial_even_when_every_target_is_accounted_for():
    report = evidence_bundle.summarise_coverage(
        {"expected": 8, "collected": 7, "unavailable": 1}
    )

    assert report["accounted"] == 8
    assert report["unaccounted"] == 0
    assert report["state"] == "PARTIAL"
    assert evidence_bundle.COVERAGE_FAILED_TARGETS in report["reasons"]


def test_the_manifest_carries_a_digest_and_size_for_every_member(keys, members):
    manifest = _manifest(keys, members)

    entries = {entry["path"]: entry for entry in manifest["members"]}
    assert manifest["member_count"] == 3
    assert manifest["total_bytes"] == sum(len(data) for data in members.values())
    assert entries["observations/linux/host-01.json"]["sha256"] == evidence_bundle.member_sha256(
        members["observations/linux/host-01.json"]
    )
    assert entries["observations/linux/host-01.json"]["kind"] == "observations"
    assert any("does not prove" in limit or "proves nothing" in limit for limit in manifest["limits"])
