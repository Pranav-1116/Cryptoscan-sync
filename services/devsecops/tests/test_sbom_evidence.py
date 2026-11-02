"""Evidence semantics that a review will check line by line.

Each test names the claim it defends. The point is not coverage of the module —
it is that the difference between "in an SBOM" and "running in production",
between "no matches" and "not assessed", and between "integrity" and
"non-repudiation" cannot silently collapse.
"""

from __future__ import annotations

from datetime import date

import pytest

from devsecops import sbom_evidence as se

AS_OF = date(2026, 11, 2)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def _artifact(digest: str = DIGEST) -> se.ArtifactIdentity:
    return se.ArtifactIdentity("ghcr.io/bank/payments-api", digest)


def _observation(*, digest: str = DIGEST, environment: str = "PRODUCTION",
                 as_of: date = AS_OF) -> se.DeploymentObservation:
    return se.DeploymentObservation(
        deployment="payments-api-prod", environment=environment,
        artifact=se.ArtifactIdentity("ghcr.io/bank/payments-api", digest),
        workload="payments-api-7d9c4f-x2b6q", observed_at=as_of,
        evidence_id="OBS-1102-01", source="k8s")


def _sbom(*, sbom_id: str = "SBOM-1", artifact: se.ArtifactIdentity | None = None,
          components: tuple[dict, ...] | None = None,
          created_at: date = AS_OF) -> se.SbomRecord:
    return se.SbomRecord(
        sbom_id, artifact if artifact is not None else _artifact(),
        components if components is not None else (
            {"name": "openssl", "version": "3.0.13", "crypto_relevant": True},),
        created_at=created_at, build_id="BUILD-1")


# --------------------------------------------------------------- identity -- #


def test_a_tag_is_refused_as_an_identity() -> None:
    with pytest.raises(se.IdentityError, match="names no digest"):
        se.parse_image_reference("ghcr.io/bank/payments-api:latest")


@pytest.mark.parametrize("tag", ["v1.2.3", "stable", "2026-11-02"])
def test_no_tag_is_accepted_even_a_pretty_one(tag: str) -> None:
    with pytest.raises(se.IdentityError):
        se.parse_image_reference(f"ghcr.io/bank/payments-api:{tag}")


def test_a_digest_reference_parses() -> None:
    artifact = se.parse_image_reference(f"ghcr.io/bank/payments-api@{DIGEST}")
    assert artifact.reference == "ghcr.io/bank/payments-api"
    assert artifact.digest == DIGEST
    assert artifact.mutable is False


def test_a_reference_that_contradicts_its_digest_is_refused() -> None:
    with pytest.raises(se.IdentityError, match="pins"):
        se.ArtifactIdentity(f"ghcr.io/bank/payments-api@{OTHER}", DIGEST)


# ----------------------------------------------------- deployment presence -- #


def test_observed_component_is_in_the_deployment() -> None:
    result = se.presence_in_deployment(_sbom(), "openssl", [_observation()])
    assert result["state"] == "PRESENT_IN_DEPLOYMENT"
    assert result["environments"] == ["PRODUCTION"]


def test_a_document_bound_to_no_digest_is_sbom_only() -> None:
    uploaded = se.SbomRecord("SBOM-upload", None, ({"name": "openssl", "version": "3.0.11"},))
    assert se.presence_in_deployment(uploaded, "openssl", [_observation()])["state"] == \
        "PRESENT_IN_SBOM_ONLY"


def test_a_digest_nobody_observed_is_in_the_artifact_only() -> None:
    assert se.presence_in_deployment(_sbom(), "openssl", [])["state"] == "PRESENT_IN_ARTIFACT"


def test_an_observation_of_another_digest_does_not_transfer() -> None:
    result = se.presence_in_deployment(_sbom(), "openssl",
                                       [_observation(digest=OTHER)])
    assert result["state"] == "PRESENT_IN_ARTIFACT"


def test_an_absent_component_is_not_in_the_sbom() -> None:
    assert se.presence_in_deployment(_sbom(), "curl", [_observation()])["state"] == \
        "NOT_IN_SBOM"


# ------------------------------------------------------------- provenance -- #


def _complete_build(**overrides) -> se.BuildIdentity:
    fields = dict(source_commit="9f2c1ab4d7", build_id="BUILD-1",
                  builder="github-actions", pipeline="release", artifact=_artifact(),
                  sbom_id="SBOM-1", started_at=AS_OF, finished_at=AS_OF)
    fields.update(overrides)
    return se.BuildIdentity(**fields)


def test_the_chain_is_complete_only_with_an_observation() -> None:
    provenance = se.build_provenance(_complete_build(), _sbom(), [_observation()])
    assert provenance["complete"] is True
    assert provenance["gaps"] == []

    unobserved = se.build_provenance(_complete_build(), _sbom(), [])
    assert unobserved["complete"] is False
    assert "never observed running" in unobserved["statement"]


def test_every_missing_link_is_named() -> None:
    provenance = se.build_provenance(
        se.BuildIdentity("not-a-sha", "", "", "", None, None), None, [])
    assert len(provenance["gaps"]) >= 4
    assert any("not a commit hash" in gap for gap in provenance["gaps"])


def test_a_sbom_of_another_artifact_is_not_this_builds() -> None:
    other = _sbom(artifact=se.ArtifactIdentity("ghcr.io/bank/payments-api", OTHER))
    gaps = se.build_provenance(_complete_build(), other, [_observation()])["gaps"]
    assert any("different artifact" in gap for gap in gaps)


def test_a_backdated_sbom_is_refused() -> None:
    early = _sbom(created_at=date(2026, 10, 1))
    gaps = se.build_provenance(_complete_build(), early, [_observation()])["gaps"]
    assert any("predates" in gap for gap in gaps)


# ---------------------------------------------------------------- storage -- #


def test_production_without_a_store_is_refused_not_degraded() -> None:
    policy = se.storage_policy(environment="PRODUCTION", configured_store=None,
                               writable=False, durable=False)
    assert policy["verdict"] == "REFUSE"
    assert policy["fallback"] is False


def test_a_store_without_backup_retention_or_integrity_is_refused() -> None:
    policy = se.storage_policy(environment="PRODUCTION", configured_store="s3://evidence",
                               writable=True, durable=True)
    assert policy["verdict"] == "REFUSE"
    assert len(policy["reasons"]) == 3


def test_a_durable_store_with_dr_and_retention_is_allowed() -> None:
    policy = se.storage_policy(environment="PRODUCTION", configured_store="s3://evidence",
                               writable=True, durable=True, backup="s3://evidence-dr",
                               retention_days=2555, integrity_verified=True)
    assert policy["verdict"] == "ALLOW"


@pytest.mark.parametrize("environment", ["dev", "test", "ci"])
def test_ephemeral_storage_is_allowed_where_the_record_does_not_depend_on_it(
        environment: str) -> None:
    policy = se.storage_policy(environment=environment, configured_store=None,
                               writable=False, durable=False)
    assert policy["verdict"] == "ALLOW"
    assert policy["mode"] == "EPHEMERAL_OK"


# ---------------------------------------------------------------- signing -- #


def _signature(key: se.SigningKey, signed_at: date = AS_OF) -> se.Signature:
    return se.Signature(key.key_id, signed_at, "sig", "SBOM-1")


def _verify(key: se.SigningKey) -> dict:
    return se.verify_signature("SBOM-1", DIGEST, _signature(key), key,
                               known_anchors=["bank-root-ca"], as_of=AS_OF)


def test_a_hash_proves_integrity_and_nothing_else() -> None:
    result = _verify(se.SigningKey("hash", "SHA-256", "ACTIVE"))
    assert result["verdict"] == "INTEGRITY_ONLY"
    assert result["claims"]["integrity"] is True
    assert result["claims"]["authenticity"] is False


def test_hmac_cannot_produce_non_repudiation() -> None:
    result = _verify(se.SigningKey("hmac", "HMAC-SHA256", "ACTIVE"))
    assert result["verdict"] == "AUTHENTIC"
    assert result["claims"]["non_repudiation"] is False


def test_an_anchored_asymmetric_key_is_non_repudiable() -> None:
    result = _verify(se.SigningKey("ed", "Ed25519", "ACTIVE", trust_anchor="bank-root-ca"))
    assert result["verdict"] == "NON_REPUDIABLE"


def test_an_unanchored_key_proves_possession_only() -> None:
    result = _verify(se.SigningKey("ed", "Ed25519", "ACTIVE"))
    assert result["verdict"] == "AUTHENTIC"
    assert result["claims"]["non_repudiation"] is False


def test_a_revoked_key_invalidates_what_it_signed() -> None:
    result = _verify(se.SigningKey("ed", "Ed25519", "REVOKED", trust_anchor="bank-root-ca"))
    assert result["verdict"] == "REVOKED_KEY"
    assert result["claims"]["authenticity"] is False


def test_rotation_keeps_an_old_signature_valid_and_says_so() -> None:
    result = _verify(se.SigningKey("ed-2025", "Ed25519", "ROTATED",
                                   trust_anchor="bank-root-ca", rotated_to="ed-2026"))
    assert result["verdict"] == "NON_REPUDIABLE"
    assert "rotated to ed-2026" in result["statement"]


def test_an_expired_key_fails_even_when_anchored() -> None:
    result = _verify(se.SigningKey("ed", "Ed25519", "ACTIVE", trust_anchor="bank-root-ca",
                                   valid_until=date(2026, 1, 1)))
    assert result["verdict"] == "EXPIRED_KEY"


def test_an_unsigned_sbom_is_its_own_verdict() -> None:
    result = se.verify_signature("SBOM-1", DIGEST, None, None, as_of=AS_OF)
    assert result["verdict"] == "UNSIGNED"


def test_an_unknown_algorithm_is_not_a_signature() -> None:
    with pytest.raises(se.IdentityError, match="not an algorithm"):
        se.SigningKey("k", "ROT13", "ACTIVE")


# ---------------------------------------------------------- vulnerabilities -- #

FEED = {"name": "osv", "version": "2026-11-01", "updated_at": date(2026, 11, 1)}
OPENSSL = {"name": "openssl", "version": "3.0.11", "purl": "pkg:generic/openssl@3.0.11"}
ADVISORY = [{"id": "CVE-2024-6119", "package": "pkg:generic/openssl",
             "affected_versions": ["3.0.11"]}]


def test_the_vocabulary_is_closed() -> None:
    assert se.VULN_STATES == ("NOT_ASSESSED", "ASSESSED_NO_MATCH", "MATCHED", "UNKNOWN",
                              "STALE_FEED", "INSUFFICIENT_IDENTIFIER")


def test_a_match_carries_the_feed_and_the_method() -> None:
    result = se.assess_vulnerabilities(OPENSSL, feed=FEED, advisories=ADVISORY, as_of=AS_OF)
    assert result["status"] == "MATCHED"
    assert result["feed"] == "osv"
    assert result["match_method"] == "purl+version"


def test_zero_matches_is_assessed_because_the_feed_was_current() -> None:
    clean = dict(OPENSSL, version="3.0.13", purl="pkg:generic/openssl@3.0.13")
    assert se.assess_vulnerabilities(clean, feed=FEED, advisories=ADVISORY,
                                     as_of=AS_OF)["status"] == "ASSESSED_NO_MATCH"


def test_zero_matches_from_a_stale_feed_is_not_an_all_clear() -> None:
    stale = se.assess_vulnerabilities(
        OPENSSL, advisories=ADVISORY, as_of=AS_OF,
        feed={"name": "osv", "version": "2026-09-01", "updated_at": date(2026, 9, 1)})
    assert stale["status"] == "STALE_FEED"
    assert stale["advisories"] == []


def test_an_identifier_less_component_cannot_be_matched() -> None:
    result = se.assess_vulnerabilities({"name": "openssl", "version": "3.0.11"},
                                       feed=FEED, as_of=AS_OF)
    assert result["status"] == "INSUFFICIENT_IDENTIFIER"


def test_no_feed_is_not_assessed_rather_than_clean() -> None:
    assert se.assess_vulnerabilities(OPENSSL, feed=None,
                                     as_of=AS_OF)["status"] == "NOT_ASSESSED"


def test_an_undatable_feed_is_unknown() -> None:
    assert se.assess_vulnerabilities(OPENSSL, feed={"name": "osv"},
                                     as_of=AS_OF)["status"] == "UNKNOWN"


# -------------------------------------------------------------------- VEX -- #


def _vex(**overrides) -> dict:
    fields = dict(cve="CVE-2024-6119", component="openssl", affected_versions=["3.0.11"],
                  application="payments-api", deployment="payments-api-prod",
                  status="NOT_AFFECTED", justification="VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",
                  reviewer="Security Team", evidence_id="EVID-1",
                  assessed_at=date(2026, 1, 1), expires_at=date(2027, 1, 1), as_of=AS_OF)
    fields.update(overrides)
    return se.vex_statement(**fields)


def test_a_current_statement_names_a_reviewer_and_an_expiry() -> None:
    statement = _vex()
    assert statement["verdict"] == "CURRENT"
    assert statement["reviewer"] == "Security Team"
    assert statement["evidence_id"] == "EVID-1"


def test_an_expired_statement_stops_suppressing_the_finding() -> None:
    statement = _vex(assessed_at=date(2025, 1, 1), expires_at=date(2026, 1, 1))
    assert statement["verdict"] == "EXPIRED"
    assert statement["expired"] is True


def test_free_text_is_not_a_justification() -> None:
    statement = _vex(justification="because we said so", reviewer=None, evidence_id=None)
    assert statement["verdict"] == "INVALID"
    assert len(statement["problems"]) == 3


def test_a_statement_cannot_expire_before_it_was_made() -> None:
    statement = _vex(assessed_at=date(2026, 2, 1), expires_at=date(2026, 1, 1))
    assert statement["verdict"] == "INVALID"
    assert any("before it was assessed" in problem for problem in statement["problems"])


def test_a_vex_id_must_look_like_a_cve() -> None:
    assert _vex(cve="INTERNAL-42")["verdict"] == "INVALID"


# --------------------------------------------------------------- licences -- #


def test_a_detected_licence_is_never_an_approval() -> None:
    result = se.license_assessment(declared="Apache-2.0", detected="Apache-2.0")
    assert result["state"] == "REQUIRES_REVIEW"


def test_declared_versus_detected_disagreement_is_a_conflict() -> None:
    assert se.license_assessment(declared="MIT", detected="GPL-3.0")["state"] == "CONFLICT"


def test_only_policy_produces_accepted_or_rejected() -> None:
    accepted = se.license_assessment(declared="MIT", detected="MIT",
                                     policy={"MIT": "ALLOW"})
    rejected = se.license_assessment(declared="GPL-3.0", detected="GPL-3.0",
                                     policy={"GPL-3.0": "DENY"})
    assert accepted["state"] == "POLICY_ACCEPTED"
    assert rejected["state"] == "POLICY_REJECTED"


def test_no_licence_is_unknown_not_permissive() -> None:
    assert se.license_assessment(declared=None,
                                 detected=None)["state"] == "UNKNOWN"


# --------------------------------------------------------------- promotion -- #


def _candidate() -> dict:
    return se.crypto_candidate("openssl", "3.0.13", algorithms=["AES-256-GCM", "RSA-3072"])


def test_an_inventory_row_starts_at_capability() -> None:
    candidate = _candidate()
    assert candidate["rung"] == "CAPABILITY"
    assert candidate["confidence"] == "LOW"


def test_evidence_climbs_the_ladder_one_rung_at_a_time() -> None:
    static = se.promote(_candidate(), [se.CryptoEvidence(
        "STATIC_OBSERVED", "file:src/tls/conn.go#L142", AS_OF, "AES-256-GCM")])
    runtime = se.promote(static, [se.CryptoEvidence(
        "RUNTIME_OBSERVED", "session:S-1", AS_OF, "AES-256-GCM")])
    network = se.promote(runtime, [se.CryptoEvidence(
        "NETWORK_OBSERVED", "pcap:1102#42", AS_OF, "TLS_AES_256_GCM_SHA384")])
    assert [static["rung"], runtime["rung"], network["rung"]] == [
        "STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"]
    assert network["confidence"] == "HIGH"


def test_a_skipped_rung_stops_the_ladder_and_names_where() -> None:
    skipped = se.promote(_candidate(), [se.CryptoEvidence(
        "RUNTIME_OBSERVED", "session:S-1", AS_OF, "AES-256-GCM")])
    assert skipped["rung"] == "CAPABILITY"
    assert "STATIC_OBSERVED" in skipped["gaps"][0]


def test_re_promotion_does_not_lose_earlier_evidence() -> None:
    static = se.promote(_candidate(), [se.CryptoEvidence(
        "STATIC_OBSERVED", "file:a#1", AS_OF, "AES-256-GCM")])
    network = se.promote(static, [
        se.CryptoEvidence("RUNTIME_OBSERVED", "session:1", AS_OF, "AES-256-GCM"),
        se.CryptoEvidence("NETWORK_OBSERVED", "pcap:1", AS_OF, "AES-256-GCM")])
    assert network["rung"] == "NETWORK_OBSERVED"
    kinds = [row["kind"] for row in network["evidence"]]
    # CAPABILITY is intrinsic to the candidate; the three observations accumulate.
    assert kinds == ["CAPABILITY", "STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"]


def test_an_observation_outside_the_ladder_is_refused() -> None:
    with pytest.raises(se.IdentityError, match="not a rung"):
        se.CryptoEvidence("OBSERVED", "somewhere")


# ---------------------------------------------------------- diff / history -- #


def _older() -> se.SbomRecord:
    return se.SbomRecord("SBOM-1", _artifact(), (
        {"name": "openssl", "version": "3.0.11", "crypto_relevant": True,
         "license": "Apache-2.0", "depends_on": ["cffi"]},
        {"name": "cffi", "version": "1.16.0"}), created_at=date(2026, 10, 1), build_id="B-1")


def _newer() -> se.SbomRecord:
    return se.SbomRecord("SBOM-2", se.ArtifactIdentity("ghcr.io/bank/payments-api", OTHER), (
        {"name": "openssl", "version": "3.0.13", "crypto_relevant": True,
         "license": "Apache-2.0", "depends_on": ["cffi", "libssl"]},
        {"name": "libssl", "version": "3.0.13"}), created_at=AS_OF, build_id="B-2")


def test_every_kind_of_movement_is_named() -> None:
    kinds = {row["kind"] for row in se.snapshot_changes(_older(), _newer())}
    assert {"VERSION_CHANGED", "PACKAGE_ADDED", "DEPENDENCY_CHANGED",
            "ARTIFACT_CHANGED"} <= kinds


def test_a_version_bump_does_not_decide_its_own_crypto_impact() -> None:
    diff = se.evidence_aware_diff(_older(), _newer(), deployments=[_observation()])
    row = next(item for item in diff["changes"] if item["kind"] == "VERSION_CHANGED")
    assert row["crypto_impact"] == "UNKNOWN"
    assert row["runtime_verification"] == "NOT_OBSERVED"


def test_observed_runtime_and_network_evidence_close_the_question() -> None:
    diff = se.evidence_aware_diff(_older(), _newer(), deployments=[_observation()],
                                  runtime_verified=["openssl"],
                                  network_verified=["openssl"])
    row = next(item for item in diff["changes"] if item["kind"] == "VERSION_CHANGED")
    assert row["crypto_impact"] == "RUNTIME_EVIDENCE_PRESENT"
    assert row["runtime_verification"] == "OBSERVED"
    assert row["network_impact"] == "OBSERVED"


def test_the_diff_carries_an_evidence_id() -> None:
    diff = se.evidence_aware_diff(_older(), _newer(), deployments=[_observation()])
    assert diff["evidence_id"].startswith("DIF-")


# ---------------------------------------------------------- input safety -- #


def test_an_import_may_not_overwrite_an_observed_fact() -> None:
    result = se.import_sbom({"deployment_identity": "attacker-prod",
                             "components": [{"name": "x", "version": "1.0.0"}]},
                            source="vendor-portal",
                            existing={"deployment_identity": "payments-api-prod"})
    assert result["verdict"] == "REJECTED"
    assert result["refused"][0]["field"] == "deployment_identity"


def test_an_accepted_import_is_untrusted_and_cannot_override() -> None:
    result = se.import_sbom({"components": [{"name": "openssl", "version": "3.0.13"}]},
                            source="vendor-portal")
    assert result["verdict"] == "ACCEPTED_AS_EVIDENCE"
    assert result["trust"] == "UNTRUSTED"
    assert all(row["may_override"] is False for row in result["components"])


def test_a_deep_graph_hits_the_depth_limit() -> None:
    document = {"components": [{"name": f"c{i}", "dependsOn": [f"c{i + 1}"]}
                               for i in range(200)] + [{"name": "c200"}]}
    budget = se.check_budget(document)
    assert budget["verdict"] == "REFUSED"
    assert any("depth" in problem for problem in budget["problems"])


def test_a_cycle_is_found_iteratively_not_by_recursion() -> None:
    budget = se.check_budget({"components": [{"name": "a", "dependsOn": ["b"]},
                                             {"name": "b", "dependsOn": ["a"]}]})
    assert budget["verdict"] == "REFUSED"
    assert budget["cycles"] == 1


def test_an_oversized_document_is_refused_by_size() -> None:
    budget = se.check_budget({"components": []}, size_bytes=100 * 1024 * 1024)
    assert budget["verdict"] == "REFUSED"


def test_an_ordinary_document_is_within_budget() -> None:
    budget = se.check_budget({"components": [{"name": "openssl", "dependsOn": ["cffi"]},
                                             {"name": "cffi"}]}, size_bytes=4096)
    assert budget["verdict"] == "WITHIN_BUDGET"
