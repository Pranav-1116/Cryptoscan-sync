"""Selection never turns a partial name, another fingerprint or ambiguity into exposure."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from cbom.nbom import probe_to_endpoint
from cbom.target_resolution import fingerprint, compare_resolution
from cbom.unified_cascade import unified_cascade, identify_target
from cbom.software_cascade import identify_software

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)
A, B = "ab" * 32, "cd" * 32
PURL = "pkg:pypi/crypto@1.0?arch=x86#lib"


def estate():
    return {
        "certificates": [
            {"fingerprint_sha256": A, "subject": "CN=payments"},
            {"fingerprint_sha256": B, "subject": "CN=payments"},
        ],
        "vendors": [{"id": "v-1", "name": "Bank Crypto"}, {"id": "v-2", "name": "Bank Crypto Services"}],
        "systems": [{"id": "pay", "name": "payments"}, {"id": "other", "name": "other"}],
        "system_vendors": [{"system_id": "pay", "vendor_id": "v-1"}, {"system_id": "other", "vendor_id": "v-2"}],
        "network_endpoints": [
            {
                "host": "pay.bank",
                "port": 443,
                "system_id": "pay",
                "certificate_subject": "CN=payments",
                "certificate_fingerprint_sha256": A,
            },
            {
                "host": "other.bank",
                "port": 443,
                "system_id": "other",
                "certificate_subject": "CN=payments",
                "certificate_fingerprint_sha256": B,
            },
            {"host": "legacy.bank", "port": 443, "system_id": "other", "certificate_subject": "CN=payments"},
        ],
        "software_sbom_bindings": [{"components": [{"package_identity": PURL}]}],
    }


def run(data, target, kind=None, search=False):
    return unified_cascade(data, target=target, kind=kind, allow_name_search=search, now=NOW)


@pytest.mark.parametrize("query", [A, A.upper(), ":".join(["AB"] * 32)])
def test_fingerprint_formats_resolve_exactly_and_bind_no_other_subject_peer(query):
    data = estate()
    before = deepcopy(data)
    result = run(data, query)
    assert result["analysis_performed"] is True
    assert result["target_resolution"]["selected"]["canonical_target"] == A
    assert result["layers"]["network"]["endpoints"] == ["pay.bank:443"]
    assert result["impact"]["affected_systems"] == ["pay"]
    binding = result["layers"]["network"]["certificate_join"]
    assert binding["subject_only_endpoint_count"] == 1
    assert binding["different_fingerprint_same_subject_count"] == 1
    assert data == before


def test_explicit_certificate_sha256_is_not_an_automatic_artifact_digest():
    data = estate()
    query = "sha256:" + A
    assert run(data, query)["analysis_performed"] is False
    assert run(data, query, "certificate")["target_resolution"]["selected"]["canonical_target"] == A


@pytest.mark.parametrize("bad", ["abc", "ab:" * 31, "SHA256:base64SSHfingerprint", "ab" * 31, "zz" * 32, None, 123])
def test_fingerprint_parser_does_not_accept_partial_hex_or_ssh_forms(bad):
    assert fingerprint(bad) is None


def test_subject_ambiguity_is_order_independent_and_requires_fingerprint_choice():
    data = estate()
    first = run(data, "CN=payments", "certificate")
    data["certificates"].reverse()
    second = run(data, "CN=payments", "certificate")
    assert first == second
    assert first["target_resolution"]["status"] == "AMBIGUOUS"
    assert first["target_resolution"]["candidate_count"] == 2
    assert first["analysis_performed"] is False and first["verdict"] == "UNRESOLVED"
    assert first["layers"] == {}
    assert identify_target(data, "CN=payments", "certificate") is None


def test_exact_fingerprint_beats_an_earlier_subject_spelled_like_a_fingerprint():
    data = estate()
    data["certificates"].insert(0, {"fingerprint_sha256": "ef" * 32, "subject": A})
    result = run(data, A)
    assert result["target"]["matched"]["subject"] == "CN=payments"
    assert result["impact"]["affected_systems"] == ["pay"]


def test_unique_exact_subject_is_labeled_weaker_but_uses_exact_downstream_identity():
    data = estate()
    data["certificates"] = data["certificates"][:1]
    result = run(data, " cn=PAYMENTS ", "certificate")
    assert result["target_resolution"]["method"] == "exact_name"
    assert result["target_resolution"]["selected"]["canonical_target"] == A
    assert result["impact"]["affected_systems"] == ["pay"]


@pytest.mark.parametrize("kind,query", [("certificate", "payment"), ("vendor", "Bank"), ("package", "crypto")])
def test_broad_names_are_opt_in_and_even_a_single_search_hit_is_not_executed(kind, query):
    data = estate()
    assert run(data, query, kind)["analysis_performed"] is False
    result = run(data, query, kind, search=True)
    assert result["target_resolution"]["status"] == "SEARCH_RESULTS"
    assert result["target_resolution"]["selected"] is None
    assert result["analysis_performed"] is False
    assert result["layers"] == {}
    choice = result["target_resolution"]["candidates"][0]
    assert run(data, choice["canonical_target"], choice["kind"])["analysis_performed"] is True


def test_vendor_id_beats_another_vendors_equal_name_and_name_prefix():
    data = estate()
    data["vendors"].insert(0, {"id": "misleading", "name": "v-1"})
    result = run(data, "v-1", "vendor")
    assert result["target_resolution"]["method"] == "exact_identity"
    assert result["impact"]["affected_systems"] == ["pay"]
    assert run(data, "V-1", "vendor")["target_resolution"]["selected"]["canonical_target"] == "misleading"
    data["vendors"].pop(0)
    assert run(data, "V-1", "vendor")["analysis_performed"] is False
    assert run(data, "Bank Crypto", "vendor")["impact"]["affected_systems"] == ["pay"]


def test_equal_casefolded_vendor_names_are_ambiguous_not_first_row():
    data = estate()
    data["vendors"].append({"id": "v-3", "name": "BANK CRYPTO"})
    result = run(data, "bank crypto", "vendor")
    assert result["target_resolution"]["candidate_count"] == 2
    assert result["analysis_performed"] is False


def test_global_exact_system_id_outranks_vendor_name_but_kind_scopes_lookup():
    data = estate()
    data["vendors"].append({"id": "v-pay", "name": "pay"})
    assert run(data, "pay")["target"]["kind"] == "system"
    assert run(data, "pay", "vendor")["target_resolution"]["selected"]["canonical_target"] == "v-pay"


def test_colliding_global_ids_are_ambiguous_and_explicit_kind_resolves():
    data = estate()
    data["vendors"].append({"id": "pay", "name": "Collision"})
    assert run(data, "pay")["target_resolution"]["status"] == "AMBIGUOUS"
    assert run(data, "pay", "vendor")["target"]["kind"] == "vendor"


@pytest.mark.parametrize(
    "query",
    [
        "pkg:pypi/crypto@1.0",
        "pkg:pypi/crypto@2.0?arch=x86#lib",
        "pkg:pypi/Crypto@1.0?arch=x86#lib",
        "pkg:pypi/crypto@1.0?arch=arm#lib",
        "pkg:pypi/crypto@1.0?arch=x86#bin",
        "pkg:pypi/crypto@latest",
        "pkg:pypi/crypto@^1.0",
    ],
)
def test_version_qualifier_subpath_case_and_ranges_do_not_guess_package_identity(query):
    assert run(estate(), query, "package")["analysis_performed"] is False


def test_conflicting_records_for_one_canonical_id_require_repair():
    data = estate()
    data["vendors"].append({"id": "v-1", "name": "Different company"})
    result = run(data, "v-1", "vendor")
    assert result["target_resolution"]["status"] == "AMBIGUOUS"
    assert result["target_resolution"]["candidate_count"] == 1
    assert result["target_resolution"]["candidates"][0]["selectable"] is False
    data["vendors"].reverse()
    assert run(data, "v-1", "vendor") == result
    assert run(data, "Bank Crypto", "vendor")["analysis_performed"] is False


def test_equivalent_fingerprint_spellings_do_not_create_false_conflicts():
    data = estate()
    data["certificates"].append({"fingerprint_sha256": A.upper(), "subject": "CN=payments"})
    assert run(data, A)["analysis_performed"] is True
    data["certificates"][-1]["subject"] = "CN=different"
    assert run(data, A)["analysis_performed"] is False
    assert run(data, "CN=different", "certificate")["analysis_performed"] is False


def test_candidate_limit_does_not_hide_ambiguity_and_only_safe_fields_are_returned():
    data = {"vendors": [{"id": f"v-{i:03}", "name": "Bank", "private_contract": "secret"} for i in range(75)]}
    result = run(data, "Bank", "vendor")
    resolution = result["target_resolution"]
    assert resolution["candidate_count"] == 75 and len(resolution["candidates"]) == 50
    assert resolution["candidates_truncated"] is True
    assert all("private_contract" not in c for c in resolution["candidates"])
    data["vendors"].reverse()
    assert run(data, "Bank", "vendor") == result


def test_truncated_name_registry_cannot_certify_unique_name_but_exact_key_can_run():
    data = estate()
    data["target_resolution_coverage"] = {"vendor_truncated": True}
    result = run(data, "Bank Crypto", "vendor")
    assert result["target_resolution"]["status"] == "INCOMPLETE"
    assert result["analysis_performed"] is False
    assert run(data, "v-1", "vendor")["analysis_performed"] is True


def test_subject_without_valid_registry_fingerprint_is_not_an_identity():
    data = {"certificates": [{"subject": "CN=payments", "fingerprint_sha256": "short-legacy"}]}
    result = run(data, "CN=payments", "certificate")
    assert result["analysis_performed"] is False
    assert result["target_resolution"]["candidates"][0]["selectable"] is False


def test_duplicate_artifact_digest_is_ambiguous_instead_of_first_scoped_row():
    digest = "sha256:" + A
    data = {"software_artifacts": [{"id": "a", "digest": digest}, {"id": "b", "digest": digest}]}
    assert run(data, digest)["target_resolution"]["status"] == "AMBIGUOUS"
    assert identify_software(data, digest, "artifact") is None
    assert run(data, "a", "artifact")["analysis_performed"] is True


def test_identity_comparison_uses_frozen_canonical_decisions_not_display_queries():
    data = estate()
    data["certificates"] = data["certificates"][:1]
    old = run(data, "CN=payments", "certificate")
    exact = run(data, A, "certificate")
    assert compare_resolution(old, exact)["comparable"] is True
    other = run(estate(), B, "certificate")
    assert compare_resolution(old, other)["comparable"] is False
    assert compare_resolution({}, exact)["comparable"] is False
    assert compare_resolution(old, run(estate(), "CN=payments", "certificate"))["comparable"] is False


def test_probe_mapping_retains_leaf_not_chain_issuer_fingerprint():
    ep = probe_to_endpoint(
        {
            "endpoint": "pay.bank:443",
            "status": "OK",
            "certificates": [
                {"subject": "CN=payments", "fingerprint_sha256": A},
                {"subject": "CN=issuer", "fingerprint_sha256": B},
            ],
        }
    )
    assert ep["certificate"]["fingerprint_sha256"] == A


def test_fingerprint_usage_and_endpoint_witnesses_never_cross_same_host_peer():
    data = estate()
    data["network_endpoints"].append(
        {
            "host": "pay.bank",
            "port": 443,
            "system_id": "pay",
            "certificate_subject": "CN=payments",
            "certificate_fingerprint_sha256": B,
        }
    )
    data["certificate_usages"] = {A.upper(): ["pay"], B: ["other"]}
    data["certificate_usage_records"] = [
        {"id": "right", "fingerprint_sha256": A.upper(), "location": "system:pay"},
        {"id": "wrong", "fingerprint_sha256": B, "location": "system:pay"},
    ]
    result = run(data, A)
    assert result["impact"]["affected_systems"] == ["pay"]
    assert '"id": "wrong"' not in __import__("json").dumps(result["traversal_evidence"])
    assert B not in __import__("json").dumps(result["traversal_evidence"])


def test_auto_partial_vendor_does_not_silently_become_a_manufacturer_match():
    data = estate()
    data["hardware"] = [{"asset_id": "hsm", "manufacturer": "Bank Crypto"}]
    result = run(data, "Bank")
    assert result["analysis_performed"] is False
    assert run(data, "Bank", search=True)["target_resolution"]["status"] == "SEARCH_RESULTS"
    # Explicit device scope remains legacy, not a new exactness certification.
    assert run(data, "Bank", "device")["target_resolution"]["method"] == "legacy_detector"


def test_auto_package_search_returns_choices_not_a_library_inference():
    result = run(estate(), "crypto", search=True)
    assert result["target_resolution"]["candidates"][0]["kind"] == "package"
    assert result["analysis_performed"] is False
