"""Process-level runtime tracing: the chain is the evidence.

The review's item 7: application → process → provider → operation → algorithm →
parameters, with a timestamp and an evidence id. A trace missing a link is a claim,
and the tests below are mostly about what the module refuses to call runtime.
"""

from __future__ import annotations

import pytest

from cbom import process_tracing as pt

OP = {
    "application": "payments-api", "pid": 9182, "provider": "OpenSSL",
    "provider_version": "3.0.13", "operation": "EVP_EncryptInit_ex",
    "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
    "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-92821",
}


def _trace(*operations):
    return pt.trace(list(operations or [OP]))


# --------------------------------------------------------------------------- #
# the chain


def test_the_review_chain_is_kept_whole():
    body = _trace()
    item = body["traces"][0]
    assert body["chain"] == ["application", "process", "provider", "operation", "algorithm"]
    assert item["chain"] == {
        "application": "application:payments-api",
        "process": "process:payments-api/9182",
        "provider": "provider:OpenSSL@3.0.13",
        "operation": "operation:EVP_EncryptInit_ex",
        "algorithm": "algorithm:AES-256-GCM",
    }
    assert item["parameters"] == {"key_size": 256, "mode": "GCM"}
    assert item["class"] == "RUNTIME_OBSERVED"


def test_a_trace_without_a_process_is_refused():
    body = _trace({**OP, "pid": None})
    assert body["traces"] == []
    assert "pid" in body["refused"][0]["reason"]
    assert "incomplete chain" in body["statement"]


def test_a_trace_without_a_timestamp_is_refused():
    body = _trace({key: value for key, value in OP.items() if key != "observed_at"})
    assert body["refused"] and "observed_at" in body["refused"][0]["reason"]


def test_an_unparseable_timestamp_is_refused_not_replaced():
    body = _trace({**OP, "observed_at": "sometime tuesday"})
    assert body["refused"] and "unparseable" in body["refused"][0]["reason"]


def test_a_provider_without_a_version_is_kept_and_marked():
    item = _trace({key: value for key, value in OP.items()
                   if key != "provider_version"})["traces"][0]
    assert item["provider"] == "OpenSSL"
    assert item["provider_version"] is None
    assert item["provider_version_known"] is False
    assert item["chain"]["provider"] == "provider:OpenSSL"


def test_no_provider_at_all_is_still_a_trace_but_not_comparable():
    item = _trace({key: value for key, value in OP.items()
                   if key not in {"provider", "provider_version"}})["traces"][0]
    assert item["provider_known"] is False
    assert item["chain"]["provider"] == "provider:UNKNOWN"


def test_the_summary_counts_processes_not_operations():
    body = _trace(OP, {**OP, "evidence_id": "RUNTIME-92822"},
                  {**OP, "pid": 9183, "evidence_id": "RUNTIME-92823"})
    assert len(body["traces"]) == 3
    assert len(body["processes"]) == 2
    assert body["applications"] == ["payments-api"]


# --------------------------------------------------------------------------- #
# providers


def test_a_provider_is_described_by_what_it_was_seen_doing():
    body = pt.provider_observations(_trace()["traces"])
    row = body["providers"][0]
    assert row["name"] == "OpenSSL" and row["version"] == "3.0.13"
    assert row["algorithms"] == ["AES-256-GCM"]
    assert row["operations"] == {"EVP_EncryptInit_ex": 1}
    assert "was observed performing AES-256-GCM" in row["statement"]


def test_operations_are_counted_per_provider():
    traces = _trace(OP, {**OP, "evidence_id": "R-2", "operation": "EVP_DecryptFinal_ex"})
    row = pt.provider_observations(traces["traces"])["providers"][0]
    assert row["operations"] == {"EVP_DecryptFinal_ex": 1, "EVP_EncryptInit_ex": 1}
    assert row["evidence_ids"] == ["R-2", "RUNTIME-92821"]


def test_an_unversioned_provider_says_it_cannot_be_compared():
    traces = _trace({key: value for key, value in OP.items()
                     if key != "provider_version"})["traces"]
    body = pt.provider_observations(traces)
    assert body["unknown_version"] == ["provider:OpenSSL"]
    assert "cannot be compared with an SBOM" in body["providers"][0]["statement"]


# --------------------------------------------------------------------------- #
# correlation


def _correlate(declared=None, **overrides):
    traces = _trace({**OP, **overrides})["traces"]
    providers = pt.provider_observations(traces)
    return pt.correlate(providers, declared or [])


def test_a_version_mismatch_is_reported_not_resolved():
    body = _correlate([{"name": "openssl", "version": "3.0.11", "evidence_id": "SBOM-1"}])
    row = body["correlations"][0]
    assert row["state"] == "VERSION_MISMATCH"
    assert row["runtime_version"] == "3.0.13"
    assert row["declared_versions"] == ["3.0.11"]
    assert set(row["evidence_ids"]) == {"SBOM-1", "RUNTIME-92821"}
    assert "not resolved" in body["statement"]


def test_an_agreeing_provider_is_a_match():
    body = _correlate([{"name": "openssl", "version": "3.0.13"}])
    assert body["correlations"][0]["state"] == "MATCH"


def test_a_provider_the_sbom_never_mentions_is_runtime_only():
    body = _correlate([{"name": "openssl", "version": "3.0.13"}], provider="BoringSSL")
    states = {row["state"] for row in body["correlations"]}
    assert states == {"SBOM_ONLY", "RUNTIME_ONLY"}


def test_a_declared_library_no_process_loaded_is_sbom_only():
    body = _correlate([{"name": "openssl", "version": "3.0.13"}], provider="BoringSSL")
    row = next(row for row in body["correlations"] if row["state"] == "SBOM_ONLY")
    assert row["name"] == "openssl"
    assert "presence on disk is not use" in row["detail"]


def test_an_unversioned_runtime_provider_cannot_match():
    traces = _trace({key: value for key, value in OP.items()
                     if key != "provider_version"})["traces"]
    body = pt.correlate(pt.provider_observations(traces),
                        [{"name": "openssl", "version": "3.0.13"}])
    assert body["correlations"][0]["state"] == "RUNTIME_VERSION_UNKNOWN"


# --------------------------------------------------------------------------- #
# the runtime-confirmed asset


def test_repeated_operations_are_one_asset_with_a_count():
    traces = _trace(OP, {**OP, "evidence_id": "R-2"})["traces"]
    body = pt.to_components(traces)
    assert len(body["components"]) == 1
    component = body["components"][0]
    properties = {row["name"]: row["value"] for row in component["properties"]}
    assert properties["cryptoscan:runtime_confirmed"] == "true"
    assert properties["cryptoscan:occurrences"] == "2"
    assert properties["cryptoscan:process"] == "9182"
    assert properties["cryptoscan:provider"] == "OpenSSL"
    assert component["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "256"


def test_a_different_process_is_a_different_asset():
    traces = _trace(OP, {**OP, "pid": 9183, "evidence_id": "R-2"})["traces"]
    assert len(pt.to_components(traces)["components"]) == 2


def test_the_asset_carries_every_evidence_id():
    traces = _trace(OP, {**OP, "evidence_id": "R-2"})["traces"]
    properties = pt.to_components(traces)["components"][0]["properties"]
    ids = sorted(row["value"] for row in properties
                 if row["name"] == "cryptoscan:evidence_id")
    assert ids == ["R-2", "RUNTIME-92821"]


def test_an_asset_without_parameters_does_not_claim_an_empty_parameter_set():
    traces = _trace({key: value for key, value in OP.items()
                     if key not in {"key_size", "mode"}})["traces"]
    component = pt.to_components(traces)["components"][0]
    assert "algorithmProperties" not in component["cryptoProperties"]


def test_the_asset_writes_no_quantum_verdict():
    traces = _trace()["traces"]
    component = pt.to_components(traces)["components"][0]
    assert "quantumVulnerable" not in component["cryptoProperties"]
    assert not any(row["name"].startswith("cryptoscan:quantum") for row in component["properties"])


# --------------------------------------------------------------------------- #
# the twin projection


def test_the_graph_walks_the_chain_and_the_shortcut():
    body = pt.graph(_trace()["traces"])
    kinds = {(edge["from"], edge["kind"], edge["to"]) for edge in body["edges"]}
    assert ("application:payments-api", "RUNS_PROCESS", "process:payments-api/9182") in kinds
    assert ("process:payments-api/9182", "LOADS_PROVIDER",
            "provider:OpenSSL@3.0.13") in kinds
    assert ("provider:OpenSSL@3.0.13", "PERFORMS_OPERATION",
            "operation:EVP_EncryptInit_ex") in kinds
    assert ("operation:EVP_EncryptInit_ex", "RESOLVES_TO",
            "algorithm:AES-256-GCM") in kinds
    assert ("application:payments-api", "USES_CRYPTO", "algorithm:AES-256-GCM") in kinds


def test_every_graph_edge_is_observed_and_carries_evidence():
    body = pt.graph(_trace(OP, {**OP, "evidence_id": "R-2"})["traces"])
    assert all(edge["provenance"] == "OBSERVED" for edge in body["edges"])
    assert all(edge["evidence_ids"] for edge in body["edges"])
    shortcut = next(edge for edge in body["edges"] if edge["kind"] == "USES_CRYPTO")
    assert shortcut["evidence_ids"] == ["R-2", "RUNTIME-92821"], "repeat observations merge"


def test_nodes_are_typed_by_their_prefix():
    body = pt.graph(_trace()["traces"])
    kinds = {node["id"]: node["kind"] for node in body["nodes"]}
    assert kinds["application:payments-api"] == "APPLICATION"
    assert kinds["algorithm:AES-256-GCM"] == "ALGORITHM"


# --------------------------------------------------------------------------- #
# summary


def test_the_summary_is_one_answer_for_an_operator():
    traces = _trace(OP, {**OP, "algorithm": "RSA-2048", "evidence_id": "R-2"},
                    {**OP, "pid": None, "evidence_id": "R-3"})
    body = pt.summary(traces)
    assert body["traces"] == 2
    assert body["processes"] == 1
    assert body["algorithms"] == {"AES-256-GCM": 1, "RSA-2048": 1}
    assert body["refused"] == 1


@pytest.mark.parametrize("missing", ["application", "pid", "operation", "algorithm",
                                     "evidence_id"])
def test_every_required_link_is_required(missing):
    body = _trace({key: value for key, value in OP.items() if key != missing})
    assert body["traces"] == []
    assert missing in body["refused"][0]["reason"]
