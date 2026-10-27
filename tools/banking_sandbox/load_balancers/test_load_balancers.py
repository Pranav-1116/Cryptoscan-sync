"""Unit predictions constructed from models are scorer tests, NEVER product measurements."""

import json
import pytest
from tools.banking_sandbox.common import records, stream
from tools.banking_sandbox.generator import generate
from tools.banking_sandbox.validator import integrity
from tools.banking_sandbox.load_balancers.catalog import SCENARIOS, CONFIG_STATES
from tools.banking_sandbox.load_balancers.validator import validate_bank, compare


@pytest.fixture(scope="module")
def estate(tmp_path_factory):
    p = tmp_path_factory.mktemp("lb") / "estate"
    generate(p, banks=2, profile="minimal")
    return p


def load(root, name, bank="bank-0001"):
    return list(records(root / "public/load_balancers" / bank / (name + ".jsonl")))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_lb_scenario_has_linked_artifacts(estate, scenario):
    c = next(c for c in load(estate, "cases") if c["scenario"] == scenario)
    assert (estate / "public" / c["config_ref"]).is_file()
    assert len(c["hop_ids"]) >= 1 and c["fixture_only"]
    hops = {h["hop_id"]: h for h in load(estate, "hops")}
    assert all(hops[i]["negotiated"] is None and not hops[i]["actual_execution"] for i in c["hop_ids"])


def test_reencryption_preserves_different_hops(estate):
    c = next(c for c in load(estate, "cases") if c["scenario"] == "tls-re-encryption")
    h = [h for h in load(estate, "hops") if h["hop_id"] in c["hop_ids"]]
    assert len(h) == 2 and len({x["crypto_asset_id"] for x in h}) == 2
    assert {x["configured"]["version"] for x in h} == {"TLS1.2", "TLS1.3"}
    assert len({x["configured"]["certificate_id"] for x in h}) == 2
    assert len({x["configured"]["cipher_preference"] for x in h}) == 2


def test_passthrough_not_lb_certificate(estate):
    c = next(c for c in load(estate, "cases") if c["scenario"] == "tls-passthrough")
    h = next(h for h in load(estate, "hops") if h["hop_id"] in c["hop_ids"])
    assert h["termination_point"] != c["lb_id"] and h["via"] == [c["lb_id"]]
    assert c["listener"]["certificate_id"] is None and c["listener"]["private_key_reference"] is None


def test_three_mtls_combinations(estate):
    cases = {c["scenario"]: c for c in load(estate, "cases")}
    actual = {
        (c["listener"]["client_certificate_required"], c["listener"]["upstream_client_certificate_required"])
        for c in cases.values()
    }
    assert {(True, True), (True, False), (False, True)} <= actual


def test_supported_not_negotiated(estate):
    c = next(c for c in load(estate, "cases") if c["scenario"] == "supported-not-negotiated")
    h = next(h for h in load(estate, "hops") if h["hop_id"] in c["hop_ids"])
    assert "AES-128-CBC" in h["supported"]["ciphers"] and h["negotiated"] is None


def test_all_configuration_states_differ(estate):
    configs = [json.loads((estate / "public" / c["config_ref"]).read_text()) for c in load(estate, "cases")]
    assert set(CONFIG_STATES) == {c["resolution"]["state"] for c in configs}
    files = {
        c["resolution"]["state"]: (
            estate / "public" / next(x["config_ref"] for x in load(estate, "cases") if x["case_id"] == c["case_id"])
        ).parent
        / "nginx.conf"
        for c in configs
    }
    assert "${LAB_TLS_VERSIONS}" in files["environment-driven"].read_text()
    assert "include ../policies/" in files["inherited"].read_text()
    assert "ssl_protocols" not in files["missing"].read_text()


def test_hsm_chain_and_public_certificates(estate):
    assert validate_bank(estate / "public", "bank-0001", True)["crypto_hops"] >= 47
    certs = {c["certificate_id"]: c for c in load(estate, "certificates")}
    for k in load(estate, "keys"):
        c = certs[k["certificate_id"]]
        assert c["private_key_reference"] == k["key_reference"] and c["key_size"] == 3072


def test_graph_has_separate_evidence_for_full_path(estate):
    c = next(c for c in load(estate, "cases") if c["scenario"] == "api-gateway-service")
    hops = [h for h in load(estate, "hops") if h["hop_id"] in c["hop_ids"]]
    assert len(hops) == 6
    assert len({h["evidence_ids"][0] for h in hops}) == 6
    assert any(h["destination"] == "bank-0001-service-mesh" and h["configured"]["mtls_required"] for h in hops)


def test_no_exported_private_material(estate):
    for p in (estate / "public/load_balancers").rglob("*"):
        if p.is_file():
            assert b"PRIVATE KEY-----" not in p.read_bytes()


def test_hidden_truth_is_separate(estate):
    assert len(list(records(estate / "control/ground_truth/bank-0001-loadbalancers.jsonl"))) == 35
    m = json.loads((estate / "manifest.json").read_text())
    assert all("ground_truth" not in r["path"] for r in m["files"])


def test_scoring_empty_keeps_missing_unknown(estate, tmp_path):
    p = tmp_path / "empty"
    stream(p, [])
    r = compare(estate, p)
    assert r["tp"] == 0 and r["fn"] > 90 and r["precision"] is None
    assert r["metrics"]["certificate"]["accuracy"] is None


def prediction(estate):
    c = next(records(estate / "control/ground_truth/bank-0001-loadbalancers.jsonl"))
    return {
        **c["modeled_sessions"][0],
        "case_id": c["case_id"],
        "bank_id": c["bank_id"],
        "lb_id": c["lb_id"],
        "status": "COMPLETE",
        "evidence_id": "UNIT_TEST_ONLY_NOT_MEASURED",
        "evidence_type": "NETWORK_OBSERVED",
        "timestamp": "2030-01-01T00:00:00Z",
    }


def test_unit_predictions_evaluate_parameters_and_attribution(estate, tmp_path):
    r = prediction(estate)
    r["cipher"] = "AES-128-CBC"
    r["termination_point"] = "WRONG"
    p = tmp_path / "unit"
    stream(p, [r])
    score = compare(estate, p)
    assert score["fp"] == 1 and score["metrics"]["attribution"]["incorrect"] == 1
    assert score["metrics"]["crypto_parameters"]["incorrect"] == 1
    assert score["metrics"]["certificate"]["correct"] == 1


@pytest.mark.parametrize(
    "change", [{"bank_id": "bank-9999"}, {"status": "FAILED", "safe": True}, {"evidence_type": "CONFIGURED"}]
)
def test_bad_observations_rejected(estate, tmp_path, change):
    r = prediction(estate)
    r.update(change)
    p = tmp_path / "bad"
    stream(p, [r])
    with pytest.raises(ValueError):
        compare(estate, p)


def test_partial_is_not_absence_or_true_negative(estate, tmp_path):
    r = prediction(estate)
    r["status"] = "PARTIAL"
    p = tmp_path / "partial"
    stream(p, [r])
    score = compare(estate, p)
    assert score["failed_or_partial_or_unknown"] == 1 and score["tp"] == 0


def test_drift_changes_config_not_negotiation(estate, tmp_path):
    from tools.banking_sandbox.operations import apply_drift

    before = (estate / "manifest.json").read_bytes()
    out = tmp_path / "drift"
    result = apply_drift(estate, out)
    assert result["load_balancer_changes"] == 2 and (estate / "manifest.json").read_bytes() == before
    changes = json.loads((out / "control/expected_results/lb-drift.json").read_text())["changes"]
    assert all(
        c["previous_certificate"] != c["current_certificate"] and c["negotiated_change"] is None for c in changes
    )
    assert integrity(out)["load_balancer_validation"]["cases"] == 70


def test_actual_lb_configuration_collection(tmp_path):
    from tools.banking_sandbox.harness import run_static

    estate = tmp_path / "estate"
    generate(estate, banks=1, profile="minimal")
    out = tmp_path / "scan"
    r = run_static(estate, out, mode="lb-config")
    assert r["failure"] is None and r["files"] == 175
    assert r["boundary_receipt"]["guard"]["oracle_read_denied"]
    findings = list(records(out / "findings.jsonl"))
    assert all(f["semantic_scope"] == "CONFIGURATION_NOT_NEGOTIATION" for f in findings)
    assert any(f["algorithms"] for f in findings)


def test_actual_fixed_live_namespace_witness(tmp_path):
    from tools.banking_sandbox.load_balancers.live import run

    r = run(tmp_path / "live")
    assert r["failure"] is None
    receipt = r["receipt"]
    h = {h["hop_id"]: h for h in receipt["network"]}
    assert receipt["interfaces"] == ["lo"] and receipt["oracle_path_read_denied"]
    assert r["parent_before"] == r["parent_after"]
    assert h["reencryption-external"]["version"] == "TLSv1.3" and h["reencryption-internal"]["version"] == "TLSv1.2"
    assert h["passthrough-end-to-end"]["termination_point"] == "backend"
    assert (
        h["drift-external"]["certificate_fingerprint_sha256"]
        != h["termination-external"]["certificate_fingerprint_sha256"]
    )
