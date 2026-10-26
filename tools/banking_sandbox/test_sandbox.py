"""Engineering tests. Synthetic predictions in tests are never published as product measurements."""

import json
import socket

import pytest
from cryptography import x509

from tools.banking_sandbox.generator import generate
from tools.banking_sandbox.common import dump, stream, records, inside
from tools.banking_sandbox.catalog import DIFFICULT, STATIC_SCENARIOS, PROFILES
from tools.banking_sandbox.sources import PYTHON_CASES
from tools.banking_sandbox.validator import integrity, score_static, compare_facts, families
from tools.banking_sandbox.operations import apply_drift, failures, PublicOnly, modes


@pytest.fixture
def estate(tmp_path):
    root = tmp_path / "estate"
    generate(root, banks=2, profile="minimal")
    return root


def test_replay_is_byte_identical_public_inputs(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    generate(a, banks=2, profile="minimal")
    generate(b, banks=2, profile="minimal")
    assert (a / "manifest.json").read_bytes() == (b / "manifest.json").read_bytes()
    assert (a / "LAB.json").read_bytes() == (b / "LAB.json").read_bytes()
    assert (a / "generation-metrics.json").read_bytes() != (b / "generation-metrics.json").read_bytes()


def test_no_network_needed_for_generation(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("generation opened socket"))
    generate(tmp_path / "offline", banks=1, profile="minimal")


@pytest.mark.parametrize("banks,scale", [(0, "small"), (2001, "small"), (1, "invalid")])
def test_invalid_bounds_refuse_without_output(tmp_path, banks, scale):
    p = tmp_path / "bad"
    with pytest.raises(ValueError):
        generate(p, banks=banks, scale=scale)
    assert not p.exists()


def test_budget_refused_before_output(tmp_path):
    p = tmp_path / "budget"
    with pytest.raises(ValueError):
        generate(p, banks=200, scale="mega", max_systems=1)
    assert not p.exists()


def test_existing_output_never_overwritten(estate):
    original = (estate / "manifest.json").read_bytes()
    with pytest.raises(ValueError):
        generate(estate, banks=1)
    assert (estate / "manifest.json").read_bytes() == original


def test_full_schema_integrity_and_all_six_boms(estate):
    r = integrity(estate, True)
    assert r["banks"] == 2 and r["bom_documents_schema_checked"] > 100
    for name in ["nbom", "cbom", "sbom", "techbom", "hbom", "vbom"]:
        assert list((estate / "public" / name).glob("*.jsonl"))


def test_truth_is_separate_and_not_in_manifest(estate):
    m = json.loads((estate / "manifest.json").read_text())
    assert all(not any(s in r["path"] for s in ["ground_truth", "expected_results", "control"]) for r in m["files"])
    assert (estate / "control").stat().st_mode & 0o777 == 0o700
    for p in (estate / "public").rglob("*.jsonl"):
        for row in records(p):
            assert not any(k.startswith("expected_") for k in row)


def test_scenario_coverage_has_real_references(estate):
    rows = list(records(estate / "public/scenarios/bank-0001.jsonl"))
    assert set(DIFFICULT) <= {r["scenario"] for r in rows}
    app = {r["app_id"]: r for r in records(estate / "public/applications/bank-0001.jsonl")}
    shared = next(r for r in rows if r["scenario"] == "shared-library-20-apps")
    assert len(shared["details"]["applications"]) == 20
    assert all(bank in app for bank in shared["details"]["applications"])


def test_different_layers_are_not_conflicts(estate):
    truth = list(records(estate / "control/ground_truth/bank-0001-scenarios.jsonl"))
    public = {r["case_id"]: r for r in records(estate / "public/scenarios/bank-0001.jsonl")}
    for row in truth:
        name = public[row["case_id"]]["scenario"]
        if name in (
            "lb-tls-termination",
            "certificate-vs-application-algorithm",
            "configured-not-negotiated",
            "weak-supported-not-negotiated",
        ):
            assert not row["expected_conflict"]
        if name == "sbom-vs-runtime-provider":
            assert row["expected_conflict"]


def test_missing_source_and_runtime_are_actually_missing(estate):
    public = estate / "public"
    apps = {a["app_id"]: a for a in records(public / "applications/bank-0001.jsonl")}
    cases = list(records(public / "scenarios/bank-0001.jsonl"))
    runtimes = {r["app_id"] for r in records(public / "runtime/bank-0001.jsonl")}
    for c in cases:
        if c["scenario"] in ("network-without-source", "legacy-network-only", "appliance-config-only"):
            assert apps[c["subject"]]["source"] is None
        if c["scenario"] == "source-without-runtime":
            assert c["subject"] not in runtimes


def test_public_runtime_export_is_not_actual_execution(estate):
    for r in records(estate / "public/runtime/bank-0001.jsonl"):
        assert r["fixture_only"] and not r["actual_execution"] and r["evidence_type"] == "IMPORTED"
        assert r["clock_kind"] == "SIMULATED"


def test_pqc_metadata_does_not_claim_execution(estate):
    r = json.loads((estate / "public/pqc/bank-0001.json").read_text())
    assert "NOT_EXECUTED" in r["implementation"]


def test_no_private_keys_written(estate):
    for p in estate.rglob("*"):
        if p.is_file():
            raw = p.read_bytes()
            assert b"-----BEGIN PRIVATE KEY-----" not in raw and b"-----BEGIN RSA PRIVATE KEY-----" not in raw


def test_actual_public_certificates_and_ca_chain(estate):
    pub = estate / "public"
    ca = []
    for name in ["root", "intermediate", "issuing"]:
        ca.append(x509.load_pem_x509_certificate((pub / f"pki/bank-0001-{name}.pem").read_bytes()))
    ca[0].public_key().verify(ca[1].signature, ca[1].tbs_certificate_bytes)
    ca[1].public_key().verify(ca[2].signature, ca[2].tbs_certificate_bytes)
    certs = x509.load_pem_x509_certificates((pub / "certificates/bank-0001.pem").read_bytes())
    assert len(certs) == 40
    ca[2].public_key().verify(certs[0].signature, certs[0].tbs_certificate_bytes)
    assert any("RSA" in type(c.public_key()).__name__ for c in certs)
    assert any("EC" in type(c.public_key()).__name__ for c in certs)


def test_drift_creates_new_snapshot_preserves_baseline(estate, tmp_path):
    old = (estate / "manifest.json").read_bytes()
    destination = tmp_path / "drift"
    r = apply_drift(estate, destination)
    assert r["changes"] == 4 and not r["live_protocol_change"]
    assert (estate / "manifest.json").read_bytes() == old
    assert (destination / "manifest.json").read_bytes() != old
    changes = json.loads((destination / "control/expected_results/drift.json").read_text())
    assert all(c["clock_kind"] == "SIMULATED" for c in changes["expected_changes"])
    integrity(destination)


def test_corrupted_evidence_is_failure_not_absence(estate):
    f = next((estate / "public/source").rglob("*.py"))
    f.write_text("changed")
    with pytest.raises(ValueError):
        integrity(estate)


@pytest.mark.parametrize("ref", ["../control/ground_truth", "/etc/passwd", "source/../../x"])
def test_traversal_refused(estate, ref):
    with pytest.raises(ValueError):
        inside(estate / "public", ref)


def test_escaping_symlink_refused(estate, tmp_path):
    (estate / "public/escape").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        inside(estate / "public", "escape")


def test_duplicate_json_keys_refused(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"x":1,"x":2}\n')
    with pytest.raises(ValueError):
        list(records(p))


def test_nonfinite_json_refused(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"x":NaN}\n')
    with pytest.raises(ValueError):
        list(records(p))


def tiny_oracle(tmp_path):
    p = tmp_path / "tiny"
    (p / "control/ground_truth").mkdir(parents=True)
    dump(p / "LAB.json", {"synthetic": True, "format": "ZELNX_SYNTHETIC_ESTATE_V1"})
    stream(
        p / "control/ground_truth/test-static.jsonl",
        [
            {"source_file": "source/yes.py", "expected_families": ["AES"], "language": "Python"},
            {"source_file": "source/no.py", "expected_families": [], "language": "Python"},
        ],
    )
    return p


def test_precision_recall_false_positive_denominators(tmp_path):
    root = tiny_oracle(tmp_path)
    result = tmp_path / "result.jsonl"
    stream(
        result,
        [
            {"source_file": "source/yes.py", "status": "COMPLETE", "algorithms": ["AES-256-GCM"]},
            {"source_file": "source/no.py", "status": "COMPLETE", "algorithms": ["MD5"]},
        ],
    )
    r = score_static(root, result)
    assert r["precision"] == 0.5 and r["recall"] == 1 and r["false_positive_rate_negative_files"] == 1


def test_failed_negative_is_unknown_not_true_negative(tmp_path):
    root = tiny_oracle(tmp_path)
    result = tmp_path / "result.jsonl"
    stream(
        result,
        [
            {"source_file": "source/yes.py", "status": "FAILED", "algorithms": []},
            {"source_file": "source/no.py", "status": "FAILED", "algorithms": []},
        ],
    )
    r = score_static(root, result)
    assert r["tn_negative_files"] == 0 and r["false_positive_rate_negative_files"] is None
    assert r["failed_or_missing_files"] == 2 and r["fn"] == 1


@pytest.mark.parametrize(
    "name,expected",
    [("HmacSHA256", {"HMAC", "SHA-256"}), ("SHA256withRSA", {"SHA-256", "RSA"}), ("AES/GCM/NoPadding", {"AES"})],
)
def test_composite_family_normalization(name, expected):
    assert families(name) == expected


def test_unknown_never_promoted_to_safe(estate, tmp_path):
    t = next(
        r
        for r in records(estate / "control/ground_truth/bank-0001-scenarios.jsonl")
        if r["expected_status"] == "UNKNOWN"
    )
    p = tmp_path / "unsafe.jsonl"
    stream(
        p,
        [
            {
                "case_id": t["case_id"],
                "bank_id": t["bank_id"],
                "subject": t["subject"],
                "layer": t["layer"],
                "safe": True,
            }
        ],
    )
    with pytest.raises(ValueError):
        compare_facts(estate, p)


def test_cross_bank_attribution_refused(estate, tmp_path):
    t = next(records(estate / "control/ground_truth/bank-0001-scenarios.jsonl"))
    p = tmp_path / "wrong.jsonl"
    stream(p, [{"case_id": t["case_id"], "bank_id": "bank-9999", "subject": t["subject"], "layer": t["layer"]}])
    with pytest.raises(ValueError):
        compare_facts(estate, p)


def test_missing_results_remain_missing(estate, tmp_path):
    p = tmp_path / "empty.jsonl"
    stream(p, [])
    r = compare_facts(estate, p)
    assert r["missing_cases"] == 70 and all(m["missing"] == 70 for m in r["metrics"].values())


def test_dashboard_never_serves_control(estate):
    h = object.__new__(PublicOnly)
    h.directory = str(estate / "public")
    for path in ["/../control/ground_truth/x", "/%2e%2e/control", "/../../etc/passwd"]:
        assert "FORBIDDEN" in h.translate_path(path)
    assert h.translate_path("/index.html") == str(estate / "public/index.html")


def test_customer_preview_does_not_claim_real_bank_assurance():
    from tools.banking_sandbox.realbanks import HTML_REALBANKS

    assert "Synthetic Banking Preview" in HTML_REALBANKS
    assert "No customer accounts" in HTML_REALBANKS
    for unsupported in ("Member FDIC", "24/7 fraud monitoring", "24/7 support", "TLS 1.2+ mandatory"):
        assert unsupported not in HTML_REALBANKS


def test_kubernetes_exports_secret_metadata_only(estate):
    rows = json.loads((estate / "public/kubernetes/bank-0001.json").read_text())["items"]
    assert {
        "Namespace",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "Pod",
        "Service",
        "Ingress",
        "Gateway",
        "Role",
        "NetworkPolicy",
    } <= {r["kind"] for r in rows}
    assert all("data" not in r and "stringData" not in r for r in rows if r["kind"] == "Secret")


def test_all_test_modes_are_honestly_typed():
    assert len(modes()["modes"]) == 15
    assert modes()["modes"]["cross-correlation"]["implementation"] == "FIXTURES_AND_EXTERNAL_RESULT_VALIDATOR_ONLY"


def test_all_static_scenario_templates_present():
    assert set(STATIC_SCENARIOS) == set(PYTHON_CASES)


def test_actual_input_failure_exercises(tmp_path):
    r = failures(tmp_path / "failure-results")
    assert r["all_rejected"] and len(r["executed_checks"]) == 3
    assert "NOT_EXECUTED" in r["database_redis_hsm_kms_cluster_outage_execution"]


def test_real_static_collector_guard_and_oracle_separation(tmp_path):
    from tools.banking_sandbox.harness import run_static

    p = tmp_path / "estate"
    generate(p, banks=1, profile="minimal")
    result = run_static(p, tmp_path / "result")
    assert result["failure"] is None
    guard = result["boundary_receipt"]["guard"]
    assert guard["oracle_read_denied"] and guard["socket_creation_denied"]
    assert result["files"] == 17


@pytest.mark.parametrize("profile", PROFILES)
def test_each_profile_generates_a_valid_bank(tmp_path, profile):
    root = tmp_path / profile
    count = generate(root, banks=1, profile=profile, scale="small")
    assert count["banks"] == 1
    assert integrity(root)["banks"] == 1


def test_200_bank_option_and_archetypes(tmp_path):
    from tools.banking_sandbox.catalog import ARCHETYPES

    root = tmp_path / "two-hundred"
    count = generate(root, banks=200, profile="minimal")
    banks = [json.loads(p.read_text()) for p in (root / "public/banks").glob("*.json")]
    assert count["banks"] == 200 and len({b["bank_id"] for b in banks}) == 200
    assert set(ARCHETYPES) == {b["archetype"] for b in banks}
    assert len({b["organization_name"] for b in banks}) == 200


def test_optional_packaging_server_rejects_escaping_path(tmp_path):
    from tools.banking_sandbox.compose.server import PublicOnly as Packaged

    h = object.__new__(Packaged)
    h.directory = str(tmp_path)
    assert "FORBIDDEN" in h.translate_path("/%2e%2e/etc/passwd")
    (tmp_path / "escape").symlink_to("/etc")
    assert "FORBIDDEN" in h.translate_path("/escape/passwd")
