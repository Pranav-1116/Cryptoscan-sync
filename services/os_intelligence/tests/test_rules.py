"""OS-CRYPTO-001…018 rule catalogue + risk model acceptance tests
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §9).

Rules are DETECTIONS, never automatic vulnerability verdicts. Severity
is computed (R=f(S,E,X,B,C)) with preserved factors and a model
version — never a multiplied 'scientifically validated score'. A rule
whose evidence source is missing is NOT EVALUABLE — never clean.
"""

from __future__ import annotations

from pathlib import Path

from os_intelligence.collector import collect_linux
from os_intelligence.risk import assess
from os_intelligence.rules import CATALOGUE, evaluate

_FIXTURES = Path(__file__).parent / "fixtures"
_HOST = (_FIXTURES / "host-linux-sample.txt").read_text()
_EMPTY = str(_FIXTURES / "empty-root")


def _section(name: str) -> str:
    return _HOST.split(f"--- {name}")[1].split("\n---")[0]


def _root_inv(tmp_path, *, with_config=True, with_storage=True,
              with_tainted=True):
    root = tmp_path / "root"
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "proc/version").write_text(
        "Linux version 6.1.158+ (u@h) (gcc) #1 SMP x86_64\n")
    (root / "etc/os-release").write_text(_section("os-release"))
    (root / "proc/crypto").write_text(_section("proc-crypto"))
    (root / "proc/modules").write_text(_section("proc-modules"))
    if with_tainted:
        (root / "proc/sys/kernel/tainted").write_text(_section("tainted"))
    if with_config:
        (root / "proc/config.gz-or-boot-config").write_text(
            _section("config-crypto"))
    if with_storage:
        (root / "proc/lsblk-f").write_text(_section("lsblk-f"))
    return collect_linux("h", source_root=str(root),
                         collect_hardware_trust=False).as_dict()


def _by_id(report, rule_id):
    return [r for r in report.results if r.rule_id == rule_id][0]


class TestCatalogue:
    def test_eighteen_rules_present(self):
        assert len(CATALOGUE) == 18
        ids = [r[0] for r in CATALOGUE]
        assert ids == [f"OS-CRYPTO-{i:03d}" for i in range(1, 19)]

    def test_every_rule_evaluates_or_is_honestly_not_evaluable(self):
        inv = collect_linux("x", source_root=_EMPTY,
                            collect_hardware_trust=False).as_dict()
        report = evaluate(inv)
        assert len(report.results) == 18
        for r in report.results:
            assert r.status in ("evaluated", "not_evaluable")
            if r.status == "not_evaluable":
                assert "NEVER" in r.evaluation_note or \
                    "never" in r.evaluation_note
                assert "unavailable" in r.evaluation_note or \
                    "not collected" in r.evaluation_note or \
                    "NOT IMPLEMENTED" in r.evaluation_note or \
                    "no predecessor" in r.evaluation_note or \
                    "without a declared baseline" in r.evaluation_note or \
                    "two points in time" in r.evaluation_note

    def test_results_are_never_verdicts(self):
        inv = collect_linux("x", source_root=_EMPTY,
                            collect_hardware_trust=False).as_dict()
        for r in evaluate(inv).results:
            d = r.as_dict()
            assert "never an automatic vulnerability verdict" in d["note"]


class TestDetections:
    def test_001_weak_implementations_detected_with_honest_wording(
            self, tmp_path):
        inv = _root_inv(tmp_path)
        # the recorded host registers hmac(sha1) — a SHA-1-based
        # implementation; the component matcher must see inside parens
        result = _by_id(evaluate(inv), "OS-CRYPTO-001")
        assert result.status == "evaluated"
        assert result.findings, "the recorded host registers sha1-family"
        assert any("sha1" in f["algorithm"] for f in result.findings)
        f = result.findings[0]
        assert f["runtime_usage_confirmed"] is False
        assert "not evidence that any application used it" in \
            f["details"]["risk"]
        assert f["details"]["observed_runtime_negotiation"] == \
            "Not established"
        assert f["details"]["business_system"] == \
            "Requires registered mapping"

    def test_001_severity_computed_with_factors(self, tmp_path):
        inv = _root_inv(tmp_path)
        f = _by_id(evaluate(inv), "OS-CRYPTO-001").findings[0]
        assert f["risk_model_version"] == "os-risk/1.0"
        factors = f["severity_factors"]["factors"]
        for key in ("S_security_significance", "E_evidence_confidence",
                    "X_actual_exposure", "B_business_impact",
                    "C_compensating_controls"):
            assert key in factors
        assert "derivation" in f["severity_factors"]
        assert "score" not in f["severity_factors"], \
            "never a multiplied numeric score"

    def test_002_af_alg_note_never_blanket_recommends_disabling(
            self, tmp_path):
        inv = _root_inv(tmp_path)
        result = _by_id(evaluate(inv), "OS-CRYPTO-002")
        assert result.status == "evaluated"
        if result.findings:
            assert "not blanket" in \
                result.findings[0]["details"]["recommendation"]

    def test_003_baseline_required_for_unexpected(self, tmp_path):
        inv = _root_inv(tmp_path)
        without = _by_id(evaluate(inv), "OS-CRYPTO-003")
        assert without.status == "not_evaluable"
        assert "cannot be asserted" in without.evaluation_note
        with_baseline = _by_id(
            evaluate(inv, baseline_modules=["overlay"]),
            "OS-CRYPTO-003")
        assert with_baseline.status == "evaluated"
        # the recorded container module line is an error line — honest
        # parsing means NO module rows, so nothing is 'unexpected'
        assert with_baseline.findings == [] or all(
            "declared baseline" in str(f["limitations"]) for f in
            with_baseline.findings)

    def test_004_taints_detected_but_never_a_verdict(self):
        inv = {
            "host_id": "h",
            "identity": {"tainted_flags": "4096",
                         "tainted_meanings": ["UNSIGNED_MODULE"]},
            "coverage": {"sources_collected": ["tainted"]},
        }
        result = _by_id(evaluate(inv), "OS-CRYPTO-004")
        assert result.status == "evaluated"
        f = result.findings[0]
        assert "never a defect verdict" in str(f["limitations"])
        assert f["severity_label"] in ("low", "medium")

    def test_004_missing_taint_source_never_zero(self):
        inv = {"host_id": "h", "identity": {},
               "coverage": {"sources_collected": []}}
        result = _by_id(evaluate(inv), "OS-CRYPTO-004")
        assert result.status == "not_evaluable"
        assert "never 'no taints'" in result.evaluation_note

    def test_007_disk_encryption_not_established_is_what_metadata_shows(
            self, tmp_path):
        inv = _root_inv(tmp_path)
        result = _by_id(evaluate(inv), "OS-CRYPTO-007")
        assert result.status == "evaluated"
        # fixture lsblk shows plain rows (error line -> no rows) — either
        # way the claim stays 'not established', never 'not encrypted'
        for f in result.findings:
            assert "not proof that no encryption exists" in \
                str(f["limitations"])

    def test_009_tpm_unavailable_is_unknown_never_absent(self):
        inv = {
            "host_id": "h",
            "hardware_trust": [{"subject": "tpm", "state": "unavailable",
                                "evidence_class": "unknown",
                                "metadata": {}, "notes": []}],
            "coverage": {"sources_collected": ["tpm_device"]},
        }
        result = _by_id(evaluate(inv), "OS-CRYPTO-009")
        f = result.findings[0]
        assert f["evidence_class"] == "unknown"
        assert "NOT proof of absence" in str(f["limitations"])
        assert f["details"]["condition"].startswith("TPM availability "
                                                    "could not be")

    def test_012_drift_needs_two_points(self, tmp_path):
        inv = _root_inv(tmp_path)
        alone = _by_id(evaluate(inv), "OS-CRYPTO-012")
        assert alone.status == "not_evaluable"
        assert "no predecessor" in alone.evaluation_note
        previous = {"crypto_api": [
            {"algorithm": "gone-alg", "driver": "gone-driver"}]}
        drifted = _by_id(evaluate(inv, previous=previous), "OS-CRYPTO-012")
        assert drifted.status == "evaluated"
        changes = {f["details"]["change"] for f in drifted.findings}
        assert "removed" in changes
        for f in drifted.findings:
            assert "not its cause" in str(f["limitations"])

    def test_014_randomness_never_judged_by_one_counter(self, tmp_path):
        inv = _root_inv(tmp_path)
        result = _by_id(evaluate(inv), "OS-CRYPTO-014")
        if result.findings:
            assert "NEVER declared secure or insecure" in \
                str(result.findings[0]["limitations"]) or \
                "never declared secure or insecure" in \
                str(result.findings[0]["limitations"]).lower()
        # explicit not_set state in config flags
        inv2 = dict(inv)
        inv2["config_flags"] = {"CONFIG_RANDOM_TRUST_CPU": "not_set"}
        inv2["coverage"] = {"sources_collected": ["config_flags"]}
        fired = _by_id(evaluate(inv2), "OS-CRYPTO-014")
        assert fired.findings
        assert fired.findings[0]["details"]["value"] == "not_set"

    def test_015_pqc_presence_is_never_usage(self):
        inv = {
            "host_id": "h",
            "crypto_api": [{"algorithm": "ml-kem-768",
                            "driver": "ml-kem-768-generic", "type": "kpp"}],
            "coverage": {"sources_collected": ["proc_crypto"]},
        }
        result = _by_id(evaluate(inv), "OS-CRYPTO-015")
        f = result.findings[0]
        assert "PQC presence is NEVER PQC usage" in str(f["limitations"])

    def test_015_no_pqc_is_never_absent(self):
        inv = {
            "host_id": "h",
            "crypto_api": [{"algorithm": "aes", "driver": "aes-generic"}],
            "coverage": {"sources_collected": ["proc_crypto"]},
        }
        result = _by_id(evaluate(inv), "OS-CRYPTO-015")
        f = result.findings[0]
        assert f["evidence_class"] == "not_detected"
        assert "NOT ruled out" in str(f["limitations"])

    def test_016_explicit_disabled_vs_unavailable(self):
        inv_off = {
            "host_id": "h",
            "config_flags": {"CONFIG_CRYPTO_RSA": "not_set"},
            "coverage": {"sources_collected": ["config_flags"]},
        }
        fired = _by_id(evaluate(inv_off), "OS-CRYPTO-016")
        assert fired.findings[0]["details"]["flags"] == ["CONFIG_CRYPTO_RSA"]
        inv_missing = {"host_id": "h", "config_flags": {},
                       "coverage": {"sources_collected": []}}
        quiet = _by_id(evaluate(inv_missing), "OS-CRYPTO-016")
        assert quiet.status == "not_evaluable"
        assert "never 'disabled'" in quiet.evaluation_note

    def test_017_tier2_absent_is_never_healthy(self):
        inv = {"host_id": "h", "coverage": {"sources_collected": []}}
        result = _by_id(evaluate(inv), "OS-CRYPTO-017")
        assert result.status == "not_evaluable"
        assert "no runtime session was collected" in \
            result.evaluation_note
        assert "never reported as 'healthy'" in result.evaluation_note
        assert "never as 'no event loss'" in result.evaluation_note

    def test_018_state_change_needs_previous(self):
        inv = {"host_id": "h",
               "hardware_trust": [{"subject": "tpm", "state": "present",
                                   "evidence_class": "observed",
                                   "metadata": {}, "notes": []}],
               "coverage": {"sources_collected": []}}
        alone = _by_id(evaluate(inv), "OS-CRYPTO-018")
        assert alone.status == "not_evaluable"
        previous = {"hardware_trust": [{"subject": "tpm",
                                        "state": "unavailable"}]}
        changed = _by_id(evaluate(inv, previous=previous), "OS-CRYPTO-018")
        assert changed.findings[0]["details"]["previous_state"] == \
            "unavailable"


class TestRiskModel:
    def test_factors_preserved_and_model_versioned(self):
        a = assess(security_significance="high", evidence_class="indicated")
        d = a.as_dict()
        assert d["risk_model_version"] == "os-risk/1.0"
        assert set(d["factors"]) == {
            "S_security_significance", "E_evidence_confidence",
            "X_actual_exposure", "B_business_impact",
            "C_compensating_controls"}
        assert "not a multiplied" in d["note"]

    def test_critical_requires_registered_high_and_observed(self):
        best = assess(security_significance="high", evidence_class="observed",
                      exposure="observed", business_impact="registered_high")
        assert best.severity_label == "critical"
        capped = assess(security_significance="high",
                        evidence_class="observed", exposure="observed")
        assert capped.severity_label == "medium", \
            "without a registered business mapping 'critical' and 'high' " \
            "are unreachable"

    def test_unknown_evidence_never_raises(self):
        a = assess(security_significance="high", evidence_class="unknown")
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3,
                "critical": 4}
        assert rank[a.severity_label] <= rank["low"], \
            "a condition with no evidence confidence never raises"

    def test_invalid_factors_are_refused_never_guessed(self):
        for kwargs in ({"security_significance": "extreme"},
                       {"security_significance": "low",
                        "exposure": "maybe"},
                       {"security_significance": "low",
                        "business_impact": "invented"},
                       {"security_significance": "low",
                        "compensating_controls": "magic"}):
            try:
                assess(**{"evidence_class": "observed", **kwargs})
            except ValueError:
                continue
            raise AssertionError(f"factor not refused: {kwargs}")

    def test_compensating_controls_reduce_but_never_invent(self):
        plain = assess(security_significance="high",
                       evidence_class="observed",
                       exposure="configuration_only")
        with_c = assess(security_significance="high",
                        evidence_class="observed",
                        exposure="configuration_only",
                        compensating_controls="recorded")
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3,
                "critical": 4}
        assert rank[with_c.severity_label] < rank[plain.severity_label]
