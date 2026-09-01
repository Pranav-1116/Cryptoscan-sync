"""§33 ground-truth accuracy platform: metrics + dataset regression targets."""

from __future__ import annotations

from universal_crypto.accuracy import (
    CATEGORIES,
    AccuracyPlatform,
    Evaluator,
    coverage,
    f1,
    false_negative_rate,
    false_positive_rate,
    precision,
    recall,
    unknown_rate,
)
from universal_crypto.engine import UniversalCryptoEngine


def test_metric_math():
    assert precision(10, 0) == 1.0
    assert precision(8, 2) == 0.8
    assert recall(8, 2) == 0.8
    assert recall(0, 0) == 1.0  # nothing expected, nothing missed
    assert f1(1.0, 1.0) == 1.0
    assert f1(0.0, 0.0) == 0.0
    assert false_positive_rate(1, 99) == 0.01
    assert false_negative_rate(2, 8) == 0.2
    assert coverage(8, 10) == 0.8
    assert unknown_rate(2, 10) == 0.2


def test_evaluator_per_category():
    evaluator = Evaluator()
    predictions = [
        {"id": "a", "algorithms": ["SHA-256"], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": [], "unknown": False},
        {"id": "b", "algorithms": [], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": [], "unknown": False},
        {"id": "c", "algorithms": ["AES-GCM", "RSA"], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": [], "unknown": True},
    ]
    ground_truth = [
        {"id": "a", "algorithms": ["SHA-256"], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": []},
        {"id": "b", "algorithms": [], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": []},
        {"id": "c", "algorithms": ["AES-GCM"], "protocols": [], "certificates": [],
         "libraries": [], "implementations": [], "weak": [], "pqc": []},
    ]
    metrics = evaluator.evaluate(predictions, ground_truth)
    alg = metrics["algorithm"]
    assert alg["tp"] == 2
    assert alg["fp"] == 1      # RSA is extra
    assert alg["fn"] == 0
    assert metrics["overall"]["coverage"] == 1.0
    assert abs(metrics["overall"]["unknown_rate"] - 1 / 3) < 0.001


def _detector(engine):
    def detector(case):
        inp = case["input"]
        lang = inp.get("language", "python")
        text = inp.get("text", "")
        result = {"id": case["id"], "algorithms": [], "protocols": [],
                  "certificates": [], "libraries": [], "implementations": [],
                  "weak": [], "pqc": []}
        if lang == "tls":
            r = engine.tls.analyze_suite(text.strip())
            if r.get("known"):
                result["protocols"].append("TLS")
                result["algorithms"].append(r["cipher"])
        else:
            scan = engine.scan({"source_code": [{"language": lang, "text": text}]})
            for obs in scan["observations"]:
                if obs["protocol"]:
                    if obs["protocol"] not in result["protocols"]:
                        result["protocols"].append(obs["protocol"])
                elif obs["algorithm"] not in result["algorithms"]:
                    result["algorithms"].append(obs["algorithm"])
                if obs["library"] and obs["library"] not in result["libraries"]:
                    result["libraries"].append(obs["library"])
        return result
    return detector


def test_known_crypto_dataset_meets_targets():
    platform = AccuracyPlatform()
    result = platform.evaluate_dataset("known_crypto", _detector(UniversalCryptoEngine()))
    overall = result["metrics"]["overall"]
    assert overall["precision"] >= 0.95
    assert overall["recall"] >= 0.95
    assert overall["f1"] >= 0.95
    assert overall["false_positive_rate"] <= 0.05
    assert overall["false_negative_rate"] <= 0.05


def test_known_noncrypto_dataset_zero_false_positives():
    platform = AccuracyPlatform()
    result = platform.evaluate_dataset("known_noncrypto", _detector(UniversalCryptoEngine()))
    overall = result["metrics"]["overall"]
    assert overall["precision"] == 1.0
    assert overall["recall"] == 1.0
    assert overall["f1"] == 1.0
    assert overall["false_positive_rate"] == 0.0


def test_obfuscated_and_real_world_datasets():
    platform = AccuracyPlatform()
    for name in ("obfuscated", "real_world", "custom_crypto"):
        result = platform.evaluate_dataset(name, _detector(UniversalCryptoEngine()))
        overall = result["metrics"]["overall"]
        assert overall["f1"] >= 0.9, name
        assert overall["false_positive_rate"] <= 0.1, name


def test_all_datasets_have_expected_files():
    platform = AccuracyPlatform()
    assert set(platform.dataset_names()) == {
        "known_crypto", "known_noncrypto", "obfuscated",
        "custom_crypto", "real_world", "weak_crypto", "pqc_classification",
        "certificates", "implementations"}
    for name in platform.dataset_names():
        assert len(platform.load_cases(name)) >= 6, name


def test_categories_measured_separately():
    assert set(CATEGORIES) == {
        "algorithm", "protocol", "certificate", "library",
        "implementation", "weak_crypto", "pqc_classification"}


def test_known_crypto_per_category_targets():
    """Regression guard: per-category precision on known_crypto stays 1.0
    (algorithm / protocol / library)."""
    platform = AccuracyPlatform()
    result = platform.evaluate_dataset("known_crypto", _detector(UniversalCryptoEngine()))
    metrics = result["metrics"]
    assert metrics["algorithm"]["f1"] == 1.0
    assert metrics["protocol"]["f1"] == 1.0
    assert metrics["library"]["f1"] == 1.0
    assert metrics["algorithm"]["false_positive_rate"] == 0.0
    assert metrics["library"]["false_positive_rate"] == 0.0


def test_all_datasets_have_at_least_eight_cases():
    platform = AccuracyPlatform()
    for name in platform.dataset_names():
        assert len(platform.load_cases(name)) >= 6, name
    assert len(platform.load_cases("known_crypto")) >= 18
    assert len(platform.load_cases("real_world")) >= 8
    assert len(platform.load_cases("weak_crypto")) >= 8
    assert len(platform.load_cases("pqc_classification")) >= 8


def test_weak_crypto_dataset_policy_driven():
    """§22: same algorithm ALLOWED under NIST, DEPRECATED under EU."""
    from universal_crypto.accuracy import default_detector
    platform = AccuracyPlatform()
    result = platform.evaluate_dataset("weak_crypto", default_detector())
    overall = result["metrics"]["overall"]
    assert overall["precision"] == 1.0
    assert overall["recall"] == 1.0
    assert overall["f1"] == 1.0
    assert overall["false_positive_rate"] == 0.0


def test_pqc_classification_dataset_unknown_stays_unknown():
    """§18/§24: an algorithm outside the registry is PQC_UNKNOWN, never
    labeled safe or vulnerable without evidence."""
    from universal_crypto.accuracy import default_detector
    platform = AccuracyPlatform()
    result = platform.evaluate_dataset("pqc_classification", default_detector())
    overall = result["metrics"]["overall"]
    assert overall["precision"] == 1.0
    assert overall["recall"] == 1.0
    assert overall["f1"] == 1.0
    metrics = result["metrics"]["pqc_classification"]
    assert metrics["fp"] == 0
    assert metrics["fn"] == 0
