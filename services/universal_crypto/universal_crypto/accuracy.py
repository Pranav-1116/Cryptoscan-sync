"""§33 Ground-truth accuracy platform.

    crypto_accuracy/
    ├── datasets/{known_crypto, known_noncrypto, obfuscated,
    │             custom_crypto, real_world}/
    │     └── cases.json          (id, input, expected)
    ├── expected/
    ├── detections/
    ├── evaluator/
    ├── precision.py / recall.py / f1.py
    └── regression_tests/

Measures per category (algorithm, protocol, certificate, library,
implementation, weak crypto, PQC classification): precision, recall, F1,
false positive rate, false negative rate, coverage, unknown rate — the
credible replacement for "we are 95% accurate".
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterable, Optional

#: categories measured separately (§33)
CATEGORIES = [
    "algorithm", "protocol", "certificate", "library",
    "implementation", "weak_crypto", "pqc_classification",
]


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 1.0


def recall(tp: int, fn: int) -> float:
    # tp=fn=0 → nothing was expected and nothing was missed: perfect recall
    # (a case with an empty ground-truth set is not a recall failure)
    return 1.0 if (tp + fn) == 0 else tp / (tp + fn)


def f1(p: float, r: float) -> float:
    return 2 * p * r / (p + r) if (p + r) else 0.0


def false_positive_rate(fp: int, tn: int) -> float:
    return fp / (fp + tn) if (fp + tn) else 0.0


def false_negative_rate(fn: int, tp: int) -> float:
    return fn / (fn + tp) if (fn + tp) else 0.0


def coverage(detected: int, labeled: int) -> float:
    return detected / labeled if labeled else 1.0


def unknown_rate(unknown: int, total: int) -> float:
    return unknown / total if total else 0.0


class Evaluator:
    """§33 per-category and overall metrics from predictions vs ground truth.

    ``predictions``: [{"id", "algorithms": [...], "protocols": [...],
    "certificates": [...], "libraries": [...], "implementations": [...],
    "weak": [...], "pqc": [...], "unknown": bool}]
    ``ground_truth``: same shape with expected values.
    """

    def evaluate(
        self,
        predictions: Iterable[dict[str, Any]],
        ground_truth: Iterable[dict[str, Any]],
    ) -> dict[str, Any]:
        truth = {case["id"]: case for case in ground_truth}
        by_category: dict[str, dict[str, int]] = {
            cat: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for cat in CATEGORIES}
        vocab: dict[str, set[str]] = {cat: set() for cat in CATEGORIES}
        unknown_total = 0
        unknown_count = 0
        labeled_total = 0

        for prediction in predictions:
            case_id = prediction["id"]
            expected = truth.get(case_id)
            if expected is None:
                continue
            labeled_total += 1
            if prediction.get("unknown"):
                unknown_count += 1
            for category in CATEGORIES:
                key = _key(category)
                exp = {str(v).upper() for v in (expected.get(key) or [])}
                pred = {str(v).upper() for v in (prediction.get(key) or [])}
                vocab[category].update(exp | pred)
                counts = by_category[category]
                counts["tp"] += len(pred & exp)
                counts["fp"] += len(pred - exp)
                counts["fn"] += len(exp - pred)
        unknown_total = labeled_total

        metrics: dict[str, Any] = {}
        for category in CATEGORIES:
            counts = by_category[category]
            # true negatives: vocabulary names absent from both expected and
            # predicted across all cases (proper confusion matrix per class)
            for case in truth.values():
                exp = {str(v).upper() for v in (case.get(_key(category)) or [])}
                counts["tn"] += len(vocab[category] - exp)
            for prediction in predictions:
                if prediction["id"] not in truth:
                    continue
                pred = {str(v).upper()
                        for v in (prediction.get(_key(category)) or [])}
                counts["tn"] -= len(pred)  # predicted names are fp, not tn
            counts["tn"] = max(0, counts["tn"])
            p = precision(counts["tp"], counts["fp"])
            r = recall(counts["tp"], counts["fn"])
            metrics[category] = {
                "precision": round(p, 4),
                "recall": round(r, 4),
                "f1": round(f1(p, r), 4),
                "false_positive_rate": round(
                    false_positive_rate(counts["fp"], counts["tn"]), 4),
                "false_negative_rate": round(
                    counts["fn"] / (counts["fn"] + counts["tp"])
                    if (counts["fn"] + counts["tp"]) else 0.0, 4),
                "tp": counts["tp"], "fp": counts["fp"], "fn": counts["fn"],
                "tn": counts["tn"],
            }
        total_tp = sum(by_category[c]["tp"] for c in CATEGORIES)
        total_fp = sum(by_category[c]["fp"] for c in CATEGORIES)
        total_fn = sum(by_category[c]["fn"] for c in CATEGORIES)
        total_tn = sum(by_category[c]["tn"] for c in CATEGORIES)
        p_all = precision(total_tp, total_fp)
        r_all = recall(total_tp, total_fn)
        metrics["overall"] = {
            "precision": round(p_all, 4),
            "recall": round(r_all, 4),
            "f1": round(f1(p_all, r_all), 4),
            "false_positive_rate": round(
                false_positive_rate(total_fp, total_tn), 4),
            "false_negative_rate": round(
                total_fn / (total_fn + total_tp) if (total_fn + total_tp) else 0.0, 4),
            "coverage": round(coverage(labeled_total, len(truth)), 4),
            "unknown_rate": round(unknown_rate(unknown_count, unknown_total), 4),
        }
        return metrics


def _key(category: str) -> str:
    return {
        "algorithm": "algorithms",
        "protocol": "protocols",
        "certificate": "certificates",
        "library": "libraries",
        "implementation": "implementations",
        "weak_crypto": "weak",
        "pqc_classification": "pqc",
    }[category]


class AccuracyPlatform:
    """§33 dataset-driven evaluation. Datasets live in
    ``universal_crypto/accuracy_data/datasets/<name>/cases.json`` and the
    detector callable maps a case input to a prediction dict.
    """

    def __init__(self, data_root: Optional[str] = None) -> None:
        self.data_root = data_root or os.path.join(
            os.path.dirname(__file__), "accuracy_data")

    def dataset_names(self) -> list[str]:
        path = os.path.join(self.data_root, "datasets")
        return sorted(d for d in os.listdir(path)
                      if os.path.isdir(os.path.join(path, d)))

    def load_cases(self, dataset: str) -> list[dict[str, Any]]:
        path = os.path.join(self.data_root, "datasets", dataset, "cases.json")
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def load_expected(self, dataset: str) -> list[dict[str, Any]]:
        return [{"id": case["id"],
                 "algorithms": case.get("expected", {}).get("algorithms", []),
                 "protocols": case.get("expected", {}).get("protocols", []),
                 "certificates": case.get("expected", {}).get("certificates", []),
                 "libraries": case.get("expected", {}).get("libraries", []),
                 "implementations": case.get("expected", {}).get("implementations", []),
                 "weak": case.get("expected", {}).get("weak", []),
                 "pqc": case.get("expected", {}).get("pqc", [])}
                for case in self.load_cases(dataset)]

    def evaluate_dataset(
        self,
        dataset: str,
        detector: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        cases = self.load_cases(dataset)
        expected = self.load_expected(dataset)
        predictions = [detector(case) for case in cases]
        return {
            "dataset": dataset,
            "cases": len(cases),
            "metrics": Evaluator().evaluate(predictions, expected),
        }

    def evaluate_all(
        self,
        detector: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        results = {}
        for name in self.dataset_names():
            results[name] = self.evaluate_dataset(name, detector)
        return results


def default_detector(engine: Optional[Any] = None) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """The §33 reference detector — one callable for every dataset shape.

    Handles all case ``input`` shapes deterministically:

    * ``{"language", "text"}``          → §4/§5 source-code detection
    * ``{"language": "tls", "text"}``   → §10 TLS suite analysis
    * ``{"algorithm", "policy", ...}``  → §22 weak-crypto policy classification
    * ``{"algorithm", "usage", ...}``   → §18/§2 PQC classification
    """
    if engine is None:
        from universal_crypto.engine import UniversalCryptoEngine
        engine = UniversalCryptoEngine()

    def detector(case: dict[str, Any]) -> dict[str, Any]:
        inp = case["input"]
        result = {"id": case["id"], "algorithms": [], "protocols": [],
                  "certificates": [], "libraries": [], "implementations": [],
                  "weak": [], "pqc": []}
        if inp.get("language") == "tls" and inp.get("text"):
            r = engine.tls.analyze_suite(inp["text"].strip())
            if r.get("known"):
                result["protocols"].append("TLS")
                result["algorithms"].append(r["cipher"])
        elif "text" in inp:
            scan = engine.scan({"source_code": [{
                "language": inp.get("language", "python"),
                "text": inp["text"]}]})
            for obs in scan["observations"]:
                if obs["protocol"]:
                    if obs["protocol"] not in result["protocols"]:
                        result["protocols"].append(obs["protocol"])
                elif obs["algorithm"] not in result["algorithms"]:
                    result["algorithms"].append(obs["algorithm"])
                if obs["library"] and obs["library"] not in result["libraries"]:
                    result["libraries"].append(obs["library"])
        elif "der" in inp or "pem" in inp:
            # §13 certificate intelligence (metadata only — keys never stored)
            cert = engine.certs.analyze_certificate(
                der=inp["der"] if isinstance(inp["der"], bytes)
                else bytes.fromhex(inp["der"]),
                location=inp.get("location", ""),
                asset_id=inp.get("asset_id", "default"))
            for alg in (cert.get("public_key_algorithm"),
                        cert.get("signature_algorithm")):
                if alg and alg != "UNKNOWN" and alg not in result["certificates"]:
                    result["certificates"].append(alg)
        elif "implementation_name" in inp or "library_hint" in inp \
                or "symbols" in inp:
            # §24 custom-crypto classification
            cls = engine.custom.classify(
                implementation_name=inp.get("implementation_name", ""),
                symbols=inp.get("symbols"),
                library_hint=inp.get("library_hint", ""),
                api_names=inp.get("api_names"))["classification"]
            result["implementations"].append(cls)
        elif "policy" in inp or "custom_rules" in inp:
            # §22 weak-crypto policy classification
            verdict = engine.weak.classify(
                algorithm=inp["algorithm"],
                policy=inp.get("policy", "NIST"),
                key_size=inp.get("key_size"),
                tls_version=inp.get("tls_version"),
                custom_rules=inp.get("custom_rules"))["verdict"]
            if verdict in ("DEPRECATED", "BANNED"):
                result["weak"].append(verdict)
        elif "algorithm" in inp:
            # §18/§2 PQC classification
            status = engine.quantum.classify(
                algorithm=inp["algorithm"],
                usage=bool(inp.get("usage", True)))["quantum_status"]
            result["pqc"].append(status)
        return result

    return detector
