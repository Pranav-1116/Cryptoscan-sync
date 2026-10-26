"""Controlled oracle evaluator. Never run inside a collector or mount in a scanner."""

from collections import Counter
from pathlib import Path
import json
from tools.banking_sandbox.common import open_estate, records, inside, file_hash
from tools.banking_sandbox.catalog import DIFFICULT, TEST_MODES, FAILURES
from tools.banking_sandbox.documents import validators


def integrity(root, full_schemas=False):
    root, meta = open_estate(root)
    public = root / "public"
    manifest = json.loads((root / "manifest.json").read_text())
    names = set()
    for f in manifest["files"]:
        p = inside(public, f["path"])
        if f["path"] in names or not p.is_file() or p.stat().st_size != f["bytes"] or file_hash(p) != f["sha256"]:
            raise ValueError("public evidence corrupted: " + f["path"])
        names.add(f["path"])
    actual = {str(p.relative_to(public)) for p in public.rglob("*") if p.is_file()}
    if names != actual:
        raise ValueError("unlisted or missing public input")
    cdx, spdx = validators()
    banks = sorted((public / "banks").glob("*.json"))
    n = 0
    for b in banks:
        bank = b.stem
        systems = {r["system_id"]: r for r in records(public / "systems" / f"{bank}.jsonl")}
        apps = {r["app_id"]: r for r in records(public / "applications" / f"{bank}.jsonl")}
        endpoints = {r["endpoint_id"]: r for r in records(public / "network" / f"{bank}.jsonl")}
        certificates = {r["certificate_id"]: r for r in records(public / "certificates" / f"{bank}.jsonl")}
        for a in apps.values():
            if (
                a["system_id"] not in systems
                or not set(a["service_ids"]) <= endpoints.keys()
                or not set(a["certificate_ids"]) <= certificates.keys()
            ):
                raise ValueError("broken app reference")
            if a["source"] is not None:
                inside(public, a["source"])
        for e in endpoints.values():
            if e["app_id"] not in apps or e["system_id"] not in systems or e["certificate_id"] not in certificates:
                raise ValueError("broken endpoint")
        cases = list(records(public / "scenarios" / f"{bank}.jsonl"))
        if set(DIFFICULT + FAILURES) != {r["scenario"] for r in cases}:
            raise ValueError("incomplete scenario coverage")
        for r in cases:
            if r.get("subject") and r["subject"] not in apps:
                raise ValueError("scenario subject missing")
        shared = next(r for r in cases if r["scenario"] == "shared-library-20-apps")
        if len(shared["details"]["applications"]) != 20 or not set(shared["details"]["applications"]) <= apps.keys():
            raise ValueError("shared-library case not materialized")
        for path in [
            public / "sbom" / f"{bank}.jsonl",
            public / "sbom" / f"{bank}-spdx.jsonl",
            public / "cbom" / f"{bank}.jsonl",
        ]:
            for i, row in enumerate(records(path)):
                if full_schemas or i < 2:
                    (spdx if path.name.endswith("-spdx.jsonl") else cdx).validate(row["document"])
                    n += 1
    return {
        "status": "FIXTURE_INTEGRITY_VALIDATED_NOT_PRODUCT_DISCOVERY",
        "banks": len(banks),
        "file_hashes_checked": len(names),
        "bom_documents_schema_checked": n,
        "schema_sampling": not full_schemas,
        "test_modes": TEST_MODES,
        "synthetic": True,
    }


def canonical_family(text):
    import re

    s = re.sub("[^A-Z0-9]", "", str(text).upper())
    for prefix, name in [
        ("HMAC", "HMAC"),
        ("SHA256", "SHA-256"),
        ("SHA384", "SHA-384"),
        ("SHA512", "SHA-512"),
        ("SHA1", "SHA-1"),
        ("AES", "AES"),
        ("RSA", "RSA"),
        ("ECDSA", "ECDSA"),
        ("ECDH", "ECDH"),
        ("ED25519", "Ed25519"),
        ("X25519", "X25519"),
        ("HKDF", "HKDF"),
        ("MD5", "MD5"),
        ("MLKEM", "ML-KEM"),
        ("MLDSA", "ML-DSA"),
        ("SLHDSA", "SLH-DSA"),
    ]:
        if s.startswith(prefix):
            return name
    return str(text) if s not in ("", "NONE", "UNKNOWN") else None


def families(text):
    import re

    primary = canonical_family(text)
    result = {primary} if primary else set()
    compact = re.sub("[^A-Z0-9]", "", str(text).upper())
    if primary in ("RSA", "ECDSA", "HMAC", "SHA-256", "SHA-384", "SHA-512", "SHA-1"):
        for token, label in [("SHA256", "SHA-256"), ("SHA384", "SHA-384"), ("SHA512", "SHA-512"), ("SHA1", "SHA-1")]:
            if token in compact:
                result.add(label)
        if "WITHRSA" in compact or compact.startswith("RSA"):
            result.add("RSA")
        if "WITHECDSA" in compact or compact.startswith("ECDSA"):
            result.add("ECDSA")
    return result


def score_static(root, result_path):
    root, meta = open_estate(root)
    results = list(records(Path(result_path)))
    observed = {}
    for row in results:
        key = row["source_file"]
        if key in observed:
            raise ValueError("duplicate collector disposition")
        observed[key] = row
    tp = fp = fn = tn = negative_cases = negative_with_fp = failed = 0
    details = []
    per_language = {}
    for p in sorted((root / "control/ground_truth").glob("*-static.jsonl")):
        for expected in records(p):
            key = expected["source_file"]
            r = observed.pop(key, None)
            wanted = set(expected["expected_families"])
            actual = (
                set().union(*(families(v) for v in r.get("algorithms", []))) if r and r.get("algorithms") else set()
            )
            ok = r is not None and r.get("status") == "COMPLETE"
            failed += not ok
            a, b, c = len(wanted & actual), len(actual - wanted), len(wanted - actual)
            tp += a
            fp += b
            fn += c
            if not wanted and ok:
                negative_cases += 1
                tn += not actual
                negative_with_fp += bool(actual)
            lang = expected["language"]
            counts = per_language.setdefault(lang, Counter())
            counts.update(tp=a, fp=b, fn=c, files=1, failed=int(not ok))
            if b or c or not ok:
                details.append(
                    {
                        "source_file": key,
                        "expected": sorted(wanted),
                        "reported": sorted(actual),
                        "status": r.get("status") if r else "MISSING",
                        "false_positive": b,
                        "false_negative": c,
                    }
                )
    fp += sum(
        len({canonical_family(v) for v in row.get("algorithms", []) if canonical_family(v)})
        for row in observed.values()
    )
    total = sum(v["files"] for v in per_language.values())

    def ratio(a, b):
        return a / b if b else None

    return {
        "scope": "ACTUAL_CRYPTOSCAN_STATIC_FAMILY_PER_FILE",
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn_negative_files": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate_negative_files": ratio(negative_with_fp, negative_cases),
        "false_negative_rate": ratio(fn, tp + fn),
        "failed_or_missing_files": failed,
        "files": total,
        "failure_rate": ratio(failed, total),
        "per_language": dict(per_language),
        "misses": details,
        "unmatched_results": list(observed),
        "no_accuracy_floor_predeclared": True,
        "key_size_correctness": None,
        "system_attribution_correctness": None,
        "owner_mapping_correctness": None,
        "dependency_correlation_correctness": None,
        "network_attribution_correctness": None,
        "runtime_attribution_correctness": None,
        "cbom_correctness": None,
        "drift_detection_correctness": None,
        "unknown_metrics_reason": "NOT_EXERCISED_BY_STATIC_FAMILY_BENCHMARK_NOT_ZERO_OR_SAFE",
        "synthetic": True,
    }


def compare_facts(root, observations):
    """External normalized product observations. No sample output manufactured from truth."""
    root, meta = open_estate(root)
    expected = {r["case_id"]: r for p in (root / "control/ground_truth").glob("*-scenarios.jsonl") for r in records(p)}
    fields = {
        "algorithm": "expected_algorithm",
        "key_size": "expected_key_size",
        "owner": "owner",
        "system_id": "system_id",
        "evidence_type": "expected_evidence_type",
        "conflict": "expected_conflict",
        "runtime_used": "expected_runtime_usage",
        "pqc_status": "expected_pqc",
    }
    metrics = {f: {"correct": 0, "incorrect": 0, "unknown": 0, "missing": 0} for f in fields}
    seen = set()
    extra = []
    for r in records(Path(observations)):
        if r["case_id"] in seen:
            raise ValueError("duplicate observation case")
        seen.add(r["case_id"])
        t = expected.get(r["case_id"])
        if not t:
            extra.append(r["case_id"])
            continue
        if r.get("bank_id") != t["bank_id"] or r.get("subject") != t["subject"] or r.get("layer") != t["layer"]:
            raise ValueError("cross-bank/system/layer attribution mismatch")
        for f, e in fields.items():
            bucket = (
                "missing"
                if f not in r
                else "unknown"
                if r[f] is None or t[e] is None
                else "correct"
                if r[f] == t[e]
                else "incorrect"
            )
            metrics[f][bucket] += 1
        if r.get("status") in ("FAILED", "PARTIAL", "UNKNOWN") and r.get("crypto_absent") is True:
            raise ValueError("failure/unknown promoted to absence")
        if t["expected_status"] == "UNKNOWN" and r.get("safe") is True:
            raise ValueError("UNKNOWN promoted to SAFE")
    for case in expected.keys() - seen:
        for m in metrics.values():
            m["missing"] += 1
    return {
        "scope": "EXTERNALLY_SUPPLIED_NORMALIZED_PRODUCT_RESULTS",
        "metrics": metrics,
        "expected_cases": len(expected),
        "observed_cases": len(seen),
        "unmatched": extra,
        "missing_cases": len(expected.keys() - seen),
        "synthetic": True,
    }
