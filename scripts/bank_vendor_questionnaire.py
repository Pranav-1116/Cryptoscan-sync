#!/usr/bin/env python3
"""Audit the bank-question traceability register, not certify vendor capability.

Source-file existence/hashes are navigation/integrity evidence only. This tool
never treats a file, self-report, test count or commercial assertion as bank
acceptance. --strict fails while any acceptance requirement remains open.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs/operations/bank-vendor-questionnaire.json"
COUNTS = {"S": 5, "M": 6, "O": 5, "R": 4, "D": 5, "I": 4, "P": 5, "C": 7, "G": 4, "A": 12}
EXPECTED = {f"{group}{n}" for group, count in COUNTS.items() for n in range(1, count + 1)}


def review(catalog: dict, root: Path = ROOT) -> dict:
    if not isinstance(catalog, dict):
        raise ValueError("Questionnaire must be an object")
    if catalog.get("schema") != "cryptoscan.bank-vendor-questionnaire/1":
        raise ValueError("Unsupported questionnaire schema")
    questions = catalog.get("questions")
    if not isinstance(questions, list) or len(questions) != len(EXPECTED):
        raise ValueError("All45 bank questions and12 additional questions are required")
    seen: set[str] = set()
    hashes: dict[str, str] = {}
    blockers: list[dict] = []
    root = root.resolve()
    for q in questions:
        if not isinstance(q, dict):
            raise ValueError("Question must be an object")
        identifier = q.get("id")
        if not isinstance(identifier, str) or identifier not in EXPECTED or identifier in seen:
            raise ValueError("Unknown or duplicate question ID")
        seen.add(identifier)
        for field in ("question", "existing_surface", "boundary", "acceptance_needed"):
            if not isinstance(q.get(field), str) or not q[field].strip():
                raise ValueError(f"{identifier}: missing meaningful {field}")
        if not isinstance(q.get("status"), str) or q["status"] not in {"PARTIAL", "EXTERNAL", "NOT_ESTABLISHED"}:
            raise ValueError("Unsupported approval claim; this register does not establish qualification")
        refs = q.get("source_refs")
        if not isinstance(refs, list) or not refs:
            raise ValueError(f"{identifier}: source navigation references required")
        for ref in refs:
            if not isinstance(ref, str):
                raise ValueError("Source path must be a string")
            path = Path(ref)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError("Unsafe source path")
            candidate = root / path
            # Reject symlinks at every level, even when they resolve inside root.
            if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root):
                raise ValueError("Symlink source reference forbidden")
            if not candidate.resolve().is_relative_to(root) or not candidate.is_file():
                raise ValueError("Missing or non-file source reference")
            if ref not in hashes:
                digest = hashlib.sha256()
                with candidate.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        digest.update(chunk)
                hashes[ref] = digest.hexdigest()
        blockers.append({"id": identifier, "status": q["status"], "needed": q["acceptance_needed"]})
    if seen != EXPECTED:
        raise ValueError("Incomplete question-ID coverage")
    return {"schema": "cryptoscan.bank-vendor-questionnaire-review/1",
        "register_integrity": "PASS", "original_questions": 45, "additional_questions": 12,
        "questions_mapped": len(seen), "status": "BLOCKED_FOR_BANK_ACCEPTANCE",
        "bank_approved": False, "discovery_completeness_proven": False,
        "source_reference_sha256": hashes, "open_acceptance": blockers,
        "limit": "Source references are navigation/integrity only, not test execution, deployment evidence, independent review, certification or an SLA."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--strict", action="store_true", help="Fail while bank acceptance remains open")
    args = parser.parse_args(argv)
    try:
        if args.catalog.stat().st_size > 2_000_000:
            raise ValueError("Questionnaire exceeds2MB")
        report = review(json.loads(args.catalog.read_text(encoding="utf-8")))
        print(json.dumps(report, indent=2, allow_nan=False))
        return 1 if args.strict else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"register_integrity": "FAIL", "bank_approved": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
