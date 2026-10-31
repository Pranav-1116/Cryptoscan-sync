#!/usr/bin/env python3
"""Precompute the labeled-calibration report the API serves.

`GET /api/v1/findings/detectors/labeled-calibration` used to run the whole
labeled accuracy corpus inside the request: 842 files scanned with the production
`scan_file`, plus the scanner registry import, on a worker thread that could have
served someone else. Measured at 6.9–10 s against a live server on a cold
process, and paid once per worker process because the result was only cached in
memory.

This script writes the same report to a file the API reads instead:

    python scripts/build_labeled_calibration.py \
        --out data/accuracy/labeled-calibration.json

The artifact carries a fingerprint of the inputs it was built from (the corpus
module and the benchmark script). The API compares that fingerprint with the tree
it is running and recomputes if they differ, so a stale artifact is never served
as current — the failure mode would be a calibration report that silently
describes a corpus nobody ships any more.

Run it in the image build (see .docker/api/Dockerfile) so a bank's first request
does not pay for it. Running it is not required for correctness: without the file
the endpoint computes the report exactly as before and writes the artifact for the
next process.

No network, no database.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCHEMA = "cryptoscan.labeled-calibration/1"

#: The files that decide what the report says. A change to either one makes every
#: stored artifact stale.
INPUTS = (
    "services/scanner/tests/accuracy/corpus.py",
    "scripts/accuracy_benchmark.py",
)


def fingerprint(root: Path = ROOT) -> str:
    """SHA-256 over the corpus definition and the benchmark that scores it."""
    digest = hashlib.sha256()
    for relative in INPUTS:
        path = root / relative
        digest.update(relative.encode())
        digest.update(path.read_bytes() if path.exists() else b"<missing>")
    return digest.hexdigest()


def calibration_payload(report: dict, *, root: Path = ROOT) -> dict:
    """The artifact: only what the endpoint needs, plus its provenance."""
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_fingerprint": fingerprint(root),
        "corpus_overall": report.get("overall"),
        "cases": [
            {
                "language": case.get("language"),
                "file": case.get("file"),
                "category": case.get("category"),
                "expected": case.get("expected") or [],
                "reports": case.get("reports") or [],
            }
            for case in (report.get("cases") or [])
        ],
    }


def build(out: Path, *, root: Path = ROOT) -> dict:
    sys.path.insert(0, str(root / "scripts"))
    import accuracy_benchmark

    payload = calibration_payload(accuracy_benchmark.run(), root=root)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(out)  # atomic: a reader never sees a half-written artifact
    return payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "data" / "accuracy" / "labeled-calibration.json"))
    args = ap.parse_args(argv)
    payload = build(Path(args.out))
    cases = payload["cases"]
    print(f"wrote {args.out}: {len(cases)} cases, overall {payload['corpus_overall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
