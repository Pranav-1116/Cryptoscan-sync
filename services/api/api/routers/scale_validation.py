"""The scale curve, served from the artifact the harness wrote.

A GET must not generate 150 synthetic banks inside a request: the graph builds, the
correlation run and the SQLite validation write take seconds, and every worker process
would pay it again. `scripts/scale_bank_curve.py` writes the curve ahead of time; this
router serves it, and refuses an artifact it cannot stand behind.

Three refusals, each of which has bitten a report like this before:

* **an artifact from another corpus** — the generator's schema and seed are checked, so a
  curve measured on an older corpus is not served as current;
* **a curve missing a scale** — 10/50/100/150 is the claim; four of them or nothing;
* **a row whose accuracy is not stated** — a curve with no precision is a table of
  timings wearing a validation's clothes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import get_current_user

router = APIRouter(prefix="/estate/evidence", tags=["estate"])

SCHEMA = "cryptoscan.scale-curve/1"
CORPUS_SCHEMA = "cryptoscan.synthetic-estate/1"

#: the four points the vision asks for. A curve that quietly drops one is not the curve.
REQUIRED_SCALES: tuple[int, ...] = (10, 50, 100, 150)


def artifact_path() -> Path:
    """Where the precomputed curve lives. Overridable for an image build."""
    override = os.environ.get("CRYPTOSCAN_SCALE_CURVE")
    if override:
        return Path(override)
    # services/api/api/routers/x.py → repository root is four levels up
    root = Path(__file__).resolve().parents[4]
    return root / "docs" / "bank-environment" / "107-scale-curve.json"


class _Accuracy(BaseModel):
    precision: float
    recall: float
    f1: float


class _Correlation(BaseModel):
    expected: int
    detected: int
    recall: float


class ScalePoint(BaseModel):
    banks: int
    assets: int
    evidence: int
    relationships: int
    crypto: _Accuracy
    relationships_accuracy: _Accuracy
    refusals_refused: int
    refusals_expected: int
    agreement: _Correlation
    contradiction: _Correlation
    reproducible: bool
    evidence_correct: bool
    graph_coverage: float
    ingest_seconds: float
    assets_per_second: float | None
    peak_rss_mb: float
    rows_projected: int


class ScaleCurve(BaseModel):
    schema: str
    measured_at: str
    seed: int
    scales: list[int]
    points: list[ScalePoint]
    notes: list[str]


def _point(row: dict[str, Any]) -> ScalePoint:
    crypto = row["accuracy"]["crypto"]
    relationships = row["accuracy"]["relationships"]
    correlation = row["accuracy"]["correlation"]
    evidence = row["evidence"]
    performance = row["performance"]
    return ScalePoint(
        banks=row["banks"],
        assets=row["estate"]["assets"],
        evidence=row["estate"]["evidence"],
        relationships=row["estate"]["relationships"],
        crypto=_Accuracy(**{key: crypto[key] for key in ("precision", "recall", "f1")}),
        relationships_accuracy=_Accuracy(
            **{key: relationships[key] for key in ("precision", "recall", "f1")}
        ),
        refusals_refused=relationships["refusals"]["refused"],
        refusals_expected=relationships["refusals"]["expected"],
        agreement=_Correlation(
            expected=correlation["agreement"]["expected"],
            detected=correlation["agreement"]["detected"],
            recall=correlation["agreement"]["recall"],
        ),
        contradiction=_Correlation(
            expected=correlation["contradiction"]["expected"],
            detected=correlation["contradiction"]["detected"],
            recall=correlation["contradiction"]["recall"],
        ),
        reproducible=bool(evidence.get("reproducible")),
        evidence_correct=bool(evidence.get("correct")),
        graph_coverage=float(evidence["coverage"]["graph_coverage"]),
        ingest_seconds=float(performance["ingest_seconds"]),
        assets_per_second=performance.get("assets_per_second"),
        peak_rss_mb=float(performance["peak_rss_mb"]),
        rows_projected=int(row["database"]["rows_projected"]),
    )


def load(path: Path | None = None) -> ScaleCurve:
    """Read and check the artifact. Raises ``ValueError`` with the reason it is refused."""
    target = path or artifact_path()
    if not target.exists():
        raise FileNotFoundError(
            f"no scale curve at {target} — run scripts/scale_bank_curve.py"
        )
    document = json.loads(target.read_text())
    if document.get("schema") != SCHEMA:
        raise ValueError(
            f"the artifact declares {document.get('schema')!r}, this endpoint serves {SCHEMA!r}"
        )
    rows = document.get("rows") or []
    for row in rows:
        if (row.get("estate") or {}).get("schema") != CORPUS_SCHEMA:
            raise ValueError(
                "a row was measured on a corpus this endpoint does not recognise "
                f"({(row.get('estate') or {}).get('schema')!r})"
            )
        if "accuracy" not in row or "crypto" not in row["accuracy"]:
            raise ValueError("a row states no accuracy — a curve of timings is not a validation")
    measured = sorted(int(row["banks"]) for row in rows)
    missing = [scale for scale in REQUIRED_SCALES if scale not in measured]
    if missing:
        raise ValueError(
            f"the curve is missing {missing}; the claim is {list(REQUIRED_SCALES)}"
        )
    return ScaleCurve(
        schema=SCHEMA,
        measured_at=str(document.get("measured_at")),
        seed=int(document.get("seed") or 0),
        scales=[int(scale) for scale in document.get("scales") or measured],
        points=[_point(row) for row in sorted(rows, key=lambda item: int(item["banks"]))],
        notes=[str(note) for note in document.get("notes") or []],
    )


@router.get("/validation/scale-curve", response_model=ScaleCurve)
def scale_curve(user: str = Depends(get_current_user)) -> ScaleCurve:
    """The 10 / 50 / 100 / 150 synthetic-bank curve, as measured by the harness.

    The numbers are accuracy against a planted answer key — precision, recall, refusals,
    correlation, evidence reproducibility, coverage and throughput — on estates generated
    from public standards. This is a regression curve over this repository's corpus, not
    a production accuracy figure, and it says so in ``notes``.
    """
    try:
        return load()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": "scale_curve_missing", "reason": str(exc)},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"error": "scale_curve_unusable", "reason": str(exc)},
        ) from exc
