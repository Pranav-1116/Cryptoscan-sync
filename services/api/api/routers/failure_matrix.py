"""The nine-mode failure matrix, served from the artifact the drills wrote.

`scripts/failure_matrix.py` runs all nine drills and writes the report; a GET
serves it. The interesting part is not the serving, it is what the endpoint
refuses, because this is exactly the document that tends to drift into a
hand-written table of green ticks:

* **an artifact from another schema** — a matrix measured by an older harness
  is not served as current;
* **a matrix that is not the nine modes** — a dropped row is how "8/9 proven"
  becomes "all failure modes covered"; the nine are named, so a missing or
  unexpected mode is refused;
* **a row marked PROVEN with no evidence of a run** — no observations and no
  observed behaviour means nothing was executed, and the claim is not served;
* **an UNPROVEN row with no reason** — "unproven" without a why is
  indistinguishable from "not done".

A `BROKEN` row is served, deliberately: hiding a mode that failed is the
failure this endpoint exists to prevent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from api.dependencies import get_current_user

router = APIRouter(prefix="/estate/evidence", tags=["estate"])

SCHEMA = "cryptoscan.failure-matrix/1"

#: the nine modes in the brief. A report missing one is not a report.
REQUIRED_MODES: tuple[str, ...] = (
    "api",
    "database",
    "worker",
    "collector",
    "agent",
    "network",
    "storage",
    "certificate_expiry",
    "queue",
)


def artifact_path() -> Path:
    """Where the generated matrix lives. Overridable for an image build."""
    override = os.environ.get("CRYPTOSCAN_FAILURE_MATRIX")
    if override:
        return Path(override)
    # services/api/api/routers/x.py → repository root is four levels up
    root = Path(__file__).resolve().parents[4]
    return root / "docs" / "bank-environment" / "109-failure-matrix.json"


class FailureRow(BaseModel):
    mode: str
    what_breaks: str
    expected: str
    verdict: Literal["PROVEN", "BROKEN", "UNPROVEN"]
    behavior: str
    observations: dict[str, Any]
    reason: str | None = None
    limit: str | None = None


class FailureMatrix(BaseModel):
    # `schema` is the artifact's own field name; `schema_` avoids shadowing
    # BaseModel and the alias keeps the wire contract unchanged.
    model_config = ConfigDict(populate_by_name=True)

    schema_: str = Field(alias="schema")
    generated_at: str
    proven: int
    broken: int
    unproven: int
    complete: bool
    rows: list[FailureRow]


def _row(document: dict[str, Any]) -> FailureRow:
    return FailureRow(
        mode=str(document["mode"]),
        what_breaks=str(document.get("what_breaks") or ""),
        expected=str(document.get("expected") or ""),
        verdict=document["verdict"],
        behavior=str(document.get("behavior") or ""),
        observations=dict(document.get("observations") or {}),
        reason=document.get("reason"),
        limit=document.get("limit"),
    )


def load(path: Path | None = None) -> FailureMatrix:
    """Read and check the artifact. Raises ``ValueError`` with the reason it is refused."""
    target = path or artifact_path()
    if not target.exists():
        raise FileNotFoundError(
            f"no failure matrix at {target} — run scripts/failure_matrix.py --json …"
        )
    document = json.loads(target.read_text())
    if document.get("schema") != SCHEMA:
        raise ValueError(
            f"the artifact declares {document.get('schema')!r}, this endpoint serves {SCHEMA!r}"
        )

    raw_rows = document.get("rows") or []
    modes = [str(row.get("mode") or "") for row in raw_rows]
    missing = [mode for mode in REQUIRED_MODES if mode not in modes]
    unexpected = [mode for mode in modes if mode not in REQUIRED_MODES]
    duplicated = sorted({mode for mode in modes if modes.count(mode) > 1})
    if missing:
        raise ValueError(f"the matrix is missing {missing}; the nine modes are required")
    if unexpected:
        raise ValueError(f"the matrix contains unknown modes {unexpected}")
    if duplicated:
        raise ValueError(f"the matrix lists {duplicated} more than once")
    if len(modes) != len(REQUIRED_MODES):
        raise ValueError(
            f"the matrix has {len(modes)} rows, expected {len(REQUIRED_MODES)}"
        )

    rows = [_row(row) for row in raw_rows]
    for row in rows:
        if row.verdict == "PROVEN" and (not row.observations or not row.behavior):
            raise ValueError(
                f"mode {row.mode!r} is marked PROVEN with no observations — a claim without an "
                "executed drill is not proof"
            )
        if row.verdict == "UNPROVEN" and not row.reason:
            raise ValueError(f"mode {row.mode!r} is UNPROVEN with no reason given")

    proven = sum(1 for row in rows if row.verdict == "PROVEN")
    if int(document.get("proven", proven)) != proven:
        raise ValueError(
            f"the artifact says {document.get('proven')} proven but {proven} rows are PROVEN"
        )
    return FailureMatrix(
        schema_=SCHEMA,
        generated_at=str(document.get("generated_at")),
        proven=proven,
        broken=sum(1 for row in rows if row.verdict == "BROKEN"),
        unproven=sum(1 for row in rows if row.verdict == "UNPROVEN"),
        complete=proven == len(REQUIRED_MODES),
        rows=rows,
    )


@router.get("/validation/failure-matrix", response_model=FailureMatrix)
def failure_matrix(user: str = Depends(get_current_user)) -> FailureMatrix:
    """The nine failure modes, each row graded by an executed drill.

    `PROVEN` here means the drill ran with the fault injected and every check passed;
    it is not a claim that the deployment is configured, monitored or observed. Each
    row carries its own `limit` saying what that drill did not establish.
    """
    try:
        return load()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": "failure_matrix_missing", "reason": str(exc)},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"error": "failure_matrix_unusable", "reason": str(exc)},
        ) from exc
