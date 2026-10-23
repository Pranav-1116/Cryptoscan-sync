"""PQC migration planning: portfolio plan + Mosca inequality."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.system_repository import SystemRepository
from quantum.plan import build_migration_plan, mosca

router = APIRouter(tags=["quantum"])


@router.get("/quantum/plan")
def quantum_plan(
    migration_years: float | None = Query(None, ge=0, le=20),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """PQC migration plan from live crypto assets: workstreams, waves, Mosca."""
    repo = SystemRepository(db)
    systems, _ = repo.list_systems(page=1, page_size=500)
    system_rows = []
    findings = []
    for system in systems:
        system_rows.append(system.to_dict())
        for asset in repo.assets_for(system.id):
            row = asset.to_dict()
            row["system_id"] = system.id
            findings.append(row)
    return build_migration_plan(findings, systems=system_rows, migration_years=migration_years)


class MoscaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_years: int | None = Field(None, ge=0, le=1000, strict=True)
    migration_years: float | None = Field(None, ge=0, le=1000, strict=True, allow_inf_nan=False)
    threat_year: int | None = Field(None, ge=1, le=9999, strict=True)


@router.post("/quantum/mosca")
def quantum_mosca(body: MoscaRequest, user: str = Depends(get_current_user)):
    """Evaluate Mosca's inequality x + y > z for one data category."""
    kwargs = {"retention_years": body.retention_years, "migration_years": body.migration_years}
    if body.threat_year is not None:
        kwargs["threat_year"] = body.threat_year
    return mosca(**kwargs)
