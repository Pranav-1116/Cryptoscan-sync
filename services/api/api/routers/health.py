from fastapi import APIRouter

from db.connection.engine import check_db_health

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    return {"status": "ok", "database": check_db_health()}
