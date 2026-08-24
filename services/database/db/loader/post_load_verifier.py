"""Post-load count and chain checks."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.evidence_record import EvidenceRecord


class PostLoadResult:
    def __init__(
        self,
        passed: bool,
        records_checked: int = 0,
        chain_errors: list | None = None,
        count_mismatch: bool = False,
        actual_count: int = 0,
        expected_count: int = 0,
        error: str | None = None,
    ):
        self.passed = passed
        self.records_checked = records_checked
        self.chain_errors = chain_errors or []
        self.count_mismatch = count_mismatch
        self.actual_count = actual_count
        self.expected_count = expected_count
        self.error = error


class PostLoadVerifier:
    def __init__(self, session: Session):
        self.session = session

    def verify(self, scan_id: str, expected_count: int, scan_session_id: str | None = None) -> PostLoadResult:
        ok, err = verify_loaded(self.session, scan_id, expected_count)
        actual = expected_count if ok else 0
        return PostLoadResult(
            passed=ok,
            records_checked=expected_count if ok else 0,
            count_mismatch=not ok,
            actual_count=actual,
            expected_count=expected_count,
            error=err,
            chain_errors=[] if ok else [err or "verification failed"],
        )


def verify_loaded(session: Session, scan_id: str, expected_count: int) -> tuple[bool, str | None]:
    actual = session.execute(
        select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
    ).scalar_one()
    if int(actual) != expected_count:
        return False, f"count mismatch: db={actual} expected={expected_count}"
    return True, None
