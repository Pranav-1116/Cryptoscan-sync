"""Post-load count and chain checks."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.loader.chain import chain_hash as compute_chain_hash
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
        scan_id = str(scan_id)
        rows = list(
            self.session.execute(
                select(EvidenceRecord)
                .where(EvidenceRecord.scan_id == scan_id)
                .order_by(EvidenceRecord.chain_position.asc())
            ).scalars()
        )
        actual = len(rows)
        if actual != int(expected_count):
            return PostLoadResult(
                passed=False,
                records_checked=actual,
                chain_errors=[],
                count_mismatch=True,
                actual_count=actual,
                expected_count=int(expected_count),
                error=f"count mismatch: db={actual} expected={expected_count}",
            )

        chain_errors: list[str] = []
        expected_previous = scan_session_id or ""
        for position, row in enumerate(rows):
            rid = str(row.id)
            if position == 0:
                if row.previous_hash not in (None, ""):
                    chain_errors.append(f"{rid}: genesis record must have no previous_hash")
                anchor = scan_session_id or ""
            else:
                if row.previous_hash != expected_previous:
                    chain_errors.append(f"{rid}: previous_hash does not link to preceding record")
                anchor = expected_previous
            expected_chain = compute_chain_hash(row.content_hash, anchor)
            if expected_chain != row.chain_hash:
                chain_errors.append(f"{rid}: chain_hash mismatch (record tampered or re-linked)")
            expected_previous = row.chain_hash

        passed = not chain_errors
        return PostLoadResult(
            passed=passed,
            records_checked=actual,
            chain_errors=chain_errors,
            count_mismatch=False,
            actual_count=actual,
            expected_count=int(expected_count),
            error=None if passed else "; ".join(chain_errors),
        )


def verify_loaded(session: Session, scan_id: str, expected_count: int) -> tuple[bool, str | None]:
    actual = session.execute(
        select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.scan_id == str(scan_id))
    ).scalar_one()
    if int(actual) != expected_count:
        return False, f"count mismatch: db={actual} expected={expected_count}"
    return True, None
