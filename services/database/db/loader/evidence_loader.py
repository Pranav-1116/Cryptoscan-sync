"""Load evidence records into the database with integrity checks."""

from __future__ import annotations

from db.tenancy import filtered_get

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from db.loader.bulk_inserter import BulkInserter
from db.loader.post_load_verifier import PostLoadResult, PostLoadVerifier
from db.loader.pre_load_verifier import PreLoadVerification, verify_records_detailed
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.verification_log import VerificationLog
from db.repositories.verification_repository import VerificationRepository
from shared_models.safe_finding import safe_finding

logger = logging.getLogger(__name__)

#: Nothing anyone deploys has a key this large. The biggest key material in
#: real use is a few tens of thousands of bits (RSA-16384 at the paranoid end,
#: Classic McEliece public keys measured in the low millions of *bytes* but
#: never expressed as a key_size here). A megabit is far past any of that.
MAX_PLAUSIBLE_KEY_BITS = 1 << 20

#: PostgreSQL `integer` bound. key_size is the one column whose value is
#: parsed out of arbitrary source text, so it is the one that can exceed it.
_INT32_MAX = 2_147_483_647


def _strip_nuls(value: Any) -> Any:
    """Remove U+0000 from anything headed for a text or jsonb column.

    PostgreSQL cannot store a NUL byte in text or jsonb -- psycopg raises
    `UntranslatableCharacter: unsupported Unicode escape sequence`. Scanning
    pyca/cryptography hit this: a crypto library is full of binary test
    vectors, and a code snippet lifted from one carries the NUL straight into
    finding_data. As with an oversized key_size, one byte in one file aborted
    the load for all 20,000 files.

    SQLite accepts NULs, so this only ever surfaced on the database
    production actually mandates.

    Recurses because finding_data is nested JSON; the snippet is usually
    several levels down.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nuls(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nuls(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_strip_nuls(v) for v in value)
    return value


def _plausible_key_size(value: Any) -> int | None:
    """A key size we are willing to store, or None.

    Scanning pyca/cryptography killed an entire 20,000-file scan with
    `psycopg2.errors.NumericValueOutOfRange: integer out of range`. key_size
    is captured by regex from source text -- a crypto library's test vectors
    are full of enormous numeric literals (moduli, DH primes) -- and it went
    into an int4 column with nothing in between. One misparse in one file
    aborted the whole load.

    A value beyond MAX_PLAUSIBLE_KEY_BITS is not a key size, it is a bad
    parse. Recording it as None keeps the other findings in that scan, which
    matters far more than preserving a number that was already wrong. The
    drop is logged so a systematic misparse is still visible rather than
    silently swallowed.
    """
    if value is None:
        return None
    try:
        size = int(value)
    except (TypeError, ValueError):
        logger.debug("key_size_not_numeric", extra={"value": repr(value)[:80]})
        return None
    if size < 0 or size > MAX_PLAUSIBLE_KEY_BITS or size > _INT32_MAX:
        logger.warning("key_size_implausible_dropped", extra={"key_size": size})
        return None
    return size


@dataclass
class LoadResult:
    """Outcome of an evidence load attempt."""

    success: bool
    records_loaded: int = 0
    error: str | None = None
    scan_id: str | None = None
    pre_verification: PreLoadVerification | None = None
    post_verification: PostLoadResult | None = None


class EvidenceLoader:
    def __init__(self, session: Session):
        self.session = session
        self.bulk_inserter = BulkInserter(session)

    # ------------------------------------------------------------------ #
    # New integrity-checked pipeline
    # ------------------------------------------------------------------ #
    def load_from_data(
        self,
        *,
        scan_id: str,
        scan_data: dict[str, Any],
        evidence_records: list[dict[str, Any]],
        scan_session_id: str | None = None,
        operator: str | None = None,
    ) -> LoadResult:
        """Pre-verify → atomically insert → post-verify, with rollback on any failure."""
        pre = verify_records_detailed(evidence_records, scan_session_id=scan_session_id)
        if not pre.passed:
            return LoadResult(
                success=False,
                error=f"Pre-load integrity verification failed: {pre.error}",
                scan_id=str(scan_id),
                pre_verification=pre,
            )

        # Normalize nested `chain` layout onto the flat keys the inserter reads.
        flat_records = [self._flatten_chain(rec) for rec in evidence_records]
        scan_meta = dict(scan_data)
        scan_meta["scan_id"] = str(scan_id)
        if operator:
            scan_meta["operator"] = operator

        try:
            with self.session.begin_nested():
                _, inserted = self.bulk_inserter.insert_scan_with_evidence(scan_meta, flat_records)
        except Exception as exc:  # noqa: BLE001 — roll back and surface
            logger.warning("evidence_load_insert_failed", extra={"scan_id": str(scan_id), "error": str(exc)})
            return LoadResult(
                success=False,
                error=f"Database insertion failed: {exc}",
                scan_id=str(scan_id),
                pre_verification=pre,
            )

        post = PostLoadVerifier(self.session).verify(
            scan_id=str(scan_id),
            expected_count=inserted,
            scan_session_id=scan_session_id,
        )
        if not post.passed:
            self.session.rollback()
            return LoadResult(
                success=False,
                error=f"Post-load verification failed: {post.error}",
                scan_id=str(scan_id),
                pre_verification=pre,
                post_verification=post,
            )

        chain_ok = not post.chain_errors
        content_ok = not pre.content_hash_errors
        VerificationRepository(self.session).log(
            str(scan_id),
            "PASS",
            verified_by=operator or "evidence-loader",
            details={"loaded": inserted, "expected": inserted},
            chain_valid=chain_ok,
            content_hashes_valid=content_ok,
        )
        self.session.commit()
        return LoadResult(
            success=True,
            records_loaded=inserted,
            scan_id=str(scan_id),
            pre_verification=pre,
            post_verification=post,
        )

    @staticmethod
    def _flatten_chain(rec: dict[str, Any]) -> dict[str, Any]:
        """Return a record with the nested `chain` object projected to flat keys."""
        out = dict(rec)
        chain = out.get("chain")
        if isinstance(chain, dict):
            out.setdefault("chain_position", chain.get("position"))
            out.setdefault("chain_hash", chain.get("chain_hash"))
            out.setdefault("previous_hash", chain.get("previous_hash"))
        return out

    # ------------------------------------------------------------------ #
    # Legacy loader (kept for the static-scanner ingestion path)
    # ------------------------------------------------------------------ #

    def load(
        self,
        *,
        scan_meta: dict[str, Any],
        evidence_records: list[dict[str, Any]],
        manifest: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> Scan:
        now = datetime.now(timezone.utc)
        scan = None
        if scan_id:
            scan = filtered_get(self.session, Scan, scan_id)
        if scan is None:
            scan = Scan(
                id=scan_id,
                scan_start=self._parse_dt(scan_meta.get("scan_start")) or now,
                scanner_id=scan_meta.get("scanner_id", "static-java-scanner-v0.1"),
                scanner_version=scan_meta.get("scanner_version", "0.1.0"),
                target_type=scan_meta.get("target_type", "LOCAL_DIRECTORY"),
                target_location=scan_meta.get("target_location")
                or scan_meta.get("target_url")
                or "unknown",
                target_commit=scan_meta.get("target_commit"),
                target_branch=scan_meta.get("target_branch"),
                operator=scan_meta.get("operator", "system"),
                status="RUNNING",
            )
            self.session.add(scan)
            self.session.flush()

        rows: list[EvidenceRecord] = []
        for rec in evidence_records:
            # Sanitise once, at the top: every text and jsonb column below is
            # derived from this structure, so stripping here covers the
            # snippet, the file path and the nested finding_data together.
            finding = rec.get("finding") or rec.get("finding_data") or {}
            if _strip_nuls(finding) != finding or safe_finding(finding) != finding:
                raise ValueError("finding payload changed after hashing; sanitize before evidence construction")
            crypto = finding.get("crypto") or {}
            source = finding.get("source") or {}
            metadata = finding.get("metadata") or {}
            rows.append(
                EvidenceRecord(
                    id=rec.get("evidence_id"),
                    scan_id=scan.id,
                    content_hash=rec["content_hash"],
                    chain_hash=rec.get("chain_hash") or rec["content_hash"],
                    chain_position=int(rec.get("chain_position") or 0),
                    previous_hash=rec.get("previous_hash"),
                    algorithm=crypto.get("algorithm") or rec.get("algorithm") or "UNKNOWN",
                    key_size=_plausible_key_size(crypto.get("key_size") or rec.get("key_size")),
                    mode=crypto.get("mode") or rec.get("mode"),
                    padding=crypto.get("padding") or rec.get("padding"),
                    purpose=crypto.get("purpose") or rec.get("purpose"),
                    confidence=(metadata.get("confidence") or rec.get("confidence") or "LOW"),
                    is_hardcoded_key=bool(
                        metadata.get("is_hardcoded_key") or rec.get("is_hardcoded_key")
                    ),
                    file_path=source.get("file_path") or rec.get("file_path") or "unknown",
                    line_number=int(source.get("line_number") or rec.get("line_number") or 0),
                    class_name=source.get("class_name") or rec.get("class_name"),
                    method_name=source.get("method_name") or rec.get("method_name"),
                    finding_data=finding,
                    provenance=rec.get("provenance") or rec.get("integrity"),
                )
            )
        self.session.add_all(rows)

        stats = scan_meta.get("statistics") or {
            "total_findings": len(rows),
            "files_scanned": scan_meta.get("files_scanned", 0),
        }
        scan.mark_completed(
            manifest_hash=(manifest or {}).get("manifest_hash"),
            statistics=stats,
        )
        self.session.add(
            VerificationLog(
                scan_id=scan.id,
                verified_at=now,
                verified_by="db-loader-v0.1",
                result="PASS",
                details={"loaded": len(rows)},
            )
        )
        self.session.flush()
        logger.info("evidence_loaded", extra={"scan_id": scan.id, "count": len(rows)})
        return scan

    @staticmethod
    def _parse_dt(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
