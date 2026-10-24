"""ORM predicates matching shared_models.import_provenance (NULL-safe)."""
from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement

from db.models.crypto_asset import CryptoAsset
from db.models.assurance import AssuranceRevision
from db.models.evidence_record import EvidenceRecord
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.scan import Scan
from db.models.system import System
from db.models.system_asset import SystemAsset
from shared_models.import_provenance import ARCHIVED_DECLARATION, IMPORT_SOURCE_BASIS, RETAINED_MIXED_EVIDENCE


class _RetainedCount(FunctionElement):
    type = String()
    inherit_cache = True


@compiles(_RetainedCount, "sqlite")
def _retained_count_sqlite(element, compiler, **kw):
    payload, identifier = [compiler.process(c, **kw) for c in element.clauses]
    return f"json_extract({payload}, '$.retained_assets.' || json_quote({identifier}))"


@compiles(_RetainedCount, "postgresql")
def _retained_count_postgres(element, compiler, **kw):
    payload, identifier = [compiler.process(c, **kw) for c in element.clauses]
    return f"(({payload} -> 'retained_assets') ->> {identifier})"


def import_clause():
    return or_(
        func.coalesce(CryptoAsset.extra["scan_id"].as_string(), "").like("cbom-ingest:%"),
        func.coalesce(cast(CryptoAsset.scanner_ids, String), "").like('%"cbom-ingest"%'),
        func.coalesce(cast(CryptoAsset.extra["cbom_import"], String), "").not_in(("", "null")),
    )


def legacy_import_clause():
    modern = and_(
        func.coalesce(cast(CryptoAsset.extra["cbom_import"]["system_id"], String), "").like('"%"'),
        func.coalesce(cast(CryptoAsset.extra["cbom_import"]["document_sha256"], String), "").like('"%"'),
        func.coalesce(CryptoAsset.extra["cbom_import"]["system_id"].as_string(), "") != "",
        func.coalesce(func.length(CryptoAsset.extra["cbom_import"]["document_sha256"].as_string()), 0) == 64,
        func.coalesce(CryptoAsset.extra["cbom_import"]["source_basis"].as_string(), "") == IMPORT_SOURCE_BASIS,
    )
    return and_(import_clause(), ~modern)


def retained_mixed_clause():
    count = select(func.count()).select_from(CryptoAssetEvidence).where(
        CryptoAssetEvidence.asset_id == CryptoAsset.id).correlate(CryptoAsset).scalar_subquery()
    reviewed_at = select(AssuranceRevision.created_at).where(
        AssuranceRevision.id == CryptoAsset.extra["legacy_cbom_disposition"]["review_id"].as_string(),
        AssuranceRevision.tenant_id.is_not_distinct_from(CryptoAsset.tenant_id),
        AssuranceRevision.kind == "legacy_mixed_review",
        _RetainedCount(AssuranceRevision.payload, CryptoAsset.id) == cast(count, String),
        AssuranceRevision.payload["state"].as_string() == "DECLARATIONS_RECONCILED_EVIDENCE_RETAINED",
    ).correlate(CryptoAsset).scalar_subquery()
    changed = select(CryptoAssetEvidence.id).join(EvidenceRecord, EvidenceRecord.id == CryptoAssetEvidence.evidence_id).where(
        CryptoAssetEvidence.asset_id == CryptoAsset.id,
        or_(CryptoAssetEvidence.updated_at > reviewed_at, EvidenceRecord.updated_at > reviewed_at)
    ).correlate(CryptoAsset).exists()
    return and_(legacy_import_clause(), reviewed_at.is_not(None), ~changed,
        func.coalesce(CryptoAsset.extra["legacy_cbom_disposition"]["state"].as_string(), "") == RETAINED_MIXED_EVIDENCE,
        cast(CryptoAsset.extra["legacy_cbom_disposition"]["evidence_link_count"].as_string(), String) == cast(count, String))


def archived_legacy_clause():
    linked_evidence = select(CryptoAssetEvidence.id).where(
        CryptoAssetEvidence.asset_id == CryptoAsset.id).correlate(CryptoAsset).exists()
    assigned = select(SystemAsset.id).where(SystemAsset.asset_id == CryptoAsset.id).correlate(CryptoAsset).exists()
    clean = and_(~linked_evidence,
        func.coalesce(CryptoAsset.extra["legacy_cbom_disposition"]["state"].as_string(), "") == ARCHIVED_DECLARATION)
    return and_(legacy_import_clause(), ~assigned, or_(clean, retained_mixed_clause()))


def _legacy_coverage_involved():
    legacy_links = select(SystemAsset.id).join(CryptoAsset, CryptoAsset.id == SystemAsset.asset_id).where(
        SystemAsset.system_id == System.id, legacy_import_clause()).correlate(System).exists()
    remembered = func.coalesce(cast(System.extra["legacy_cbom_observation_unproven"], String), "").in_(("true", "1"))
    old_stamp = and_(System.extra["cbom"]["source"].as_string() == "ingest",
                     or_(System.coverage_status.in_(("CURRENT", "STALE")), System.last_scanned_at.is_not(None)))
    return or_(legacy_links, remembered, func.coalesce(old_stamp, False))


def _completed_scan_time():
    # Take the time from the scanner run, never from an import's later stamp.
    return select(func.coalesce(Scan.scan_end, Scan.scan_start)).where(
        Scan.id == System.last_scan_id,
        Scan.tenant_id.is_not_distinct_from(System.tenant_id), Scan.status == "COMPLETED",
    ).correlate(System).scalar_subquery()


def coverage_scanned_at_clause():
    return case((_legacy_coverage_involved(), _completed_scan_time()), else_=System.last_scanned_at)


def legacy_coverage_review_clause():
    return and_(_legacy_coverage_involved(), _completed_scan_time().is_(None),
                func.coalesce(System.coverage_status, "") != "FAILED")
