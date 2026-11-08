"""Binary Intelligence tables (docs/binary-intelligence/01_PRODUCT_SPEC.md §11).

Revision ID: 0140
Revises: 0139
Create Date: 2026-10-16

binary_artifacts          — artifact identity, digest, source (immutable:
                            a different digest is a new version)
binary_scan_runs          — scan configuration, scanner + signature
                            versions, status, structural report
binary_crypto_findings    — normalized findings: evidence class and
                            usage status carry the claim
binary_evidence           — evidence references and provenance,
                            preserved separately from findings
binary_analysis_coverage  — coverage and analysis limitations, separate
                            from finding confidence (§7)
"""

import sqlalchemy as sa
from alembic import op

revision = "0140"
down_revision = "0139"
branch_labels = None
depends_on = None

_COMMON = (
    sa.Column("tenant_id", sa.String(120), nullable=True),
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def _table(name, *columns):
    op.create_table(name, *columns, *_COMMON)


def upgrade() -> None:
    _table(
        "binary_artifacts",
        sa.Column("artifact_id", sa.String(80), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("file_size", sa.Integer, nullable=False),
        sa.Column("detected_format", sa.String(40), nullable=False),
        sa.Column("format_reason", sa.Text, nullable=False),
        sa.Column("original_filename", sa.String(200), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_location", sa.String(400), nullable=True),
        sa.Column("uploaded_by", sa.String(120), nullable=False),
    )
    op.create_index("ix_binary_artifacts_sha256",
                    "binary_artifacts", ["sha256"])
    op.create_index("ix_binary_artifacts_tenant_artifact",
                    "binary_artifacts", ["tenant_id", "artifact_id"],
                    unique=True)
    op.create_index("ix_binary_artifacts_tenant_sha",
                    "binary_artifacts", ["tenant_id", "sha256"],
                    unique=True)

    _table(
        "binary_scan_runs",
        sa.Column("scan_id", sa.String(80), nullable=False),
        sa.Column("artifact_id", sa.String(80), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("scan_profile", sa.String(20), nullable=False),
        sa.Column("scanner_version", sa.String(80), nullable=False),
        sa.Column("signature_database_version", sa.String(120),
                  nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("structural_report", sa.JSON, nullable=True),
        sa.Column("pqc_assessment", sa.JSON, nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_binary_scan_runs_tenant_scan",
                    "binary_scan_runs", ["tenant_id", "scan_id"],
                    unique=True)
    op.create_index("ix_binary_scan_runs_tenant_artifact",
                    "binary_scan_runs", ["tenant_id", "artifact_id"])
    op.create_index("ix_binary_scan_runs_artifact_id",
                    "binary_scan_runs", ["artifact_id"])

    _table(
        "binary_crypto_findings",
        sa.Column("run_id", sa.String(80), nullable=False),
        sa.Column("finding_id", sa.String(80), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("finding_type", sa.String(60), nullable=False),
        sa.Column("algorithm", sa.String(60), nullable=False),
        sa.Column("variant", sa.String(80), nullable=False),
        sa.Column("operation", sa.String(60), nullable=False),
        sa.Column("mode_or_padding", sa.String(40), nullable=False),
        sa.Column("key_size_bits", sa.Integer, nullable=True),
        sa.Column("library", sa.String(80), nullable=False),
        sa.Column("detection_method", sa.String(80), nullable=False),
        sa.Column("evidence_class", sa.String(40), nullable=False),
        sa.Column("usage_status", sa.String(40), nullable=False),
        sa.Column("runtime_confirmed", sa.Boolean, nullable=False),
        sa.Column("quantum_vulnerable", sa.Boolean, nullable=False),
        sa.Column("pqc_family", sa.Boolean, nullable=False),
        sa.Column("limitations", sa.JSON, nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_binary_crypto_findings_run",
                    "binary_crypto_findings", ["run_id"])
    op.create_index("ix_binary_crypto_findings_tenant_run",
                    "binary_crypto_findings", ["tenant_id", "run_id"])
    op.create_index("ix_binary_crypto_findings_finding_id",
                    "binary_crypto_findings", ["finding_id"])

    _table(
        "binary_evidence",
        sa.Column("finding_id", sa.String(80), nullable=False),
        sa.Column("evidence_type", sa.String(40), nullable=False),
        sa.Column("location", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("excerpt", sa.Text, nullable=False),
    )
    op.create_index("ix_binary_evidence_finding",
                    "binary_evidence", ["finding_id"])
    op.create_index("ix_binary_evidence_tenant_finding",
                    "binary_evidence", ["tenant_id", "finding_id"])

    _table(
        "binary_analysis_coverage",
        sa.Column("run_id", sa.String(80), nullable=False),
        sa.Column("total_bytes", sa.Integer, nullable=False),
        sa.Column("bytes_inspected", sa.Integer, nullable=False),
        sa.Column("sections_total", sa.Integer, nullable=False),
        sa.Column("sections_inspected", sa.Integer, nullable=False),
        sa.Column("executable_sections", sa.Integer, nullable=False),
        sa.Column("symbols_found", sa.Integer, nullable=False),
        sa.Column("symbols_stripped", sa.Boolean, nullable=False),
        sa.Column("unresolved_dependencies", sa.JSON, nullable=True),
        sa.Column("unsupported_regions", sa.JSON, nullable=True),
        sa.Column("extraction_failures", sa.JSON, nullable=True),
        sa.Column("deep_analysis_completed", sa.Boolean, nullable=False),
        sa.Column("packed_or_encrypted_suspected", sa.Boolean,
                  nullable=False),
        sa.Column("analysis_timeouts", sa.Integer, nullable=False),
    )
    op.create_index("ix_binary_analysis_coverage_run",
                    "binary_analysis_coverage", ["run_id"])
    op.create_index("ix_binary_analysis_coverage_tenant_run",
                    "binary_analysis_coverage", ["tenant_id", "run_id"],
                    unique=True)


def downgrade() -> None:
    for name in ("binary_analysis_coverage", "binary_evidence",
                 "binary_crypto_findings", "binary_scan_runs",
                 "binary_artifacts"):
        op.drop_table(name)
