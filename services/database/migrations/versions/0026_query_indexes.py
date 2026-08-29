"""Hot-path composite indexes (Week 59-60): estate-scale query performance.

Mirrors the __table_args__ indexes on the models so existing deployments get
them without a rebuild. Indexes match measured hot queries:

- evidence_records (scan_id, chain_position): per-scan listing + chain verify
- evidence_records (scan_id, compliance_status): failing-findings per scan
  (remediation suggestions, migration auto-tasks, gate evidence)
- crypto_assets (algorithm, file_path): asset listing filter+order
- systems (current_agility_score): agility ranking
- migration_tasks (project_id, status): progress/status derivation

Revision ID: 0026
Revises: 0025
Create Date: 2026-08-29
"""
from alembic import op

# revision identifiers
revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

INDEXES = [
    ("ix_evidence_scan_chain", "evidence_records", ["scan_id", "chain_position"]),
    ("ix_evidence_scan_status", "evidence_records", ["scan_id", "compliance_status"]),
    ("ix_assets_algorithm_file", "crypto_assets", ["algorithm", "file_path"]),
    ("ix_systems_agility_score", "systems", ["current_agility_score"]),
    ("ix_migration_tasks_project_status", "migration_tasks", ["project_id", "status"]),
]


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _columns in reversed(INDEXES):
        op.drop_index(name, table_name=table)
