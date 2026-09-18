"""Real CDT tables — live virtual replica flight simulator

Revision ID: 0219
Revises: 0218
"""
import sqlalchemy as sa
from alembic import op
revision = "0219"
down_revision = "0218"
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Real CDT entities table
    op.create_table(
        "cdt_entities",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("system_id", sa.String(100), nullable=False),
        sa.Column("properties", sa.JSON(), nullable=True),
        sa.Column("crypto_properties", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, default=0.0),
        sa.Column("compliance_status", sa.JSON(), nullable=True),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("isolation", sa.String(100), nullable=False, default="twin isolated"),
        sa.Column("deterministic", sa.Boolean(), nullable=False, default=True),
    )
    op.create_index("ix_cdt_entities_system_id", "cdt_entities", ["system_id"])
    op.create_index("ix_cdt_entities_entity_type", "cdt_entities", ["entity_type"])
    
    # Real CDT relationships table
    op.create_table(
        "cdt_relationships",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column("properties", sa.JSON(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False, default=1.0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_cdt_relationships_source", "cdt_relationships", ["source_id"])
    op.create_index("ix_cdt_relationships_target", "cdt_relationships", ["target_id"])
    op.create_index("ix_cdt_relationships_type", "cdt_relationships", ["relationship_type"])
    
    # Real CDT snapshots table
    op.create_table(
        "cdt_snapshots",
        sa.Column("snapshot_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("entity_count", sa.Integer(), nullable=False, default=0),
        sa.Column("relationship_count", sa.Integer(), nullable=False, default=0),
        sa.Column("merkle_root", sa.String(64), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=True),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("isolation", sa.String(100), nullable=False, default="twin S3 immutable"),
        sa.Column("deterministic", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    
    # Real CDT simulations table
    op.create_table(
        "cdt_simulations",
        sa.Column("simulation_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("scenario_type", sa.String(50), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.Column("changes", sa.JSON(), nullable=True),
        sa.Column("constraints", sa.JSON(), nullable=True),
        sa.Column("assumptions", sa.JSON(), nullable=True),
        sa.Column("impact", sa.JSON(), nullable=True),
        sa.Column("effort", sa.JSON(), nullable=True),
        sa.Column("cost", sa.JSON(), nullable=True),
        sa.Column("risk", sa.JSON(), nullable=True),
        sa.Column("timeline", sa.JSON(), nullable=True),
        sa.Column("recommendations", sa.JSON(), nullable=True),
        sa.Column("compliance_impact", sa.JSON(), nullable=True),
        sa.Column("report", sa.Text(), nullable=True),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("deterministic", sa.Boolean(), nullable=False, default=True),
        sa.Column("isolation", sa.String(200), nullable=False, default="simulation runs on cloned twin state fully isolated"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_cdt_simulations_scenario", "cdt_simulations", ["scenario_type"])
    
    # Real CDT events table (audit trail)
    op.create_table(
        "cdt_events",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=True),
        sa.Column("simulation_id", sa.String(36), nullable=True),
        sa.Column("snapshot_id", sa.String(36), nullable=True),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
    )

def downgrade() -> None:
    op.drop_table("cdt_events")
    op.drop_table("cdt_simulations")
    op.drop_table("cdt_snapshots")
    op.drop_table("cdt_relationships")
    op.drop_table("cdt_entities")
