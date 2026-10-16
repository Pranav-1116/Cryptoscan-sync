"""HBOM estate snapshots (§4.4, round 71 — the independent HBOM leg).

The HBOM was the TechBOM's hardware projection layer and the live
engine's in-memory document — never an independent, unified generator
over the persisted estate. Round 71 adds
``cbom/hbom.py`` (``generate_hbom``: ONE deterministic document over
every ``hardware_assets`` row, per-asset identity + evidence
references, content-addressed by SHA-256 over its canonical
serialization, anchored to the estate's latest observation instead of
a wall clock) and this table pins those documents:

* ``content_hash`` — SHA-256 over the exact stored payload (the
  ``content_hash`` member itself excluded), so a snapshot is
  content-addressed and a mutated payload is detectable on read
  (integrity self-check: OK / MISMATCH).
* ``environment`` / ``as_of`` — which environment the estate document
  belongs to and its deterministic anchor.
* ``uq_hbom_snapshot_tenant_env_hash`` — identical (tenant,
  environment, content) pins collapse to one row (idempotent
  creation). No scan foreign key: the HBOM is an estate document, not
  the rendering of one scan run.
"""

from alembic import op
import sqlalchemy as sa

revision = "0095"
down_revision = "0094"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hbom_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("environment", sa.String(60), nullable=False, server_default=""),
        sa.Column("content_hash", sa.String(64), nullable=False, index=True),
        sa.Column("format", sa.String(10), nullable=False, server_default="json"),
        sa.Column("generator", sa.String(30), nullable=False, server_default="api"),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("snapshotted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("as_of", sa.String(40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "environment", "content_hash",
                            name="uq_hbom_snapshot_tenant_env_hash"),
    )


def downgrade() -> None:
    op.drop_table("hbom_snapshots")
