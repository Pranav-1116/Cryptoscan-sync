"""Work the twin opens, and the observation that would close it (spec 94 §23).

Revision 0118. Adds ``estate_remediation_work``.

``REMEDIATE`` was the one phase of the twin's loop reported ``NOT_CONNECTED``: the twin
could show a conflict, a coverage loss and a simulation blocker, and it opened nothing
from any of them. This table is that hand-off.

The columns that matter are the proof ones. ``proof_kind`` says whether closure is
machine-checkable (``OBSERVATION_VALUE``, ``COLLECTOR_STATUS``) or has to be asserted by a
human (``HUMAN``) — and a ``HUMAN`` item is never auto-closed. ``proof_evidence_id`` names
the record that closed a row, so a closure is a citation rather than a status change.

Downgrade drops the table. Nothing else depends on it: no foreign keys point here on
purpose, because a work item must survive the asset row it was opened against (an asset
that disappears is a reason to re-check the item, not to delete the memory of it).
"""
from alembic import op
import sqlalchemy as sa

revision = "0118"
down_revision = "0117"
branch_labels = depends_on = None


def upgrade():
    op.create_table(
        "estate_remediation_work",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(64), nullable=True, index=True),
        sa.Column("claim_key", sa.String(96), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("subject_id", sa.String(120), nullable=True),
        sa.Column("subject_kind", sa.String(40), nullable=True),
        sa.Column("title", sa.String(400), nullable=False),
        sa.Column("claim", sa.Text(), nullable=False),
        sa.Column("not_proven", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="OPEN"),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_by", sa.String(120), nullable=True),
        sa.Column("opened_from", sa.String(96), nullable=True),
        sa.Column("proof_kind", sa.String(30), nullable=False, server_default="HUMAN"),
        sa.Column("proof_fact_type", sa.String(120), nullable=True),
        sa.Column("proof_expected", sa.String(200), nullable=True),
        sa.Column("proof_note", sa.Text(), nullable=True),
        sa.Column("proven_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("proof_observation_id", sa.String(96), nullable=True),
        sa.Column("proof_evidence_id", sa.String(96), nullable=True),
        sa.Column("proof_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("proof_detail", sa.JSON(), nullable=True),
        sa.Column("reconcile_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_estate_remediation_tenant_claim", "estate_remediation_work",
        ["tenant_id", "claim_key"], unique=True,
    )
    op.create_index("ix_estate_remediation_status", "estate_remediation_work", ["status"])
    op.create_index("ix_estate_remediation_subject", "estate_remediation_work", ["subject_id"])


def downgrade():
    op.drop_index("ix_estate_remediation_subject", table_name="estate_remediation_work")
    op.drop_index("ix_estate_remediation_status", table_name="estate_remediation_work")
    op.drop_index("ix_estate_remediation_tenant_claim", table_name="estate_remediation_work")
    op.drop_table("estate_remediation_work")
