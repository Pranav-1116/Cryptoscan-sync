"""Positive authorization, shared budgets, attempts and transactional outbox."""
from alembic import op
import sqlalchemy as sa

revision = "0102"
down_revision = "0101"
branch_labels = None
depends_on = None


def _create(name, *columns, constraints=(), tenant=True):
    base = [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)]
    if tenant:
        base.append(sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_table(name, *base, *columns, *constraints)
    if tenant:
        op.create_index("ix_" + name + "_tenant_id", name, ["tenant_id"])


def upgrade():
    op.add_column("user_sessions", sa.Column("user_id", sa.String(36), nullable=True))
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    _create("execution_control_events", sa.Column("actor_id", sa.String(36), nullable=False),
            sa.Column("action", sa.String(40), nullable=False), sa.Column("entity_id", sa.String(36), nullable=False),
            sa.Column("detail", sa.JSON, nullable=False))
    _create("estate_execution_policies",
            sa.Column("estate_key", sa.String(64), nullable=False, unique=True),
            sa.Column("revision", sa.Integer, nullable=False),
            sa.Column("contract", sa.JSON, nullable=False),
            sa.Column("stopped", sa.Boolean, nullable=False))
    _create("scan_approvals", sa.Column("policy_revision", sa.Integer, nullable=False),
            sa.Column("contract", sa.JSON, nullable=False),
            sa.Column("requests_used", sa.Integer, nullable=False),
            sa.Column("version", sa.Integer, nullable=False),
            sa.Column("approved_by", sa.String(36), nullable=False),
            sa.Column("supersedes_id", sa.String(36)),
            sa.Column("revoked_at", sa.DateTime(timezone=True)))
    _create("execution_budgets", sa.Column("capacity", sa.Integer, nullable=False),
            sa.Column("requests_per_second", sa.Integer, nullable=False),
            sa.Column("active", sa.Integer, nullable=False),
            sa.Column("version", sa.Integer, nullable=False),
            sa.Column("schedule", sa.JSON, nullable=False),
            sa.Column("request_times", sa.JSON, nullable=False), tenant=False)
    _create("execution_attempts", sa.Column("job_id", sa.String(36), nullable=False),
            sa.Column("approval_id", sa.String(36), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("checkpoint", sa.String(80), nullable=False),
            sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("budget_ids", sa.JSON, nullable=False),
            sa.Column("fence", sa.String(64), nullable=False),
            sa.Column("version", sa.Integer, nullable=False),
            constraints=(sa.UniqueConstraint("job_id", name="uq_execution_attempt_job"),))
    op.create_index("ix_execution_attempts_job_id", "execution_attempts", ["job_id"])
    _create("execution_outbox", sa.Column("job_id", sa.String(36), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("version", sa.Integer, nullable=False),
            sa.Column("lease_until", sa.DateTime(timezone=True)),
            sa.Column("published_at", sa.DateTime(timezone=True)),
            constraints=(sa.UniqueConstraint("job_id", name="uq_execution_outbox_job"),))


def downgrade():
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    with op.batch_alter_table("user_sessions") as batch:
        batch.drop_column("user_id")
    for name in ("execution_outbox", "execution_attempts", "execution_budgets", "scan_approvals", "estate_execution_policies", "execution_control_events"):
        op.drop_table(name)
