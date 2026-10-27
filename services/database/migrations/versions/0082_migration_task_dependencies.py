"""Migration task dependencies (round 30 execution engine).

advanced/61 §4.2: tasks were created unordered — "No Dependency-Aware
Task Ordering". This adds the `depends_on` JSON column (list of task
ids that must reach DONE/SKIPPED before this task may start) plus an
index on project_id that the execution-plan staging query walks.
"""

from alembic import op
import sqlalchemy as sa

revision = "0082"
down_revision = "0081"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "migration_tasks",
        sa.Column("depends_on", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("migration_tasks", "depends_on")
