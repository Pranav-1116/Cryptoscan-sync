"""Index exact-estate receipt keyset inspection; no delivery data changes."""
from alembic import op

revision = "0097"
down_revision = "0096"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_notification_deliveries_inspection", "notification_deliveries", ["scope_key", "created_at", "id"])


def downgrade() -> None:
    # Index-only rollback preserves every receipt, lease and deduplication key.
    op.drop_index("ix_notification_deliveries_inspection", table_name="notification_deliveries")
