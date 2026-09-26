"""class:`tenants` / `tenant_memberships` / `tenant_usage_events` /
`tenant_provision_events` / `tenant_invites` + `tenant_id` scoping columns.

Revision ID: 0057
Revises: 0056
Create Date: 2026-09-19

Adds the multi-tenant SaaS core (see db/models/tenant.py): tenant
organizations, user memberships, append-only usage metering, tenant
lifecycle audit events, and invite tokens (SHA-256 hash only — raw tokens
are shown once and never stored).

Also adds the tenant-scoping columns that already exist on the ORM models:

* ``api_keys.tenant_id``     — machine keys minted inside a tenant are
                                hard-bound to it (api.dependencies).
* ``monitor_targets.tenant_id`` — 24/7 monitor targets owned per tenant.

Mirrors the ORM models exactly (see schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── tenants ─────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("plan", sa.String(20), nullable=False, server_default="FREE"),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspend_reason", sa.String(500), nullable=True),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    op.create_index("ix_tenants_plan", "tenants", ["plan"])
    op.create_index("ix_tenants_status", "tenants", ["status"])

    # ── tenant_memberships ──────────────────────────────────────────────
    op.create_table(
        "tenant_memberships",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("tenant_role", sa.String(20), nullable=False, server_default="member"),
        sa.UniqueConstraint("tenant_id", "username", name="uq_tenant_member"),
    )
    op.create_index("ix_tenant_memberships_tenant_id", "tenant_memberships", ["tenant_id"])
    op.create_index("ix_memberships_username", "tenant_memberships", ["username"])

    # ── tenant_usage_events (append-only metering) ─────────────────────
    op.create_table(
        "tenant_usage_events",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(60), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("detail", sa.String(300), nullable=True),
    )
    op.create_index("ix_tenant_usage_events_tenant_id", "tenant_usage_events", ["tenant_id"])
    op.create_index("ix_usage_tenant_kind_time", "tenant_usage_events", ["tenant_id", "kind", "created_at"])

    # ── tenant_provision_events (lifecycle audit) ──────────────────────
    op.create_table(
        "tenant_provision_events",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("actor", sa.String(100), nullable=False),
        sa.Column("detail", sa.String(500), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenant_provision_events_tenant_id", "tenant_provision_events", ["tenant_id"])
    op.create_index("ix_tenant_provision_events_occurred_at", "tenant_provision_events", ["occurred_at"])

    # ── tenant_invites (raw token shown once; hash stored) ─────────────
    op.create_table(
        "tenant_invites",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("tenant_role", sa.String(20), nullable=False, server_default="member"),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("invited_by", sa.String(100), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_tenant_invites_tenant_id", "tenant_invites", ["tenant_id"])
    op.create_index("ix_tenant_invites_token_hash", "tenant_invites", ["token_hash"], unique=True)
    op.create_index("ix_invites_tenant_pending", "tenant_invites", ["tenant_id", "accepted_at"])

    # ── tenant scoping columns on existing tables ──────────────────────
    op.add_column("api_keys", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])
    op.add_column("monitor_targets", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_monitor_targets_tenant_id", "monitor_targets", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_monitor_targets_tenant_id", table_name="monitor_targets")
    op.drop_column("monitor_targets", "tenant_id")
    op.drop_index("ix_api_keys_tenant_id", table_name="api_keys")
    op.drop_column("api_keys", "tenant_id")
    op.drop_index("ix_invites_tenant_pending", table_name="tenant_invites")
    op.drop_index("ix_tenant_invites_token_hash", table_name="tenant_invites")
    op.drop_index("ix_tenant_invites_tenant_id", table_name="tenant_invites")
    op.drop_table("tenant_invites")
    op.drop_index("ix_tenant_provision_events_occurred_at", table_name="tenant_provision_events")
    op.drop_index("ix_tenant_provision_events_tenant_id", table_name="tenant_provision_events")
    op.drop_table("tenant_provision_events")
    op.drop_index("ix_usage_tenant_kind_time", table_name="tenant_usage_events")
    op.drop_index("ix_tenant_usage_events_tenant_id", table_name="tenant_usage_events")
    op.drop_table("tenant_usage_events")
    op.drop_index("ix_memberships_username", table_name="tenant_memberships")
    op.drop_index("ix_tenant_memberships_tenant_id", table_name="tenant_memberships")
    op.drop_table("tenant_memberships")
    op.drop_index("ix_tenants_status", table_name="tenants")
    op.drop_index("ix_tenants_plan", table_name="tenants")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")
