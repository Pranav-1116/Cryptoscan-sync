"""Keep derived facts tenant-local and enforce NULL-safe identity.

Existing duplicate facts are not silently removed: a failed preflight names
sample identities so an operator can reconcile derived rows against evidence
and rerun the migration. Evidence is never modified by this revision.
"""

from alembic import op
import sqlalchemy as sa

revision = "0087"
down_revision = "0086"
branch_labels = None
depends_on = None


_IDENTITY = (
    "algorithm", "coalesce(tenant_id, '')", "(tenant_id IS NULL)",
    "coalesce(purpose, '')", "coalesce(file_path, '')",
    "coalesce(key_size, 0)", "(key_size IS NULL)", "coalesce(mode, '')",
)


def upgrade() -> None:
    connection = op.get_bind()
    # The old unique constraint does not protect NULL key_size or separate
    # tenant-local identities. Reject ambiguous existing rows before DDL;
    # dropping either row here would conceal a projection/evidence mismatch.
    duplicates = connection.execute(sa.text("""
        SELECT coalesce(tenant_id, '<platform>') AS tenant, algorithm,
               coalesce(purpose, '') AS purpose, coalesce(file_path, '') AS file_path,
               key_size, coalesce(mode, '') AS mode, count(*) AS n
        FROM cryptographic_facts
        GROUP BY tenant_id, algorithm, coalesce(purpose, ''),
                 coalesce(file_path, ''), key_size, coalesce(mode, '')
        HAVING count(*) > 1
        LIMIT 5
    """)).mappings().all()
    if duplicates:
        raise RuntimeError(
            "cryptographic_facts contains duplicate tenant-local identities; "
            "reconcile derived facts from evidence before migration 0087: "
            f"{[dict(row) for row in duplicates]}"
        )

    with op.batch_alter_table("cryptographic_facts") as batch:
        batch.drop_constraint("uq_fact_identity", type_="unique")
        # 0085 made this NOT NULL despite TenantScoped's platform-NULL contract.
        batch.alter_column("tenant_id", existing_type=sa.String(36), nullable=True)
    op.create_index("uq_fact_identity", "cryptographic_facts", [sa.text(expr) for expr in _IDENTITY], unique=True)


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(sa.text(
        "SELECT 1 FROM cryptographic_facts WHERE tenant_id IS NULL LIMIT 1"
    )).first():
        raise RuntimeError("cannot downgrade 0087 while platform facts have NULL tenant_id")
    # 0085's global constraint would reject identical non-NULL identities in
    # different tenants. Refuse before dropping the new protective index.
    if connection.execute(sa.text("""
        SELECT 1 FROM cryptographic_facts
        WHERE purpose IS NOT NULL AND file_path IS NOT NULL
          AND key_size IS NOT NULL AND mode IS NOT NULL
        GROUP BY algorithm, purpose, file_path, key_size, mode
        HAVING count(*) > 1 LIMIT 1
    """)).first():
        raise RuntimeError(
            "cannot downgrade 0087 with facts sharing a global identity across tenants"
        )
    op.drop_index("uq_fact_identity", table_name="cryptographic_facts")
    with op.batch_alter_table("cryptographic_facts") as batch:
        batch.alter_column("tenant_id", existing_type=sa.String(36), nullable=False)
        batch.create_unique_constraint(
            "uq_fact_identity", ["algorithm", "purpose", "file_path", "key_size", "mode"]
        )
