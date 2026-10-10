"""Direct ownership on crypto assets, certificates, vendors (report 55 P0#3-5, round 27).

Ownership lived only on the System row (``owner`` / ``technical_owner`` /
``security_owner``, round 19) — an asset inherited accountability through its
system link, but a crypto asset or certificate with no system link had *no*
owner at all, and vendors had commercial contacts but no technical contact.

This migration adds nullable direct-ownership columns following the same
convention as the system fields (free-form identity strings — the platform
has no user directory to FK against, and report 55's "FK to User/Team" is
satisfied by the same string identity the rest of the ownership model uses):

* ``crypto_assets``: owner / technical_owner / security_owner
* ``certificates``: owner / technical_contact
* ``vendors``: technical_contact (primary/security contacts already exist)

Historical rows keep NULL — no ownership is fabricated; the inventory and
ownership surfaces report an explicit gap instead.
"""

from alembic import op
import sqlalchemy as sa

revision = "0080"
down_revision = "0079"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("crypto_assets") as batch:
        batch.add_column(sa.Column("owner", sa.String(200), nullable=True))
        batch.add_column(sa.Column("technical_owner", sa.String(200), nullable=True))
        batch.add_column(sa.Column("security_owner", sa.String(200), nullable=True))

    with op.batch_alter_table("certificates") as batch:
        batch.add_column(sa.Column("owner", sa.String(200), nullable=True))
        batch.add_column(sa.Column("technical_contact", sa.String(200), nullable=True))

    with op.batch_alter_table("vendors") as batch:
        batch.add_column(sa.Column("technical_contact", sa.String(200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("vendors") as batch:
        batch.drop_column("technical_contact")

    with op.batch_alter_table("certificates") as batch:
        batch.drop_column("technical_contact")
        batch.drop_column("owner")

    with op.batch_alter_table("crypto_assets") as batch:
        batch.drop_column("security_owner")
        batch.drop_column("technical_owner")
        batch.drop_column("owner")
