"""Crypto asset identity spine (§4.2, round 57).

Adds the canonical durable identity column (``asset_key``) to
``crypto_assets`` — the ONE string derivable identically from an evidence
row, an asset row, a fact row or a BOM component
(shared/shared_models/asset_identity.py, version tag ``fact:v1``). Until
now identity existed only as in-memory tuples per write path, so nothing
durable joined an observation across shapes, scans or exports.

Backfill is Python-side (one canonical implementation, works on SQLite
and PostgreSQL). No unique constraint yet: legacy forks (same identity
claimed by several rows, e.g. from line-shifted re-scans) are legal
history — the spine makes them VISIBLE (reconcile reports duplicate
keys) instead of crashing migration; the single-writer cutover decides
their disposition.
"""

from alembic import op
import sqlalchemy as sa

revision = "0092"
down_revision = "0091"
branch_labels = None
depends_on = None


def _backfill_asset_keys(conn) -> int:
    """Compute the spine key for every row that lacks one. Returns the
    number of rows updated. Uses the canonical shared derivation — the
    migration must never re-implement identity logic."""
    from shared_models.asset_identity import crypto_asset_key

    rows = conn.execute(sa.text(
        "SELECT id, algorithm, purpose, file_path, key_size, mode "
        "FROM crypto_assets WHERE asset_key IS NULL"
    )).fetchall()
    updated = 0
    for row_id, algorithm, purpose, file_path, key_size, mode in rows:
        key = crypto_asset_key(algorithm, purpose, file_path, key_size, mode)
        conn.execute(
            sa.text("UPDATE crypto_assets SET asset_key = :k WHERE id = :i"),
            {"k": key, "i": row_id},
        )
        updated += 1
    return updated


def upgrade() -> None:
    op.add_column("crypto_assets",
                  sa.Column("asset_key", sa.String(100), nullable=True))
    op.create_index("ix_crypto_assets_asset_key", "crypto_assets", ["asset_key"])
    conn = op.get_bind()
    _backfill_asset_keys(conn)


def downgrade() -> None:
    op.drop_index("ix_crypto_assets_asset_key", table_name="crypto_assets")
    op.drop_column("crypto_assets", "asset_key")
