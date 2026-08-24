"""
Create baselines table

Revision ID: 0006
Revises: 0005
Create Date: 2024-01-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create baselines table"""
    op.create_table(
        'baselines',
        sa.Column('baseline_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('system_identifier', sa.String(200), nullable=False, index=True),
        sa.Column('environment', sa.String(50), nullable=False),
        sa.Column('approved_scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('approved_by', sa.String(100), nullable=False),
        sa.Column('approved_at', sa.DateTime, nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='ACTIVE'),
        sa.Column('notes', sa.Text, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        sa.ForeignKeyConstraint(['approved_scan_id'], ['scans.scan_id']),
    )
    
    # Create index on system_identifier + environment + status
    op.create_index(
        'ix_baselines_system_env_status',
        'baselines',
        ['system_identifier', 'environment', 'status']
    )


def downgrade() -> None:
    """Drop baselines table"""
    op.drop_index('ix_baselines_system_env_status', 'baselines')
    op.drop_table('baselines')