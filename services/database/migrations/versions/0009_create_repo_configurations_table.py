"""
Create repo_configurations table

Revision ID: 0009
Revises: 0008
Create Date: 2024-01-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create repo_configurations table"""
    op.create_table(
        'repo_configurations',
        sa.Column('config_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('repo_url', sa.String(500), nullable=False, unique=True, index=True),
        sa.Column('repo_name', sa.String(200), nullable=False),
        sa.Column('enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('scan_on_push', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('scan_on_pr', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('baseline_scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('notification_emails', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        
        sa.ForeignKeyConstraint(['baseline_scan_id'], ['scans.scan_id']),
    )
    
    # Create index on enabled
    op.create_index('ix_repo_configs_enabled', 'repo_configurations', ['enabled'])


def downgrade() -> None:
    """Drop repo_configurations table"""
    op.drop_index('ix_repo_configs_enabled', 'repo_configurations')
    op.drop_table('repo_configurations')