"""
Initial migration: Create scans table.

Revision ID: 0001
Revises: None
Create Date: 2024-01-15 10:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create scans table."""
    op.create_table(
        'scans',
        
        # Primary key
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), primary_key=True),
        
        # Timestamps
        sa.Column('scan_start', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('scan_end', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False, 
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        
        # Scanner metadata
        sa.Column('scanner_id', sa.VARCHAR(100), nullable=False),
        sa.Column('scanner_version', sa.VARCHAR(20), nullable=False),
        
        # Target information
        sa.Column('target_type', sa.VARCHAR(50), nullable=False),  # GIT_REPO, LOCAL_DIR
        sa.Column('target_location', sa.TEXT, nullable=False),
        sa.Column('target_commit', sa.VARCHAR(40), nullable=True),
        sa.Column('target_branch', sa.VARCHAR(100), nullable=True),
        
        # Execution metadata
        sa.Column('operator', sa.VARCHAR(100), nullable=True),
        sa.Column('status', sa.VARCHAR(20), nullable=False, server_default='RUNNING'),
        
        # Statistics (JSONB for flexibility)
        sa.Column('statistics', sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=True),
        
        # Integrity
        sa.Column('manifest_hash', sa.VARCHAR(64), nullable=True),
        
        # Indexes for common queries
        sa.Index('idx_scans_start_desc', 'scan_start', postgresql_ops={'scan_start': 'DESC'}),
        sa.Index('idx_scans_target_location', 'target_location', postgresql_using='hash'),
        sa.Index('idx_scans_target_commit', 'target_commit'),
        sa.Index('idx_scans_status', 'status'),
        
        # Check constraints
        sa.CheckConstraint(
            "status IN ('RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name='scans_status_check'
        ),
        sa.CheckConstraint(
            "target_type IN ('GIT_REPOSITORY', 'LOCAL_DIRECTORY', 'ARCHIVE')",
            name='scans_target_type_check'
        ),
    )
    
    # Add comment to table
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
        COMMENT ON TABLE scans IS 
        'Scan sessions - one record per complete scan execution'
    """)


def downgrade():
    """Drop scans table."""
    op.drop_table('scans')