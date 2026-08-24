"""
Create scan_jobs table

Revision ID: 0008
Revises: 0007
Create Date: 2024-01-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create scan_jobs table"""
    op.create_table(
        'scan_jobs',
        sa.Column('job_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('job_type', sa.String(50), nullable=False),
        sa.Column('target_repo', sa.Text, nullable=False),
        sa.Column('target_commit', sa.String(40), nullable=True),
        sa.Column('target_branch', sa.String(100), nullable=False),
        sa.Column('triggered_by', sa.String(100), nullable=False),
        sa.Column('status', sa.Enum('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', name='scanjobstatus'), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('error_message', sa.Text, nullable=True),
        
        sa.ForeignKeyConstraint(['scan_id'], ['scans.scan_id']),
    )
    
    # Create indexes
    op.create_index('ix_scan_jobs_status', 'scan_jobs', ['status'])
    op.create_index('ix_scan_jobs_created_at', 'scan_jobs', ['created_at'])


def downgrade() -> None:
    """Drop scan_jobs table"""
    op.drop_index('ix_scan_jobs_created_at', 'scan_jobs')
    op.drop_index('ix_scan_jobs_status', 'scan_jobs')
    op.drop_table('scan_jobs')
    
    # Drop enum type
    op.execute('DROP TYPE scanjobstatus')