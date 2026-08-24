"""
Create drift_events table

Revision ID: 0007
Revises: 0006
Create Date: 2024-01-15
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create drift_events table"""
    op.create_table(
        'drift_events',
        sa.Column('drift_id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('baseline_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('current_scan_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('detected_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('drift_type', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('drift_details', postgresql.JSONB, nullable=False),
        sa.Column('resolution_status', sa.String(50), nullable=False, server_default='OPEN'),
        sa.Column('resolved_by', sa.String(100), nullable=True),
        sa.Column('resolved_at', sa.DateTime, nullable=True),
        sa.Column('resolution_notes', sa.Text, nullable=True),
        
        sa.ForeignKeyConstraint(['baseline_id'], ['baselines.baseline_id']),
        sa.ForeignKeyConstraint(['current_scan_id'], ['scans.scan_id']),
    )
    
    # Create index on resolution_status + severity
    op.create_index(
        'ix_drift_events_status_severity',
        'drift_events',
        ['resolution_status', 'severity']
    )


def downgrade() -> None:
    """Drop drift_events table"""
    op.drop_index('ix_drift_events_status_severity', 'drift_events')
    op.drop_table('drift_events')