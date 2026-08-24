"""
Create evidence_records table.

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-15 10:05:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    """Create evidence_records table."""
    op.create_table(
        'evidence_records',
        
        # Primary key
        sa.Column('evidence_id', postgresql.UUID(as_uuid=True), primary_key=True),
        
        # Foreign key to scans
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        
        # Content integrity
        sa.Column('content_hash', sa.VARCHAR(64), nullable=False, index=True),
        
        # Chain integrity
        sa.Column('chain_position', sa.INTEGER, nullable=False),
        sa.Column('chain_hash', sa.VARCHAR(64), nullable=False),
        sa.Column('previous_hash', sa.VARCHAR(64), nullable=True),
        
        # Extracted fields for fast querying (denormalized from finding_data)
        sa.Column('algorithm', sa.VARCHAR(50), nullable=True, index=True),
        sa.Column('key_size', sa.INTEGER, nullable=True),
        sa.Column('mode', sa.VARCHAR(50), nullable=True),
        sa.Column('padding', sa.VARCHAR(50), nullable=True),
        sa.Column('purpose', sa.VARCHAR(50), nullable=True),
        sa.Column('confidence', sa.VARCHAR(20), nullable=True),
        
        # Location fields
        sa.Column('file_path', sa.TEXT, nullable=True),
        sa.Column('line_number', sa.INTEGER, nullable=True),
        sa.Column('class_name', sa.TEXT, nullable=True),
        sa.Column('method_name', sa.VARCHAR(200), nullable=True),
        
        # Flags
        sa.Column('is_hardcoded_key', sa.BOOLEAN, nullable=False, server_default='false'),
        
        # Full finding data (immutable JSONB)
        sa.Column('finding_data', postgresql.JSONB, nullable=False),
        
        # Provenance metadata
        sa.Column('provenance', postgresql.JSONB, nullable=True),
        
        # Timestamps
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.TIMESTAMP(timezone=True), nullable=True),
        
        # Foreign key constraint
        sa.ForeignKeyConstraint(
            ['scan_id'],
            ['scans.scan_id'],
            name='fk_evidence_records_scan_id',
            ondelete='CASCADE'
        ),
        
        # Unique constraint: position per scan
        sa.UniqueConstraint('scan_id', 'chain_position', name='uq_scan_chain_position'),
        
        # Check constraints
        sa.CheckConstraint('chain_position >= 0', name='evidence_chain_position_check'),
        sa.CheckConstraint(
            "confidence IN ('HIGH', 'MEDIUM', 'LOW')",
            name='evidence_confidence_check'
        ),
    )
    
    # Indexes for common queries
    op.create_index(
        'idx_evidence_scan_position',
        'evidence_records',
        ['scan_id', 'chain_position']
    )
    
    op.create_index(
        'idx_evidence_algorithm',
        'evidence_records',
        ['algorithm']
    )
    
    op.create_index(
        'idx_evidence_hardcoded_key',
        'evidence_records',
        ['is_hardcoded_key'],
        postgresql_where=sa.text('is_hardcoded_key = true')
    )
    
    # GIN index for JSONB queries
    op.create_index(
        'idx_evidence_finding_data_gin',
        'evidence_records',
        ['finding_data'],
        postgresql_using='gin'
    )
    
    # Add table comment
    op.execute("""
        COMMENT ON TABLE evidence_records IS 
        'Evidence records with cryptographic integrity proofs. Immutable after creation.'
    """)


def downgrade():
    """Drop evidence_records table."""
    op.drop_table('evidence_records')