"""
Integration tests for tamper detection.
Tests that modifications to evidence are detected.
"""
import pytest
from evidence.core.pipeline import EvidencePipeline
from evidence.verification.verifier import EvidenceVerifier


@pytest.fixture
def sample_findings():
    """Sample findings for testing."""
    return [
        {
            'finding_id': 'finding-1',
            'algorithm': 'DES',
            'file_path': 'Test.java',
            'line_number': 100
        },
        {
            'finding_id': 'finding-2',
            'algorithm': 'AES',
            'file_path': 'Crypto.java',
            'line_number': 200
        },
        {
            'finding_id': 'finding-3',
            'algorithm': 'MD5',
            'file_path': 'Hash.java',
            'line_number': 300
        }
    ]


def test_tamper_detection_content_modification(sample_findings):
    """Test that modifying finding content is detected."""
    # Arrange: Create evidence chain
    pipeline = EvidencePipeline(scan_session_id='test-scan-1')
    evidence_records = pipeline.process_findings(sample_findings)
    
    # Act: Tamper with middle finding (change algorithm)
    evidence_records[1].finding['algorithm'] = 'TAMPERED'
    
    # Verify
    result = EvidenceVerifier.verify_evidence_chain(
        evidence_records,
        scan_session_id='test-scan-1'
    )
    
    # Assert: Tampering detected
    assert result.is_valid is False
    assert any('Content hash mismatch' in error for error in result.errors)
    assert any('finding-2' in error or 'position 1' in error for error in result.errors)


def test_tamper_detection_record_deletion(sample_findings):
    """Test that deleting a record is detected."""
    # Arrange: Create evidence chain
    pipeline = EvidencePipeline(scan_session_id='test-scan-2')
    evidence_records = pipeline.process_findings(sample_findings)
    manifest = pipeline.create_manifest()
    
    # Act: Delete middle record
    tampered_records = [evidence_records[0], evidence_records[2]]
    
    # Verify manifest
    result = EvidenceVerifier.verify_manifest(manifest, tampered_records)
    
    # Assert: Deletion detected via count mismatch
    assert result.is_valid is False
    assert any('count mismatch' in error.lower() for error in result.errors)


def test_tamper_detection_record_reordering(sample_findings):
    """Test that reordering records is detected."""
    # Arrange: Create evidence chain
    pipeline = EvidencePipeline(scan_session_id='test-scan-3')
    evidence_records = pipeline.process_findings(sample_findings)
    
    # Act: Swap first and second records (but keep their chain_position values)
    reordered_records = [evidence_records[1], evidence_records[0], evidence_records[2]]
    
    # Verify
    result = EvidenceVerifier.verify_evidence_chain(
        reordered_records,
        scan_session_id='test-scan-3'
    )
    
    # Assert: Reordering detected via chain hash mismatch
    assert result.is_valid is False
    assert any('chain hash mismatch' in error.lower() for error in result.errors)


def test_tamper_detection_chain_hash_modification(sample_findings):
    """Test that modifying chain_hash is detected."""
    # Arrange: Create evidence chain
    pipeline = EvidencePipeline(scan_session_id='test-scan-4')
    evidence_records = pipeline.process_findings(sample_findings)
    
    # Act: Modify chain_hash directly
    evidence_records[1].chain_hash = 'tampered-hash-xxxxxxxxx'
    
    # Verify
    result = EvidenceVerifier.verify_evidence_chain(
        evidence_records,
        scan_session_id='test-scan-4'
    )
    
    # Assert: Tampering detected
    assert result.is_valid is False
    assert any('chain hash mismatch' in error.lower() for error in result.errors)


def test_no_false_positives_on_valid_chain(sample_findings):
    """Test that valid evidence chain passes verification."""
    # Arrange: Create valid evidence chain
    pipeline = EvidencePipeline(scan_session_id='test-scan-5')
    evidence_records = pipeline.process_findings(sample_findings)
    manifest = pipeline.create_manifest()
    
    # Act: Verify without tampering
    chain_result = EvidenceVerifier.verify_evidence_chain(
        evidence_records,
        scan_session_id='test-scan-5'
    )
    manifest_result = EvidenceVerifier.verify_manifest(manifest, evidence_records)
    
    # Assert: No errors
    assert chain_result.is_valid is True
    assert len(chain_result.errors) == 0
    assert manifest_result.is_valid is True
    assert len(manifest_result.errors) == 0


def test_tamper_detection_manifest_hash(sample_findings):
    """Test that modifying manifest_hash is detected."""
    # Arrange
    pipeline = EvidencePipeline(scan_session_id='test-scan-6')
    evidence_records = pipeline.process_findings(sample_findings)
    manifest = pipeline.create_manifest()
    
    # Act: Tamper with manifest hash
    manifest.manifest_hash = 'tampered-manifest-hash'
    
    # Verify
    result = EvidenceVerifier.verify_manifest(manifest, evidence_records)
    
    # Assert: Tampering detected
    assert result.is_valid is False
    assert any('manifest hash' in error.lower() for error in result.errors)