"""
Unit tests for canonical JSON serialization.
"""
from evidence.hashing.canonical_serializer import CanonicalSerializer


def test_removes_excluded_fields():
    """Test that excluded fields are removed from serialization."""
    # Arrange
    data = {
        'algorithm': 'AES',
        'finding_id': 'should-be-removed',
        'scan_timestamp': '2024-01-15',
        'line_number': 247,
    }
    
    # Act
    result_bytes = CanonicalSerializer.serialize(data)
    result_str = result_bytes.decode('utf-8')
    
    # Assert: Excluded fields not in output
    assert 'finding_id' not in result_str
    assert 'scan_timestamp' not in result_str
    
    # Assert: Included fields present
    assert 'algorithm' in result_str
    assert 'line_number' in result_str


def test_sorts_keys_alphabetically():
    """Test that keys are sorted alphabetically."""
    # Arrange
    data = {
        'zebra': 1,
        'alpha': 2,
        'middle': 3,
    }
    
    # Act
    result_str = CanonicalSerializer.serialize(data).decode('utf-8')
    
    # Assert: Keys appear in alphabetical order
    alpha_pos = result_str.index('alpha')
    middle_pos = result_str.index('middle')
    zebra_pos = result_str.index('zebra')
    
    assert alpha_pos < middle_pos < zebra_pos


def test_no_whitespace_in_output():
    """Test that output contains no unnecessary whitespace."""
    # Arrange
    data = {'key': 'value', 'nested': {'inner': 'data'}}
    
    # Act
    result_str = CanonicalSerializer.serialize(data).decode('utf-8')
    
    # Assert: No spaces after separators
    assert ', ' not in result_str
    assert ': ' not in result_str
    assert '\n' not in result_str


def test_identical_data_produces_identical_hash():
    """Test that same data always produces same serialization (determinism)."""
    # Arrange
    data1 = {'algorithm': 'AES', 'mode': 'GCM', 'line': 100}
    data2 = {'mode': 'GCM', 'line': 100, 'algorithm': 'AES'}  # Different key order
    
    # Act
    result1 = CanonicalSerializer.serialize(data1)
    result2 = CanonicalSerializer.serialize(data2)
    
    # Assert: Identical output despite different input key order
    assert result1 == result2


def test_handles_nested_structures():
    """Test serialization of nested dictionaries and lists."""
    # Arrange
    data = {
        'outer': {
            'inner': {
                'deep': 'value'
            },
            'list': [3, 1, 2]
        }
    }
    
    # Act
    result_str = CanonicalSerializer.serialize(data).decode('utf-8')
    
    # Assert: Valid JSON produced
    import json
    parsed = json.loads(result_str)
    assert parsed['outer']['inner']['deep'] == 'value'


def test_handles_unicode_correctly():
    """Test that Unicode characters are preserved."""
    # Arrange
    data = {
        'message': 'Hello 世界 🔐',
        'algorithm': 'AES'
    }
    
    # Act
    result_bytes = CanonicalSerializer.serialize(data)
    result_str = result_bytes.decode('utf-8')
    
    # Assert: Unicode preserved
    assert '世界' in result_str
    assert '🔐' in result_str


def test_utf8_encoding():
    """Test that output is properly UTF-8 encoded."""
    # Arrange
    data = {'key': 'value'}
    
    # Act
    result = CanonicalSerializer.serialize(data)
    
    # Assert: Returns bytes
    assert isinstance(result, bytes)
    
    # Assert: Valid UTF-8
    decoded = result.decode('utf-8')
    assert isinstance(decoded, str)