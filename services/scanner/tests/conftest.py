"""
Pytest fixtures for scanner tests.
"""
import pytest
from pathlib import Path
import tempfile
import shutil
from scanner.core.scanner import CryptoScanner, Scanner  # noqa: F401
from scanner.config.scanner_config import ScannerConfig


@pytest.fixture
def temp_workspace():
    """Create temporary workspace for tests."""
    workspace = Path(tempfile.mkdtemp(prefix="cryptoscan_test_"))
    yield workspace
    shutil.rmtree(workspace, ignore_errors=True)


@pytest.fixture
def sample_java_files(temp_workspace):
    """Create sample Java files for testing."""
    samples_dir = temp_workspace / "samples"
    samples_dir.mkdir()
    
    # Sample 1: Cipher with DES
    (samples_dir / "BadCrypto.java").write_text("""
package com.example;
import javax.crypto.Cipher;

public class BadCrypto {
    public void encrypt() throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        // This uses weak DES encryption
    }
}
""")
    
    # Sample 2: Good AES-GCM
    (samples_dir / "GoodCrypto.java").write_text("""
package com.example;
import javax.crypto.Cipher;

public class GoodCrypto {
    public void encrypt() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // This uses strong AES-256-GCM
    }
}
""")
    
    # Sample 3: MessageDigest with MD5
    (samples_dir / "HashExample.java").write_text("""
package com.example;
import java.security.MessageDigest;

public class HashExample {
    public void hash() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        // Weak hash function
    }
}
""")
    
    # Sample 4: Hardcoded key
    (samples_dir / "HardcodedKey.java").write_text("""
package com.example;
import javax.crypto.spec.SecretKeySpec;

public class HardcodedKey {
    private static final byte[] KEY = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    
    public void badPractice() {
        SecretKeySpec keySpec = new SecretKeySpec(new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}, "AES");
        // CRITICAL: Hardcoded key!
    }
}
""")
    
    return samples_dir


@pytest.fixture
def scanner_config():
    """Create test scanner configuration."""
    return ScannerConfig(
        max_workers=1,  # Single-threaded for tests
        timeout_per_file=10,
        scan_test_files=True,
    )


@pytest.fixture
def crypto_scanner(scanner_config):
    """Create CryptoScanner instance."""
    return CryptoScanner(config=scanner_config)


@pytest.fixture
def expected_findings():
    """Expected findings from sample files."""
    return {
        'des': {
            'algorithm': 'DES',
            'file': 'BadCrypto.java',
            'line': 6,
        },
        'aes_gcm': {
            'algorithm': 'AES',
            'mode': 'GCM',
            'file': 'GoodCrypto.java',
        },
        'md5': {
            'algorithm': 'MD5',
            'file': 'HashExample.java',
        },
        'hardcoded_key': {
            'is_hardcoded_key': True,
            'file': 'HardcodedKey.java',
        }
    }