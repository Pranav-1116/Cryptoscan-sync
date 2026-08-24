# services/api/api/security/hmac_verifier.py

"""
Production HMAC verification for GitHub webhook security.
Implements constant-time comparison to prevent timing attacks.
"""

import hmac
import hashlib
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class HMACVerifier:
    """
    Cryptographically secure HMAC verification.
    Prevents webhook forgery using constant-time comparison.
    """
    
    ALGORITHM = hashlib.sha256
    HEADER_NAME = "X-Hub-Signature-256"
    
    def __init__(self, secret: str):
        """
        Initialize verifier with webhook secret.
        
        Args:
            secret: HMAC secret (must match GitHub webhook config)
        
        Raises:
            ValueError: If secret is empty
        """
        if not secret or len(secret.strip()) == 0:
            raise ValueError("HMAC secret cannot be empty")
        
        self.secret = secret.encode("utf-8")
    
    def compute_signature(self, payload: bytes) -> str:
        """
        Compute HMAC-SHA256 signature of payload.
        
        Args:
            payload: Raw request body bytes
        
        Returns:
            Signature string format: "sha256=<hex>"
        """
        if not isinstance(payload, bytes):
            payload = payload.encode("utf-8")
        
        computed_hash = hmac.new(
            self.secret,
            payload,
            self.ALGORITHM
        ).hexdigest()
        
        return f"sha256={computed_hash}"
    
    def verify(self, payload: bytes, signature_header: Optional[str]) -> bool:
        """
        Verify webhook signature (constant-time comparison).
        
        Args:
            payload: Raw request body
            signature_header: Value from X-Hub-Signature-256 header
        
        Returns:
            True if valid, False otherwise
        
        Security:
            - Uses hmac.compare_digest() for constant-time comparison
            - Prevents timing attacks
            - Log suspicious attempts
        """
        if not signature_header:
            logger.warning("Missing HMAC signature header")
            return False
        
        # Compute expected signature
        expected_signature = self.compute_signature(payload)
        
        # Constant-time comparison (prevents timing attacks)
        is_valid = hmac.compare_digest(expected_signature, signature_header)
        
        if not is_valid:
            logger.warning(
                f"HMAC verification failed. "
                f"Expected: {expected_signature[:20]}..., "
                f"Got: {signature_header[:20]}..."
            )
        
        return is_valid
    
    @staticmethod
    def extract_signature_from_headers(headers: dict) -> Optional[str]:
        """
        Extract HMAC signature from HTTP headers (case-insensitive).
        
        Args:
            headers: HTTP headers dictionary
        
        Returns:
            Signature value or None if not found
        """
        # GitHub uses X-Hub-Signature-256
        for key, value in headers.items():
            if key.lower() == "x-hub-signature-256":
                return value
        
        return None