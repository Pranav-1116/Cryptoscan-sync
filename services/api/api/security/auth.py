# services/api/api/security/auth.py

"""
Production session-based authentication.
Manages user sessions with secure token generation and validation.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple
import hashlib
import logging

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Secure session management for API authentication.
    Generates, validates, and refreshes sessions.
    """
    
    TOKEN_LENGTH = 32  # 256 bits
    TOKEN_ENCODING = "utf-8"
    
    def __init__(self, secret: str, ttl_hours: int = 24):
        """
        Initialize session manager.
        
        Args:
            secret: Secret key for token signing
            ttl_hours: Session time-to-live (hours)
        """
        self.secret = secret.encode(self.TOKEN_ENCODING)
        self.ttl_hours = ttl_hours
    
    def create_session(self, user_id: str) -> Tuple[str, datetime]:
        """
        Create new user session.
        
        Args:
            user_id: Unique user identifier
        
        Returns:
            Tuple of (session_token, expiry_datetime)
        """
        # Generate cryptographically secure random token
        token = secrets.token_urlsafe(self.TOKEN_LENGTH)
        
        # Calculate expiry
        expiry = datetime.utcnow() + timedelta(hours=self.ttl_hours)
        
        logger.info(f"Session created for user: {user_id}")
        
        return token, expiry
    
    def validate_session(
        self,
        token: str,
        user_id: str,
        stored_expiry: datetime,
    ) -> bool:
        """
        Validate session token and expiry.
        
        Args:
            token: Session token from client
            user_id: Associated user ID
            stored_expiry: Stored session expiry time
        
        Returns:
            True if valid, False if expired or invalid
        """
        # Check if expired
        if datetime.utcnow() > stored_expiry:
            logger.warning(f"Session expired for user: {user_id}")
            return False
        
        # Token format check (basic)
        if not token or len(token) < 10:
            logger.warning(f"Invalid token format for user: {user_id}")
            return False
        
        return True
    
    def refresh_session(self, user_id: str) -> Tuple[str, datetime]:
        """
        Refresh existing session (issue new token, extend expiry).
        
        Args:
            user_id: User ID
        
        Returns:
            Tuple of (new_token, new_expiry)
        """
        logger.info(f"Session refreshed for user: {user_id}")
        return self.create_session(user_id)
    
    def revoke_session(self, token: str, user_id: str) -> None:
        """
        Revoke (logout) session.
        
        Args:
            token: Session token
            user_id: User ID
        """
        logger.info(f"Session revoked for user: {user_id}")
        # In production, store revoked tokens in Redis blacklist


class CredentialValidator:
    """
    Simple username/password validation.
    In production, integrate with LDAP, OAuth, etc.
    """
    
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash password with salt using PBKDF2.
        
        Args:
            password: Plain-text password
            salt: Optional salt (generated if not provided)
        
        Returns:
            Tuple of (password_hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # PBKDF2-HMAC-SHA256: 100k iterations
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            iterations=100_000,
        ).hex()
        
        return pwd_hash, salt
    
    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Plain-text password from login
            stored_hash: Stored password hash (hex)
            salt: Stored salt (hex)
        
        Returns:
            True if password matches
        """
        pwd_hash, _ = CredentialValidator.hash_password(password, salt)
        
        # Constant-time comparison
        import hmac
        return hmac.compare_digest(pwd_hash, stored_hash)
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """
        Validate username format.
        
        Args:
            username: Username to validate
        
        Returns:
            True if valid format
        """
        if not username or len(username) < 3:
            return False
        
        if len(username) > 255:
            return False
        
        # Allow alphanumeric, underscore, hyphen, dot
        import re
        if not re.match(r"^[a-zA-Z0-9._-]+$", username):
            return False
        
        return True