"""
Session Management
Simple session-based auth (Month 3 MVP)
"""
import hashlib
import hmac
import json
import time
from typing import Optional
from dataclasses import dataclass


@dataclass
class Session:
    username: str
    created_at: float
    expires_at: float


class SessionManager:
    """
    Simple HMAC-signed session manager
    Session format: base64(json({username, exp})).hmac_signature
    """
    
    def __init__(self, secret: str, ttl_seconds: int = 86400):
        self.secret = secret.encode()
        self.ttl = ttl_seconds
    
    def create_session(self, username: str) -> str:
        """
        Create new session token
        Returns: signed session token
        """
        now = time.time()
        session_data = {
            "username": username,
            "created_at": now,
            "expires_at": now + self.ttl
        }
        
        # Encode session data
        import base64
        session_json = json.dumps(session_data)
        session_b64 = base64.b64encode(session_json.encode()).decode()
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret,
            session_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Token format: data.signature
        return f"{session_b64}.{signature}"
    
    def validate_session(self, token: str) -> Optional[str]:
        """
        Validate session token
        Returns: username if valid, None otherwise
        """
        try:
            # Split token
            parts = token.split(".")
            if len(parts) != 2:
                return None
            
            session_b64, signature = parts
            
            # Verify HMAC signature
            expected_sig = hmac.new(
                self.secret,
                session_b64.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
            
            # Decode session data
            import base64
            session_json = base64.b64decode(session_b64).decode()
            session_data = json.loads(session_json)
            
            # Check expiration
            if time.time() > session_data["expires_at"]:
                return None
            
            return session_data["username"]
        
        except Exception:
            return None
    
    def refresh_session(self, token: str) -> Optional[str]:
        """
        Refresh session (extend TTL)
        Returns: new token if valid, None otherwise
        """
        username = self.validate_session(token)
        if username:
            return self.create_session(username)
        return None