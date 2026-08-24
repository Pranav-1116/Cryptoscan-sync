"""
Authentication Middleware - Validates JWT tokens and manages sessions.

Intercepts all requests and validates authentication.
"""

import logging
from typing import Callable
from datetime import datetime, timedelta
import jwt

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from api.config.settings import APISettings
from api.security.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for JWT validation.
    
    Validates JWT tokens in Authorization header.
    Allows specific paths to bypass authentication.
    """

    # Paths that don't require authentication
    UNPROTECTED_PATHS = {
        "/health",
        "/ready",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/api/v1/auth/login",
        "/api/v1/webhooks/github",  # GitHub webhooks use HMAC verification
    }

    def __init__(self, app, settings: APISettings):
        """
        Initialize middleware.
        
        Args:
            app: FastAPI application
            settings: APISettings instance
        """
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: Callable) -> any:
        """
        Process request with authentication.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
        
        Returns:
            Response
        """
        # Skip authentication for protected paths
        if self._is_unprotected_path(request.url.path):
            return await call_next(request)
        
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Missing Authorization header",
                    "error_code": "MISSING_AUTH_HEADER"
                }
            )
        
        # Parse "Bearer <token>"
        try:
            scheme, token = auth_header.split(" ")
            if scheme.lower() != "bearer":
                raise ValueError(f"Invalid auth scheme: {scheme}")
        except ValueError as e:
            logger.warning(
                f"Invalid Authorization header format",
                extra={"error": str(e)}
            )
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Invalid Authorization header format",
                    "error_code": "INVALID_AUTH_HEADER"
                }
            )
        
        # Validate token
        try:
            payload = jwt.decode(
                token,
                self.settings.SECRET_KEY,
                algorithms=[self.settings.JWT_ALGORITHM]
            )
            
            # Store user info in request state
            request.state.user_id = payload.get("sub")
            request.state.user_email = payload.get("email")
            request.state.user_roles = payload.get("roles", [])
            
            logger.debug(
                "Authentication successful",
                extra={
                    "user_id": request.state.user_id,
                    "user_email": request.state.user_email
                }
            )
        
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Token has expired",
                    "error_code": "TOKEN_EXPIRED"
                }
            )
        
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "Invalid token",
                    "error_code": "INVALID_TOKEN"
                }
            )
        
        # Continue to next middleware
        response = await call_next(request)
        return response

    @staticmethod
    def _is_unprotected_path(path: str) -> bool:
        """
        Check if path is unprotected (no auth required).
        
        Args:
            path: Request path
        
        Returns:
            True if path is unprotected
        """
        # Exact matches
        if path in AuthMiddleware.UNPROTECTED_PATHS:
            return True
        
        # Prefix matches
        for unprotected in AuthMiddleware.UNPROTECTED_PATHS:
            if path.startswith(unprotected):
                return True
        
        return False


def generate_jwt_token(
    user_id: str,
    email: str,
    roles: list[str],
    settings: APISettings
) -> str:
    """
    Generate JWT token.
    
    Args:
        user_id: User ID
        email: User email
        roles: User roles
        settings: APISettings
    
    Returns:
        JWT token string
    """
    now = datetime.utcnow()
    expiry = now + timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    
    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "iat": now,
        "exp": expiry
    }
    
    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    
    return token