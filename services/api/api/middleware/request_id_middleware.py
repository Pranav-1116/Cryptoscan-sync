"""
Request ID Middleware - Injects unique request ID for tracing.

Every request gets a unique ID for distributed tracing.
"""

import logging
import uuid
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware that injects request ID.
    
    Adds unique X-Request-ID to every request for tracing.
    """

    REQUEST_ID_HEADER = "X-Request-ID"

    async def dispatch(self, request: Request, call_next: Callable) -> any:
        """
        Add request ID to request and response.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
        
        Returns:
            Response with X-Request-ID header
        """
        # Extract request ID from header or generate new one
        request_id = request.headers.get(self.REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Store in request state
        request.state.request_id = request_id
        
        # Log request start
        logger.info(
            f"{request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client": request.client.host if request.client else None
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers[self.REQUEST_ID_HEADER] = request_id
        
        # Log response
        logger.info(
            f"{request.method} {request.url.path} {response.status_code}",
            extra={
                "request_id": request_id,
                "status_code": response.status_code,
                "method": request.method,
                "path": request.url.path
            }
        )
        
        return response