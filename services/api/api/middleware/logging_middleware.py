"""
Logging Middleware - Structured logging for all requests/responses.

Logs request/response details in structured JSON format.
"""

import logging
import time
import json
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured request/response logging.
    
    Logs timing, headers, body size, etc.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> any:
        """
        Log request and response details.
        
        Args:
            request: HTTP request
            call_next: Next middleware/handler
        
        Returns:
            Response
        """
        start_time = time.time()
        
        # Extract request details
        request_id = getattr(request.state, "request_id", "unknown")
        method = request.method
        path = request.url.path
        query_params = dict(request.query_params) if request.query_params else {}
        
        # Get request body size
        body_size = 0
        if "content-length" in request.headers:
            try:
                body_size = int(request.headers["content-length"])
            except ValueError:
                pass
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(
                "Request processing failed",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "error": str(e),
                    "error_type": type(e).__name__
                },
                exc_info=True
            )
            raise
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Extract response details
        status_code = response.status_code
        response_headers = dict(response.headers)
        
        # Log request/response
        logger.info(
            f"{method} {path}",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "status_code": status_code,
                "process_time_ms": round(process_time * 1000, 2),
                "query_params": query_params,
                "request_body_size": body_size,
                "response_size": response.headers.get("content-length", "unknown")
            }
        )
        
        return response