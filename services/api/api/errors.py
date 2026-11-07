"""Stable API error contract (gap analysis §B).

Every error response carries a stable ``error_code`` and the ``request_id``
of the call. The canonical codes are stable — clients may switch on them:

    UNAUTHENTICATED, FORBIDDEN, NOT_FOUND, CONFLICT, RATE_LIMITED,
    UPSTREAM_UNAVAILABLE, INVALID_ARGUMENT, UNSUPPORTED_COLLECTOR,
    EVIDENCE_REQUIRED

plus INTERNAL_ERROR for an unhandled server fault (the one non-table code;
it means "the server failed", never "the data is fine").

Middleware layers may emit more specific stable refinements (for example
INVALID_TOKEN or ABAC_DENIED); those are documented subclasses of the
canonical classes and are just as stable.

The envelope is additive: ``detail`` keeps its historical shape (string,
field list, or object) so existing clients do not break.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

UNAUTHENTICATED = "UNAUTHENTICATED"
FORBIDDEN = "FORBIDDEN"
NOT_FOUND = "NOT_FOUND"
CONFLICT = "CONFLICT"
RATE_LIMITED = "RATE_LIMITED"
UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
INVALID_ARGUMENT = "INVALID_ARGUMENT"
UNSUPPORTED_COLLECTOR = "UNSUPPORTED_COLLECTOR"
EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
INTERNAL_ERROR = "INTERNAL_ERROR"

ERROR_CODES = frozenset({
    UNAUTHENTICATED,
    FORBIDDEN,
    NOT_FOUND,
    CONFLICT,
    RATE_LIMITED,
    UPSTREAM_UNAVAILABLE,
    INVALID_ARGUMENT,
    UNSUPPORTED_COLLECTOR,
    EVIDENCE_REQUIRED,
    INTERNAL_ERROR,
})

STATUS_TO_CODE = {
    400: INVALID_ARGUMENT,
    401: UNAUTHENTICATED,
    403: FORBIDDEN,
    404: NOT_FOUND,
    405: NOT_FOUND,
    409: CONFLICT,
    412: CONFLICT,
    422: INVALID_ARGUMENT,
    429: RATE_LIMITED,
    502: UPSTREAM_UNAVAILABLE,
    503: UPSTREAM_UNAVAILABLE,
    504: UPSTREAM_UNAVAILABLE,
}


def code_for_status(status: int) -> str:
    return STATUS_TO_CODE.get(status, INTERNAL_ERROR)


def error_envelope(code: str, detail, request_id: str | None = None) -> dict:
    """Build the stable error body. ``detail`` keeps its existing shape."""
    if code not in ERROR_CODES:
        raise ValueError(f"unknown error code {code!r}; valid: {sorted(ERROR_CODES)}")
    body: dict = {"detail": detail, "error_code": code}
    if request_id:
        body["request_id"] = request_id
    return body


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def install_error_contract(app: FastAPI) -> None:
    """Route every error through the stable envelope.

    ``detail`` is preserved verbatim (string, validation field list, or
    object), so clients that read ``detail`` keep working; the code and
    request id ride alongside.
    """

    @app.exception_handler(RequestValidationError)
    async def invalid_argument(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content=error_envelope(
                INVALID_ARGUMENT, exc.errors(), _request_id(request)),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception(request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        code = code_for_status(exc.status_code)
        # a handler that already chose a specific stable code keeps it
        if isinstance(detail, dict) and detail.get("error_code") in ERROR_CODES:
            code = detail["error_code"]
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(code, detail, _request_id(request)),
            # exception-specified headers survive the envelope (RFC 8594
            # deprecation trail, Retry-After, ...)
            headers=getattr(exc, "headers", None) or None,
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # never leak the traceback or exception text to the client
        return JSONResponse(
            status_code=500,
            content=error_envelope(
                INTERNAL_ERROR, "internal server error", _request_id(request)),
        )
