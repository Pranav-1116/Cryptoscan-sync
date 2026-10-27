"""Distributed-trace context (OpenTelemetry-shaped, no external SDK).

The existing :class:`api.middleware.request_id_middleware.RequestIDMiddleware`
correlates a request by ``X-Request-ID``. This module extends that into a small,
dependency-free trace context: a ``trace_id`` + ``span_id`` bound to a
``contextvars.ContextVar`` so any code (middleware, routers, repositories) can
read the active trace and so structured logs emitted during a request carry it.

It is deliberately **not** a full OTel/jaeger exporter — the product has no
APM backend — but it gives real end-to-end correlation that can be shipped to
any log/metrics backend later (and is what Uptime/ELK integration would key on).
"""

from __future__ import annotations

import contextvars
import uuid

#: per-request trace context (trace_id, span_id)
_TraceContext = contextvars.ContextVar("trace_context", default=None)


def new_trace() -> tuple[str, str]:
    """Generate a W3C-ish ``trace_id`` (hex) + a ``span_id`` (hex)."""
    return uuid.uuid4().hex, uuid.uuid4().hex[:16]


def push_trace(trace_id: str, span_id: str) -> None:
    _TraceContext.set((trace_id, span_id))


def active_trace() -> tuple[str | None, str | None]:
    ctx = _TraceContext.get()
    if ctx:
        return ctx[0], ctx[1]
    return None, None


def reset_trace() -> None:
    _TraceContext.set(None)
