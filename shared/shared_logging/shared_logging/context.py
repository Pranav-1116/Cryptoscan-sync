"""Request / scan context for structured logs."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import structlog


def bind_context(**kwargs) -> None:
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()


@contextmanager
def log_context(**kwargs) -> Iterator[None]:
    structlog.contextvars.bind_contextvars(**kwargs)
    try:
        yield
    finally:
        structlog.contextvars.unbind_contextvars(*kwargs.keys())
