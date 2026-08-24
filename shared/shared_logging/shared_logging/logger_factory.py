"""Structured JSON logging factory."""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric)

    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json_output or not sys.stdout.isatty():
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def create_logger(name: str = "cryptoscan", json_format: bool | None = None, **kwargs):
    return structlog.get_logger(name)
