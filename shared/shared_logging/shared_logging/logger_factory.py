"""Structured logging factory — enterprise defaults for every service.

Guarantees:

- **One pipeline**: stdlib ``logging`` records are routed through structlog's
  ``ProcessorFormatter`` so *all* log output shares the same JSON/console
  shape — no dual-format logs.
- **Secret redaction**: a processor scrubs sensitive keys (passwords, tokens,
  secrets, keys) from every event dict, including nested structures, before
  rendering. Applies to structlog *and* stdlib log calls.
- **Idempotent configuration**: repeated ``configure_logging`` calls
  reconfigure levels in place instead of stacking duplicate handlers.
- **Correlation**: ``structlog.contextvars`` are merged into every event
  (see :mod:`shared_logging.context`).
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any

import structlog

#: Value substituted for every redacted secret.
REDACTED = "[REDACTED]"

#: Key fragments (case-insensitive, substring match) that mark a value as
#: sensitive wherever they appear.
SENSITIVE_KEY_MARKERS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "credential",
        "authorization",
        "cookie",
    }
)

#: Keys that are sensitive only as an exact match — a substring rule here
#: would clobber correlation/context fields (session_id, commit_author, …).
EXACT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"auth", "bearer", "session", "sessionid", "refresh"}
)

_NOISY_LIBRARIES = ("urllib3", "git", "asyncio")

_config_lock = threading.Lock()
_handler: logging.StreamHandler | None = None


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith("_size") or lowered in {"size", "sizes"}:
        return False
    if lowered in EXACT_SENSITIVE_KEYS:
        return True
    return any(marker in lowered for marker in SENSITIVE_KEY_MARKERS)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (REDACTED if _is_sensitive_key(str(k)) and v not in (None, "", [], {})
                else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def redact_secrets(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor: mask sensitive keys anywhere in the event."""
    return _redact(event_dict)


def _shared_processors(redact: bool) -> list[Any]:
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if redact:
        processors.append(redact_secrets)
    processors.extend(
        [
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]
    )
    return processors


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    *,
    redact: bool = True,
    force: bool = False,
) -> None:
    """Configure process-wide logging.

    Args:
        level: root log level name (DEBUG/INFO/WARNING/ERROR/CRITICAL).
        json_output: render machine-readable JSON lines. Defaults to JSON
            whenever stdout is not a TTY (containers, CI, pipes).
        redact: scrub sensitive keys from every log event. Leave on.
        force: replace any pre-existing root handlers (e.g. after a test).
    """
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    use_json = json_output or not sys.stdout.isatty()

    shared = _shared_processors(redact)
    renderer = (
        structlog.processors.JSONRenderer() if use_json else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    global _handler
    with _config_lock:
        root = logging.getLogger()
        if force or _handler is None or _handler not in root.handlers:
            new_handler = logging.StreamHandler(sys.stdout)
            new_handler.setFormatter(
                structlog.stdlib.ProcessorFormatter(
                    foreign_pre_chain=[
                        # Pull stdlib ``extra={...}`` into the event dict so
                        # shared processors (incl. redaction) apply to it.
                        structlog.stdlib.ExtraAdder(),
                        *shared,
                    ],
                    processors=[
                        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                        renderer,
                    ],
                )
            )
            # Replace only handlers we installed; leave pytest/caplog and
            # application-specific handlers untouched.
            root.handlers[:] = [
                h for h in root.handlers if h is not _handler
            ] + [new_handler]
            _handler = new_handler
        else:
            _handler.setLevel(numeric)
        root.setLevel(numeric)

        for name in _NOISY_LIBRARIES:
            logging.getLogger(name).setLevel(max(numeric, logging.INFO))


def create_logger(name: str = "cryptoscan", json_format: bool | None = None, **kwargs):
    """Return a bound structlog logger (see :func:`configure_logging`)."""
    return structlog.get_logger(name)
