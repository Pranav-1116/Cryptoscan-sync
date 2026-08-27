"""Tests for shared_logging.logger_factory — structlog configuration and loggers."""

from __future__ import annotations

import json

import structlog


from shared_logging.logger_factory import configure_logging, create_logger


def test_create_logger_returns_bound_logger():
    logger = create_logger("worker.test")
    # structlog bound loggers are callable wrappers, not stdlib Logger.
    assert logger is not None
    assert callable(logger.info)


def test_configure_logging_sets_level_and_json(capsys):
    configure_logging(level="INFO", json_output=True)
    logger = create_logger("scanner.test")
    logger.info("scan finished", scan_id="s-1")
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["event"] == "scan finished"
    assert payload["scan_id"] == "s-1"
    assert payload["level"] == "info"


def test_configure_logging_honours_level_filtering(capsys):
    configure_logging(level="WARNING", json_output=True)
    logger = create_logger("scanner.filtered")
    logger.info("this must be dropped")
    logger.warning("this must appear")
    out = capsys.readouterr().out
    assert "this must be dropped" not in out
    assert "this must appear" in out


def test_json_output_includes_timestamp(capsys):
    configure_logging(level="INFO", json_output=True)
    create_logger("api.test").warning("token expired")
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert "timestamp" in payload


def test_structlog_still_configured_after_import():
    # configure_logging must have left structlog usable globally.
    logger = structlog.get_logger("post.configure")
    assert logger is not None
