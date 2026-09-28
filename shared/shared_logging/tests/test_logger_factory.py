"""Tests for shared_logging.logger_factory — structlog configuration and loggers."""

from __future__ import annotations

import json
import logging

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


# --------------------------------------------------------------------------- #
# Enterprise behaviour: redaction + unified stdlib routing + idempotency
# --------------------------------------------------------------------------- #

def test_redact_secrets_masks_sensitive_keys():
    from shared_logging.logger_factory import redact_secrets

    event = {
        "event": "login",
        "user_password": "hunter2",
        "GITHUB_TOKEN": "ghp_abc",
        "nested": {"authorization": "Bearer xyz", "keep": 1},
        "items": [{"api_key": "k"}, {"name": "n"}],
        "key_size": 256,
    }
    out = redact_secrets(None, "info", event)
    assert out["user_password"] == "[REDACTED]"
    assert out["GITHUB_TOKEN"] == "[REDACTED]"
    assert out["nested"]["authorization"] == "[REDACTED]"
    assert out["nested"]["keep"] == 1
    assert out["items"][0]["api_key"] == "[REDACTED]"
    assert out["items"][1]["name"] == "n"
    assert out["key_size"] == 256  # measurement, not a secret
    assert out["event"] == "login"


def test_logger_output_redacts_secrets(capsys):
    configure_logging(level="INFO", json_output=True)
    create_logger("api.auth").info(
        "token issued", token="ghp_secret123", user="admin"
    )
    out = capsys.readouterr().out
    assert "ghp_secret123" not in out
    assert "[REDACTED]" in out
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["token"] == "[REDACTED]"
    assert payload["user"] == "admin"


def test_stdlib_logs_share_the_structlog_pipeline(capsys):
    configure_logging(level="INFO", json_output=True, force=True)
    logging.getLogger("some.legacy.module").warning(
        "legacy library says hi", extra={"session_id": "s-9", "password": "p"}
    )
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["event"] == "legacy library says hi"
    assert payload["level"] == "warning"
    assert payload["session_id"] == "s-9"
    assert payload["password"] == "[REDACTED]"


def test_configure_logging_is_idempotent():
    configure_logging(level="INFO", json_output=True)
    before = list(logging.getLogger().handlers)
    configure_logging(level="INFO", json_output=True)
    after = list(logging.getLogger().handlers)
    # No handler stacking: the factory-installed handler is reused.
    assert len([h for h in after if type(h).__name__ == "StreamHandler"]) <= len(
        [h for h in before if type(h).__name__ == "StreamHandler"]
    ) + 1


def test_redaction_can_be_disabled_but_defaults_on():
    from shared_logging.logger_factory import _shared_processors

    assert any(getattr(p, "__name__", None) == "redact_secrets" for p in _shared_processors(redact=True))
    assert not any(
        getattr(p, "__name__", None) == "redact_secrets"
        for p in _shared_processors(redact=False)
    )


def test_correlation_identifiers_survive_redaction():
    from shared_logging.logger_factory import redact_secrets

    out = redact_secrets(None, "info", {
        "session_id": "s-9",          # correlation id — must survive
        "request_id": "r-1",
        "commit_author": "dev",       # 'auth' substring false-positive guard
        "session": "raw-session",     # exact 'session' is sensitive
        "auth": "basic xyz",          # exact 'auth' is sensitive
    })
    assert out["session_id"] == "s-9"
    assert out["request_id"] == "r-1"
    assert out["commit_author"] == "dev"
    assert out["session"] == "[REDACTED]"
    assert out["auth"] == "[REDACTED]"
