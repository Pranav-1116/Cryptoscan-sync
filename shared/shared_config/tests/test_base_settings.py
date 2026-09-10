"""Enterprise behaviour of shared_config.BaseSettings."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared_config.base_settings import (
    KNOWN_WEAK_SECRETS,
    BaseSettings,
    ConfigurationError,
)


class ServiceSettings(BaseSettings):
    """Mimics a typical service subclass."""

    SMTP_PASSWORD: str = "smtp-pass"
    API_KEY: str = "abcd1234"
    KEY_SIZE: int = 2048
    REQUIRED_IN_PROD: str = ""


class ProductionSettings(ServiceSettings):
    ENVIRONMENT: str = "production"

    def production_violations(self):
        violations = super().production_violations()
        if not self.REQUIRED_IN_PROD:
            violations.append("REQUIRED_IN_PROD is required in production")
        return violations


def test_environment_aliases_normalize():
    assert BaseSettings(ENVIRONMENT="dev").ENVIRONMENT == "development"
    assert BaseSettings(ENVIRONMENT="PROD").ENVIRONMENT == "production"
    assert BaseSettings(ENVIRONMENT="Testing").ENVIRONMENT == "test"


def test_invalid_environment_rejected():
    with pytest.raises(ValidationError):
        BaseSettings(ENVIRONMENT="productionn")


def test_log_level_normalized_and_validated():
    assert BaseSettings(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"
    with pytest.raises(ValidationError):
        BaseSettings(LOG_LEVEL="LOUD")


def test_environment_predicates():
    settings = BaseSettings(ENVIRONMENT="staging")
    assert settings.is_staging and not settings.is_production
    assert not settings.is_development
    assert BaseSettings(ENVIRONMENT="development").is_development
    assert BaseSettings(ENVIRONMENT="test").is_test


def test_sensitive_field_detection():
    fields = ServiceSettings().sensitive_fields()
    assert "SECRET_KEY" in fields
    assert "SMTP_PASSWORD" in fields
    assert "API_KEY" in fields
    # Measurement fields must not be treated as secrets.
    assert "KEY_SIZE" not in fields
    assert "DATABASE_URL" not in fields


def test_redacted_masks_secrets_but_not_the_rest():
    settings = ServiceSettings()
    dump = settings.redacted()
    assert dump["SECRET_KEY"] == "[REDACTED]"
    assert dump["SMTP_PASSWORD"] == "[REDACTED]"
    assert dump["API_KEY"] == "[REDACTED]"
    assert dump["KEY_SIZE"] == 2048


def test_repr_never_leaks_secrets():
    text = repr(ServiceSettings(SECRET_KEY="super-secret-value-do-not-print"))
    assert "super-secret-value-do-not-print" not in text
    assert "smtp-pass" not in text
    assert "[REDACTED]" in text


def test_production_gate_rejects_weak_secret_key():
    for weak in ("", "short", *KNOWN_WEAK_SECRETS):
        # ENVIRONMENT is pinned: pydantic-settings lets an ambient
        # ENVIRONMENT variable override the class default, which would
        # silently no-op the gate under a dev/test shell.
        settings = ProductionSettings(
            SECRET_KEY=weak, REQUIRED_IN_PROD="x", ENVIRONMENT="production"
        )
        with pytest.raises(ConfigurationError) as exc:
            settings.validate_for_production()
        assert "SECRET_KEY" in str(exc.value)


def test_production_gate_passes_with_strong_configuration():
    settings = ProductionSettings(
        SECRET_KEY="a" * 48, REQUIRED_IN_PROD="configured", ENVIRONMENT="production"
    )
    settings.validate_for_production()  # no raise


def test_production_gate_lists_service_extensions():
    settings = ProductionSettings(
        SECRET_KEY="a" * 48, REQUIRED_IN_PROD="", ENVIRONMENT="production"
    )
    with pytest.raises(ConfigurationError) as exc:
        settings.validate_for_production()
    assert "REQUIRED_IN_PROD" in str(exc.value)


def test_production_gate_is_noop_outside_production():
    # Development keeps demo defaults without failing.
    ServiceSettings(ENVIRONMENT="development").validate_for_production()
